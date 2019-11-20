#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <fltUser.h>
#include <locale>
#include <comdef.h>
#include <winioctl.h>
#include <Fwptypes.h>

#define DEVICE_SEND CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_WRITE_DATA)
#define DEVICE_REC CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_READ_DATA)

HANDLE FltServerPort;
WCHAR ServerPortName[] = L"\\FltAntivairusPort";

#define PIPE_NAME   TEXT("\\\\.\\pipe\\GUIpipe")
#define PIPE_NAME02 TEXT("\\\\.\\pipe\\GUIpipe02")
#define PIPE_NAME_LOGGER TEXT("\\\\.\\pipe\\LoggerPipe")
// Количество обработанных запросов от клиентов
CRITICAL_SECTION lock;
int requests = 0;
int updateNetworkDriver = 0;
HANDLE create_pipe(int first)
{
	HANDLE pipe;
	// Двунаправленная передача данных через канал
	DWORD open_mode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED;
	if (first)
		open_mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
	pipe = CreateNamedPipe(PIPE_NAME, // Имя канала
		open_mode,
		// Побайтовая передача данных, блокирующая
		PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
		// Количество подключений не ограничено
		PIPE_UNLIMITED_INSTANCES,
		// Размеры буферов приема и передачи
		512, 512,
		0, // Таймаут по умолчанию
		NULL // Настройки безопасности
	);
	if (pipe == INVALID_HANDLE_VALUE || pipe == NULL)
	{
		printf("Error CreateNamedPipe(): %d\n", GetLastError());
		return 0;
	}
	return pipe;
}

void getRegistryKey(const char* key, char* buf) {
	HKEY  hKey;
	DWORD dwType = KEY_ALL_ACCESS;
	DWORD dwBufSize = 255;

	RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\SupaFilter", 0, KEY_READ, &hKey);
	RegQueryValueEx(hKey, key, NULL, &dwType, (unsigned char*)buf, &dwBufSize);
}

void storeToRegistry(const char* key, char* value) {
	unsigned int len = strlen(value);
	HKEY  hKey;
	int status;
	status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\SupaFilter", 0, KEY_WRITE, &hKey);
	status = RegSetValueEx(hKey, key, 0, REG_SZ, (BYTE*)value, len);
	RegCloseKey(hKey);
}


void saveProtectedFilesToRegistry(char* files) {
	storeToRegistry("ProtectedFiles", files);
	//int step = 0;
	//int size = strlen(files);
	//for (int i = 0; i < size && files[i] != '\0';)
	//{
	//	char* file = files;
	//	while (true) {
	//		if (files[i] == '\n' or files[i] == '\0') {
	//			files[i] = '\0';
	//			if (step == 0) {
	//				storeToRegistry("ProtectedFiles", file);
	//				step++;
	//			}
	//			else if (step == 1) {
	//				storeToRegistry("ProtectedRegistry", files);
	//				break;
	//			}
	//			i++;
	//			files += i;
	//			break;
	//		}
	//		i++;
	//	}
	//	//files += strlen(file) + 1;
	//	//i = 0;
	//}
}


NTSTATUS FltConnect() {
	NTSTATUS status;
	HANDLE hPort;
	status = FilterConnectCommunicationPort(ServerPortName,
		0,
		0,
		0,
		0,
		&FltServerPort);
	if (status != ERROR_SUCCESS) {
		printf("Cannot connect to FltPort\n");
		printf("error_code= %x\n", status);
	}
	return status;
}

NTSTATUS FltSendMessage(char* message) {
	NTSTATUS status;
	ULONG bytesReturned = 0;

	status = FilterSendMessage(FltServerPort,
		message,
		sizeof(message),
		0,
		0,
		&bytesReturned);
	if (status != ERROR_SUCCESS) {
		printf("Cannot send message to FltPort\n");
		printf("error_code= %x\n", status);
	}

	return status;
}

VOID FltClose() {
	FilterClose(FltServerPort);
}

void saveSnortRulesToRegistry(char* rules) {
	storeToRegistry("SnortRules", rules);
}

DWORD WINAPI instance_thread(void* param)
{
	HANDLE pipe = (HANDLE)param;
	// Цикл обработки запросов клиентов
	while (1)
	{
		int rcv = 0, len;
		char buf[1024] = { 0 };
		DWORD read, written;
		int i;
		// Чтение запроса из канала
		while (rcv < (sizeof(buf) - 1))
		{
			printf("start reading\n");
			if (!ReadFile(pipe, buf + rcv, sizeof(buf) - 1 - rcv, &read, NULL))
			{
				printf(" Client disconnected (on read)\n");
				CloseHandle(pipe);
				return 0;
			}
			printf("read %d bytes\n", read);
			for (i = rcv; i < rcv + (int)read; i++)
			{
				if (buf[i] == '\n')
				{
					rcv = sizeof(buf);
					break;
				}
				rcv++;
			}
		}
		len = strlen(buf);
		if (len > 0)
		{
			buf[len - 1] = 0;
			len--;
		}
		printf("Received request: '%s'\n", buf);
		if (strlen(buf) < 2) {
			return 0;
		}
		char idString[2] = { 0 };
		idString[0] = buf[0];
		idString[1] = buf[1];
		int id = atoi(idString);
		printf("action =  %d\n", id);

		switch (id)
		{
		case 1:
			//saveProtectedFilesToRegistry(buf + 3);
			// on js side
			// storeToRegistry("ProtectedRegistry", buf+2);
			FltSendMessage((char*)"update\0");
			break;
		case 2:
			saveSnortRulesToRegistry(buf + 2);
			updateNetworkDriver = 1;
			break;
		case 3:
			//saveProtectedFilesToRegistry(buf + 3);
			// on js side
			//storeToRegistry("ProtectedFiles", buf+2);
			FltSendMessage((char*)"update\0");
			break;
		case 4:
		case 5:
			// switch
			FltSendMessage(buf+2);
			break;
		case 6:
			updateNetworkDriver = buf[2+7] - 46; // 2 or 3
			break;
		default:
			break;
		}
		// Отправка ответа
		EnterCriticalSection(&lock);
		requests++;
		LeaveCriticalSection(&lock);
	}
	return 0;
}
// Поток обрабатывает подключения клиентов и создание
// новых экземпляров канала в случае подключения клиентов
DWORD WINAPI server_thread(void* param)
{
	HANDLE pipe = (HANDLE)param;
	// Серверный цикл ожидания подключения клиентов
	while (1)
	{
		// Принятие подключения от клиента
		BOOL connected = ConnectNamedPipe(pipe, 0);
		if (!connected && (GetLastError() == ERROR_PIPE_CONNECTED))
		{
			connected = TRUE;
		}
		if (connected)
		{
			HANDLE thread;
			printf(" New client connected => new thread created\n");
			// Создание потока, обслуживающего подключившегося клиента
			thread = CreateThread(0, 0, instance_thread, (void*)pipe, 0, NULL);
			// Создание нового экземпляра канала - для подключения
			// следующего клиента.
			pipe = create_pipe(0);
		}
		else
		{
			CloseHandle(pipe);
			pipe = create_pipe(0);
		}
	}
	return 0;
}


VOID replyTo(const char* pipe, const char* message) {
	NTSTATUS status;
	HANDLE hPipe;
	DWORD writtenBytes;

	hPipe = CreateFile(
		pipe,
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		0,
		NULL);

	if (hPipe == INVALID_HANDLE_VALUE) {
		printf("Can't connect to pipe %s\n", pipe);
	}
	else {
		status = WriteFile(
			hPipe,
			message,
			strlen(message),
			&writtenBytes,
			NULL);
		if (!status) {
			printf("Can't write to pipe pipe\n", pipe);
			CloseHandle(hPipe);
			hPipe = NULL;
		}
	}
}

typedef struct _FILTER_MESSAGE {
	FILTER_MESSAGE_HEADER FilterMessageHeader;
	WCHAR FilterMessageBody[128];
} FILTER_MESSAGE, * PFILTER_MESSAGE;


DWORD WINAPI flt_thread(void* param) {
	NTSTATUS status;
	FILTER_MESSAGE message;
	HANDLE hPipe = NULL;
	DWORD writtenBytes;

	status = FltConnect();
	if (status != ERROR_SUCCESS) {
		return status;
	}

	while (1) {
		status = FilterGetMessage(FltServerPort,
			&message.FilterMessageHeader,
			sizeof(message),
			NULL
		);
		char str[128] = { 0 };

		if (status != ERROR_SUCCESS) {
			printf("error FltGetMessage (%x)\n", status);
		}
		else {
			_bstr_t b(message.FilterMessageBody);
			strcpy_s(str, b);
			printf("%s\n", str);
		}

		if (str != NULL) {
			replyTo(PIPE_NAME_LOGGER, str);

			if (message.FilterMessageBody[0] == L'0' &&
				message.FilterMessageBody[1] == L'1') {
				replyTo(PIPE_NAME02, str + 2);
			}
		}
		else {
			printf("str==NULL\n");
		}
	}

	FltClose();
}

DWORD WINAPI network_thread(void* param) {

	DWORD dwReturnBytes;
	unsigned long ioctl;
	HANDLE hHandl;
	NTSTATUS status;

	hHandl = CreateFile("\\\\.\\Filter", GENERIC_ALL, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, 0);
	status = GetLastError();
	if (status != 0) {
		printf("network ioctl error %x\n", status);
		return 1;
	}

	while (1) {
		if (updateNetworkDriver == 0) {
			char mes[1024] = { 0 };
			status = DeviceIoControl(hHandl, DEVICE_REC, NULL, 0, mes, 1024, &dwReturnBytes, NULL);
			if (status != ERROR_SUCCESS) {
				//printf("error DeviceIoControl %x\n", status);
			}
			if (mes[0] != 0) {
				replyTo(PIPE_NAME_LOGGER, mes);
				replyTo(PIPE_NAME02, mes);
			}
		}
		else if (updateNetworkDriver > 0) {
			char mes[1024] = { updateNetworkDriver };
			status = DeviceIoControl(hHandl, DEVICE_SEND, NULL, 0, mes, 1024, &dwReturnBytes, NULL);
			if (status != ERROR_SUCCESS) {
				printf("error DeviceIoControl DEVICE_SEND %x\n", status);
			}
			updateNetworkDriver = 0;
		}
	}

	return 0;
}


int main()
{
	HANDLE NetworkThread;
	NetworkThread = CreateThread(NULL, 0, network_thread, 0, 0, NULL);

	setlocale(LC_ALL, "Russian");

	setlocale(LC_ALL, "ru_RU.utf8");
	//SetConsoleOutputCP(65001);

	HANDLE FltThread;
	FltThread = CreateThread(NULL, 0, flt_thread, 0, 0, NULL);

	DWORD dwDisposition;
	HKEY  hKey;
	DWORD Ret;
	Ret = RegCreateKeyEx(HKEY_LOCAL_MACHINE, "System\\CurrentControlSet\\Services\\SupaFilter", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, &dwDisposition);
	if (Ret != ERROR_SUCCESS)
	{
		printf("Error opening or creating new key\n");
		return FALSE;
	}

	// Создание первого экземпляра канала
	HANDLE pipe = create_pipe(1);
	HANDLE thread;
	if (!pipe)
		return -1;
	InitializeCriticalSection(&lock);
	printf("Listening pipe...\n");
	thread = CreateThread(NULL, 0, server_thread, (void*)pipe, 0, NULL);


	system("sc start SupaFilter");
	system("sc start Network");


	while (1)
	{
		EnterCriticalSection(&lock);
		printf("Waiting for requests (%d complete)...\n", requests);
		LeaveCriticalSection(&lock);
		Sleep(2000);
	}

	return 0;
}