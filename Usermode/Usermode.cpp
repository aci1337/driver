#include <Windows.h>
#include <WinNT.h>
#include <cstdio>

#define IOCTL_GET_WIN_VER CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_PROCESS_BASE_ADDRESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _WIN_VER_INFO {
	ULONG MajorVersion;
	ULONG MinorVersion;
} WIN_VER_INFO, * PWIN_VER_INFO;

typedef struct _PROCESS_BASE_ADDRESS_INFO {
	HANDLE ProcessId;
	PVOID BaseAddress;
} PROCESS_BASE_ADDRESS_INFO, * PPROCESS_BASE_ADDRESS_INFO;
HANDLE hDevice;
int main()
{
	hDevice = CreateFileW((L"\\.\\MyDuduez"), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (hDevice == INVALID_HANDLE_VALUE) {
		DWORD error = GetLastError();
		printf("Failed to open MyDuduez. Error code: %d\n", error);
	}

	// Retrieve Windows version
	WIN_VER_INFO WinVerInfo = { 0 };
	DWORD BytesReturned;
	BOOL Result = DeviceIoControl(hDevice, IOCTL_GET_WIN_VER, &WinVerInfo, sizeof(WinVerInfo), &WinVerInfo, sizeof(WinVerInfo), &BytesReturned, NULL);
	if (!Result) {
		DWORD error = GetLastError();
		printf("Failed to retrieve Windows version. Error code: %d\n", error);
	}
	printf("Windows version: %d.%d\n", WinVerInfo.MajorVersion, WinVerInfo.MinorVersion);

	// Retrieve process base address
	DWORD ProcessId = GetCurrentProcessId();
	PROCESS_BASE_ADDRESS_INFO ProcessBaseAddressInfo = { 0 };
	ProcessBaseAddressInfo.ProcessId = (HANDLE)ProcessId;
	Result = DeviceIoControl(hDevice, IOCTL_GET_PROCESS_BASE_ADDRESS, &ProcessBaseAddressInfo, sizeof(ProcessBaseAddressInfo), &ProcessBaseAddressInfo, sizeof(ProcessBaseAddressInfo), &BytesReturned, NULL);
	if (!Result) {
		DWORD error = GetLastError();
		printf("Failed to retrieve process base address. Error code: %d\n", error);
	}
	printf("Process base address: %p\n", ProcessBaseAddressInfo.BaseAddress);

	return 0;
}