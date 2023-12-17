#pragma once
#include <DbgHelp.h>

#define BUFFER_SIZE 0x10000

typedef struct BASE_RELOCATION_BLOCK {
	DWORD PageAddress;
	DWORD BlockSize;
} BASE_RELOCATION_BLOCK, *PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, *PBASE_RELOCATION_ENTRY;

#define CountRelocationEntries(dwBlockSize)		\
	(dwBlockSize -								\
	sizeof(BASE_RELOCATION_BLOCK)) /			\
	sizeof(BASE_RELOCATION_ENTRY)

inline PIMAGE_NT_HEADERS GetNTHeaders(ULONG_PTR dwImageBase)
{
	return (PIMAGE_NT_HEADERS)(dwImageBase + 
		((PIMAGE_DOS_HEADER)dwImageBase)->e_lfanew);
}

PLOADED_IMAGE GetLoadedImage(ULONG_PTR dwImageBase);

PLOADED_IMAGE ReadRemoteImage(HANDLE hProcess, LPCVOID lpImageBaseAddress);

VOID FreeImage(PLOADED_IMAGE pImage);
BOOL IsPEFile(const LPVOID lpImage);
BOOL IsPE32(const LPVOID lpImage);
DWORD GetSubsytem(const LPVOID lpImage, bool bo32Bit);
WORD GetSubsystemEx(const HANDLE hProcess, const LPVOID lpImageBaseAddress, bool bo32Bit);
bool HasRelocation(const LPVOID lpImage, bool bo32Bit);
bool GetRelocAddress(const LPVOID lpImage, IMAGE_DATA_DIRECTORY* pImageDataReloc, bool bo32Bit);

