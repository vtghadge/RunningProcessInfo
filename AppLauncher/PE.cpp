#include "pch.h"

PLOADED_IMAGE GetLoadedImage(ULONG_PTR dwImageBase)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)dwImageBase;

	PLOADED_IMAGE pImage = new(std::nothrow) LOADED_IMAGE();
	if (nullptr == pImage)
	{
		return nullptr;
	}

	pImage->FileHeader =
		(PIMAGE_NT_HEADERS)(dwImageBase + pDosHeader->e_lfanew);

	pImage->NumberOfSections =
		pImage->FileHeader->FileHeader.NumberOfSections;

	pImage->Sections =
		(PIMAGE_SECTION_HEADER)(dwImageBase + pDosHeader->e_lfanew +
			sizeof(IMAGE_NT_HEADERS));

	return pImage;
}

PLOADED_IMAGE ReadRemoteImage(HANDLE hProcess, LPCVOID lpImageBaseAddress)
{
	BYTE* lpBuffer = new(std::nothrow) BYTE[BUFFER_SIZE];
	if (nullptr == lpBuffer)
	{
		return nullptr;
	}

	BOOL bSuccess = ReadProcessMemory
		(
		hProcess,
		lpImageBaseAddress,
		lpBuffer,
		BUFFER_SIZE,
		0
		);
	if (!bSuccess)
		return nullptr;

	PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)lpBuffer;

	PLOADED_IMAGE pImage = new(std::nothrow) LOADED_IMAGE();
	if (nullptr == pImage)
	{
		delete lpBuffer;
		return nullptr;
	}

	pImage->FileHeader = 
		(PIMAGE_NT_HEADERS)(lpBuffer + pDOSHeader->e_lfanew);

	pImage->NumberOfSections = 
		pImage->FileHeader->FileHeader.NumberOfSections;

	pImage->Sections = 
		(PIMAGE_SECTION_HEADER)(lpBuffer + pDOSHeader->e_lfanew + 
		sizeof(IMAGE_NT_HEADERS32));

	delete []lpBuffer;

	return pImage;
}

VOID FreeImage(PLOADED_IMAGE pImage)
{
	if (pImage)
	{
		delete pImage;
	}
}

BOOL IsPEFile(const LPVOID lpImage)
{
	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
	const auto lpImageNTHeader = (PIMAGE_NT_HEADERS)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
	if (lpImageNTHeader->Signature == IMAGE_NT_SIGNATURE)
		return TRUE;

	return FALSE;
}

BOOL IsPE32(const LPVOID lpImage)
{
	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
	const auto lpImageNTHeader = (PIMAGE_NT_HEADERS)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
	if (lpImageNTHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
		return TRUE;

	return FALSE;
}

DWORD GetSubsytem(const LPVOID lpImage, bool bo32Bit)
{
	if (bo32Bit)
	{
		const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
		const auto lpImageNTHeader = (PIMAGE_NT_HEADERS32)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
		return lpImageNTHeader->OptionalHeader.Subsystem;
	}

	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
	const auto lpImageNTHeader = (PIMAGE_NT_HEADERS64)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
	return lpImageNTHeader->OptionalHeader.Subsystem;
}

WORD GetSubsystemEx(const HANDLE hProcess, const LPVOID lpImageBaseAddress, bool bo32Bit)
{
	IMAGE_DOS_HEADER ImageDOSHeader = {};

	if (bo32Bit)
	{
		const BOOL bGetDOSHeader = ReadProcessMemory(hProcess, lpImageBaseAddress, (LPVOID)&ImageDOSHeader, sizeof(IMAGE_DOS_HEADER), nullptr);
		if (!bGetDOSHeader)
		{
			wprintf(L"\n GetSubsystemEx: ReadProcessMemory failed error(%u)", GetLastError());
			return (WORD)-1;
		}

		constexpr IMAGE_NT_HEADERS32 ImageNTHeader = {};
		const BOOL bGetNTHeader = ReadProcessMemory(hProcess, (LPVOID)((uintptr_t)lpImageBaseAddress + ImageDOSHeader.e_lfanew), (LPVOID)&ImageNTHeader, sizeof(IMAGE_NT_HEADERS32), nullptr);
		if (!bGetNTHeader)
		{
			wprintf(L"\n GetSubsystemEx: ReadProcessMemory 2 failed error(%u)", GetLastError());
			return (WORD)-1;
		}

		return ImageNTHeader.OptionalHeader.Subsystem;
	}

	BOOL bGetDOSHeader = ReadProcessMemory(hProcess, lpImageBaseAddress, (LPVOID)&ImageDOSHeader, sizeof(IMAGE_DOS_HEADER), nullptr);
	if (!bGetDOSHeader)
	{
		wprintf(L"\n GetSubsystemEx: ReadProcessMemory failed error(%u)", GetLastError());
		return (WORD)-1;
	}

	IMAGE_NT_HEADERS64 ImageNTHeader = {};
	BOOL bGetNTHeader = ReadProcessMemory(hProcess, (LPVOID)((uintptr_t)lpImageBaseAddress + ImageDOSHeader.e_lfanew), (LPVOID)&ImageNTHeader, sizeof(IMAGE_NT_HEADERS64), nullptr);
	if (!bGetNTHeader)
	{
		wprintf(L"\n GetSubsystemEx: ReadProcessMemory 2 failed error(%u)", GetLastError());
		return (WORD)-1;
	}

	return ImageNTHeader.OptionalHeader.Subsystem;
}

bool HasRelocation(const LPVOID lpImage, bool bo32Bit)
{
	PIMAGE_DOS_HEADER lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;

	if (bo32Bit)
	{
		auto lpImageNTHeader = (PIMAGE_NT_HEADERS32)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
		if (lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0)
		{
			return true;
		}

		return false;
	}

	auto lpImageNTHeader = (PIMAGE_NT_HEADERS64)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
	if (lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0)
	{
		return true;
	}

	return false;
}

bool GetRelocAddress(const LPVOID lpImage, IMAGE_DATA_DIRECTORY *pImageDataReloc, bool bo32Bit)
{
	if (nullptr == pImageDataReloc)
	{
		return false;
	}

	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
	if (bo32Bit)
	{
		const auto lpImageNTHeader = (PIMAGE_NT_HEADERS32)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
		if (lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0)
		{
			*pImageDataReloc = lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
			return true;
		}

		return false;
	}

	const auto lpImageNTHeader = (PIMAGE_NT_HEADERS64)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
	if (lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0)
	{
		*pImageDataReloc = lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
		return true;
	}

	return false;
}
