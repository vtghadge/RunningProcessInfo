#pragma once

#define ONE_MINUTE	1000*60*1

#define PROCESS_ID		"ProcessId"
#define PROCESS_NAME	"ProcessName"
#define SERVER_URL				"https://webhook.site/c2455784-3080-4ce9-a19b-16deb0051ea0"

#define FILE_NAME_CONFIG_W						L"Config.ini"
#define RUNINNG_PROCESS_SECTION_NAME			L"Server"
#define RUNINNG_PROCESS_KEY_NAME_API_ID			L"ApiId"
#define RUNINNG_PROCESS_KEY_NAME_SERVER_URL		L"ServerUrl"
#define DOWNLOADED_FILE_KEY_NAME_REQUEST_URL	L"RequestUrl"

class ProcessManager
{
public:

	struct ProcessInfo
	{
		DWORD m_dwProcessId;
		std::wstring m_processName;
		ProcessInfo(DWORD dwProcessId, std::wstring& processName) : m_dwProcessId(dwProcessId), m_processName(processName){}
	};

	ProcessManager();
	~ProcessManager();

	typedef std::list<std::shared_ptr<ProcessInfo>> RunningProcessList;
	bool StartWorkerThread();
	static DWORD WINAPI WorkerThread(void* parameter);
	bool WorkerThreadImplementation();

private:
	bool GetRunningProcessList();
	bool GetProcessPathFromPid(DWORD dwProcessId, std::wstring& processName);
	bool SendRunningProcessList();
	bool Serialize(std::string& serializeBuffer);
	bool SendProcessEventToServer(std::string URL, std::string jsonData);
	bool QueryURLInfo();

private:
	std::wstring m_serverUrl;
	HANDLE m_hThreadStopEvent;
	std::wstring m_configFilePath;
	RunningProcessList m_runningProcessList;

};

std::string ConvertWstringToString(std::wstring& wstring);
bool GetWorkingDirPathW(std::wstring& folderPath, bool bIncludeLastBackslash);
bool GetPrivateProfileStringExW(const std::wstring sectionName, const std::wstring keyName, const std::wstring filePath, std::wstring& valueBuffer, size_t bufferSize = 1024);

