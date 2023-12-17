#pragma once

#define ONE_MINUTE	1000*60*1

#define PROCESS_ID		"ProcessId"
#define PROCESS_NAME	"ProcessName"
#define SERVER_URL				"https://webhook.site/c2455784-3080-4ce9-a19b-16deb0051ea0"

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

private:
	RunningProcessList m_runningProcessList;
	HANDLE m_hThreadStopEvent;

};

std::string ConvertWstringToString(std::wstring& wstring);

