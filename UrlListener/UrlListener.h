#pragma once

#define ONE_MINUTE	1000*60*1

#define PROCESS_ID		"ProcessId"
#define PROCESS_NAME	"ProcessName"

#define FILE_NAME_CONFIG_W						L"Config.ini"
#define URL_LISTENER_SECTION_NAME				L"Client"
#define URL_LISTENER_KEY_NAME_API_ID			L"ApiId"
#define URL_LISTENER_KEY_NAME_TOKEN_URL			L"TokenUrl"
#define URL_LISTENER_KEY_NAME_REQUEST_URL		L"RequestUrl"

class URLListener
{
private:

	URLListener();
	URLListener& operator = (const URLListener&) = delete;
	URLListener(const URLListener&);

public:

	struct ProcessInfo
	{
		DWORD m_dwProcessId;
		std::wstring m_processName;
		ProcessInfo(DWORD dwProcessId, std::wstring& processName) : m_dwProcessId(dwProcessId), m_processName(processName) {}
	};

	static URLListener* GetInstance();
	static void Create();
	static void Release();

	static BOOL WINAPI CtrlCHandler(DWORD fdwCtrlType);

	~URLListener();

	typedef std::list<std::shared_ptr<ProcessInfo>> RunningProcessList;
	bool StartURLListenerThread();
	bool StopURLListenerThread();
	static DWORD WINAPI URLListenerThread(void* parameter);
	bool URLListenerThreadImplementation();
	bool GetRunningProcessList();

private:

	bool QueryURLInfo();
	bool Deserialize(std::string& jsonProcInfo);
	bool BuildRequestURL(std::string &latestRequestIdResponse, std::string& latestRequestId, std::string &requestURL);
	bool GetServerResponse(const char* URL, std::string& Response);

private:
	std::string m_latestRequestId;
	std::string m_apiId;
	std::string m_tokenUrl;
	std::string m_requestUrl;
	HANDLE m_hThread;
	HANDLE m_hThreadStopEvent;
	std::wstring m_configFilePath;
	RunningProcessList m_runningProcessList;

	static std::unique_ptr<URLListener> s_pUrlListener;

};

size_t CurlUpdateCallback(void* ptr, size_t size, size_t nmemb, void* userData);
size_t CurlUpdateHttpHeaderCallback(void* ptr, size_t size, size_t nmemb, void* userData);
