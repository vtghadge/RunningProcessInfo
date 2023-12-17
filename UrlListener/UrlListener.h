#pragma once



#define ONE_MINUTE	1000*60*1

#define PROCESS_ID		"ProcessId"
#define PROCESS_NAME	"ProcessName"
#define SERVER_URL			"https://webhook.site/token/c2455784-3080-4ce9-a19b-16deb0051ea0/request/45ac2ace-7fcc-4713-9041-4a76702232e4/raw"
#define API_ID				"c2455784-3080-4ce9-a19b-16deb0051ea0"

#define FILE_NAME_CONFIG_W						L"Config.ini"
#define URL_LISTENER_SECTION_NAME				L"Client"
#define URL_LISTENER_KEY_NAME_API_ID			L"ApiId"
#define URL_LISTENER_KEY_NAME_TOKEN_URL			L"TokenUrl"
#define URL_LISTENER_KEY_NAME_REQUEST_URL		L"RequestUrl"

class URLListener
{
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

	URLListener();
	~URLListener();

	typedef std::list<std::shared_ptr<ProcessInfo>> RunningProcessList;
	bool StartURLListenerThread();
	static DWORD WINAPI URLListenerThread(void* parameter);
	bool URLListenerThreadImplementation();
	bool GetRunningProcessList();

private:

	bool QueryURLInfo();
	bool Deserialize(std::string& jsonProcInfo);
	bool BuildRequestURL(std::string &latestRequestIdResponse, std::string& latestRequestId, std::string &requestURL);
	bool GetServerResponse(const char* URL, std::string& Response);

private:
	HANDLE m_hThread;
	std::string m_latestRequestId;
	std::string m_apiId;
	std::string m_tokenUrl;
	std::string m_requestUrl;
	HANDLE m_hThreadStopEvent;
	std::wstring m_configFilePath;
	RunningProcessList m_runningProcessList;

	static std::unique_ptr<URLListener> s_pUrlListener;

};

bool GetWorkingDirPathW(std::wstring& folderPath, bool bIncludeLastBackslash);
size_t CurlUpdateCallback(void* ptr, size_t size, size_t nmemb, void* userData);
size_t CurlUpdateHttpHeaderCallback(void* ptr, size_t size, size_t nmemb, void* userData);
bool GetPrivateProfileStringExW(const std::wstring sectionName, const std::wstring keyName, const std::wstring filePath, std::wstring& valueBuffer, size_t bufferSize = 1024);
std::string ConvertWstringToString(std::wstring& wstring);
std::wstring ConvertStringToWstring(std::string& string);
