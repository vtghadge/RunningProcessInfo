// UrlListener.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"

std::unique_ptr<URLListener> URLListener::s_pUrlListener = nullptr;

int main()
{
	URLListener::Create();

	bool boRet = URLListener::GetInstance()->StartURLListenerThread();
	if (false == boRet)
	{
		URLListener::Release();
		return 0;
	}

	URLListener::Release();
	return 0;
}

URLListener::URLListener()
{
    m_hThreadStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

	GetWorkingDirPathW(m_configFilePath, true);
	m_configFilePath += FILE_NAME_CONFIG_W;
}

URLListener* URLListener::GetInstance()
{
    if (nullptr == s_pUrlListener.get())
    {
        s_pUrlListener = std::make_unique<URLListener>();
    }

    return s_pUrlListener.get();
}

void URLListener::Create()
{
    if (nullptr == s_pUrlListener.get())
    {
        s_pUrlListener.reset(new URLListener());
    }
}

void URLListener::Release()
{
    s_pUrlListener.reset(nullptr);
}

URLListener::~URLListener()
{
    if (m_hThreadStopEvent)
    {
        CloseHandle(m_hThreadStopEvent);
    }
}

bool URLListener::StartURLListenerThread()
{
	bool boRet = QueryURLInfo();
	if (false == boRet)
	{
		wprintf(L"\n StartURLListenerThread: QueryURLInfo failed with Error(%u)", GetLastError());
		return false;
	}

    m_hThread = CreateThread(NULL, 0, this->URLListenerThread, this, 0, NULL);
    if (NULL == m_hThread)
    {
        wprintf(L"\n StartURLListenerThread: CreateThread failed with Error(%u)", GetLastError());
        return false;
    }

    WaitForSingleObject(m_hThread, INFINITE);
    CloseHandle(m_hThread);

    return true;
}

DWORD __stdcall URLListener::URLListenerThread(void* parameter)
{
    if (nullptr == parameter)
    {
        return 0;
    }

    URLListener* pURLListenerObj = reinterpret_cast<URLListener*>(parameter);

    pURLListenerObj->URLListenerThreadImplementation();

    return 0;
}

bool URLListener::URLListenerThreadImplementation()
{
    bool boRes;
    DWORD dwWaitResult;

    DWORD dwWaitTime = ONE_MINUTE;
    while (true)
    {
        boRes = GetRunningProcessList();
        if (false == boRes)
        {
            break;
        }

        dwWaitResult = WaitForSingleObject(m_hThreadStopEvent, dwWaitTime);
        if (WAIT_OBJECT_0 == dwWaitResult)
        {
            break;
        }
    }

    return true;
}

bool URLListener::GetRunningProcessList()
{
	std::string latestRequestIdResponse;
	bool boRet = GetServerResponse(m_tokenUrl.c_str(), latestRequestIdResponse);
	if (false == boRet)
	{
		return boRet;
	}

	std::string requestUrl;
	std::string latestRequestId;
	boRet = BuildRequestURL(latestRequestIdResponse, latestRequestId, requestUrl);
	if (false == boRet)
	{
		return boRet;
	}

	if (latestRequestId == m_latestRequestId)
	{
		wprintf(L"\n BuildRequestURL: No new request present on server.");
		return true;
	}

	m_latestRequestId = latestRequestId;
	wprintf(L"\n BuildRequestURL: Found new request on server with Id(%S).", latestRequestId);

	std::string jsonProcInfo;
	boRet = GetServerResponse(requestUrl.c_str(), jsonProcInfo);
	if (false == boRet)
	{
		return boRet;
	}

	boRet = Deserialize(jsonProcInfo);
	if (false == boRet)
	{
		return boRet;
	}

	return true;
}

bool URLListener::BuildRequestURL(std::string& latestRequestIdResponse, std::string& latestRequestId, std::string& requestURL)
{
	rapidjson::Document document;
	document.Parse(latestRequestIdResponse.c_str());

	if (
		true != document.IsObject()							||
		true != document.HasMember("latest_request_id")		||
		true != document["latest_request_id"].IsString())
	{
		wprintf(L"\n BuildRequestURL: latest_request_id is not present in response.");
		return false;
	}

	const char* RequestId = document["latest_request_id"].GetString();
	std::string RequestIdA = RequestId;

	latestRequestId = RequestIdA;

	requestURL = m_requestUrl;
	requestURL += RequestIdA;
	requestURL += "/raw";

	return true;
}

bool URLListener::GetServerResponse(const char* URL, std::string& Response)
{
	CURLcode CurlResult;
	CURL* pCurlHandle = NULL;
	struct curl_slist* HeaderData = NULL;
	char chCurlErrorBuffer[CURL_ERROR_SIZE + 1];

	const char *pHeader = "Content-Type: text/data";

	int iRetVal = 0;
	HeaderData = curl_slist_append(HeaderData, pHeader);

	CurlResult = curl_global_init(CURL_GLOBAL_DEFAULT);
	if (CURLE_OK != CurlResult)
	{
		std::string strLog = curl_easy_strerror(CurlResult);
		return false;
	}

	pCurlHandle = curl_easy_init();
	if (NULL == pCurlHandle)
	{
		curl_global_cleanup();
		return false;
	}

	if (CURLE_OK != curl_easy_setopt(pCurlHandle, CURLOPT_ERRORBUFFER, chCurlErrorBuffer))
	{
		wprintf(L"curl_easy_setopt() Failed for CURLOPT_ERRORBUFFER.");
		return false;
	}
	if (CURLE_OK != curl_easy_setopt(pCurlHandle, CURLOPT_VERBOSE, 0L))
	{
		wprintf(L"curl_easy_setopt() Failed for CURLOPT_VERBOSE.");
		return false;
	}
	if (CURLE_OK != curl_easy_setopt(pCurlHandle, CURLOPT_CONNECTTIMEOUT, 30))
	{
		wprintf(L"curl_easy_setopt() Failed for CURLOPT_CONNECTTIMEOUT.");
		return false;
	}
	if (CURLE_OK != curl_easy_setopt(pCurlHandle, CURLOPT_URL, URL))
	{
		wprintf(L"curl_easy_setopt() Failed for CURLOPT_URL.");
		return false;
	}
	if (CURLE_OK != curl_easy_setopt(pCurlHandle, CURLOPT_SSL_VERIFYPEER, false))
	{
		wprintf(L"curl_easy_setopt() Failed for CURLOPT_SSL_VERIFYPEER.");
		return false;
	}
	if (CURLE_OK != curl_easy_setopt(pCurlHandle, CURLOPT_SSL_VERIFYHOST, 0L))
	{
		wprintf(L"curl_easy_setopt() Failed for CURLOPT_SSL_VERIFYHOST.");
		return false;
	}
	if (CURLE_OK != curl_easy_setopt(pCurlHandle, CURLOPT_NOSIGNAL, 1))
	{
		wprintf(L"curl_easy_setopt() Failed for CURLOPT_NOSIGNAL.");
		return false;
	}
	if (CURLE_OK != curl_easy_setopt(pCurlHandle, CURLOPT_HTTPGET, 1L))
	{
		wprintf(L"curl_easy_setopt() Failed for CURLOPT_POST.");
		return false;
	}
	if (CURLE_OK != curl_easy_setopt(pCurlHandle, CURLOPT_HEADERFUNCTION, CurlUpdateHttpHeaderCallback))
	{
		wprintf(L"curl_easy_setopt() Failed for CURLOPT_HEADERFUNCTION.");
		return false;
	}
	if (CURLE_OK != curl_easy_setopt(pCurlHandle, CURLOPT_HEADERDATA, (void*)NULL))
	{
		wprintf(L"curl_easy_setopt() Failed for CURLOPT_HEADERDATA.");
		return false;
	}
	if (CURLE_OK != curl_easy_setopt(pCurlHandle, CURLOPT_WRITEFUNCTION, CurlUpdateCallback))
	{
		wprintf(L"curl_easy_setopt() Failed for CURLOPT_WRITEFUNCTION.");
		return false;
	}
	if (CURLE_OK != curl_easy_setopt(pCurlHandle, CURLOPT_WRITEDATA, &Response))
	{
		wprintf(L"curl_easy_setopt() Failed for CURLOPT_WRITEDATA.");
		return false;
	}
	if (CURLE_OK != curl_easy_setopt(pCurlHandle, CURLOPT_LOW_SPEED_LIMIT, 10))
	{
		wprintf(L"curl_easy_setopt() Failed for CURLOPT_LOW_SPEED_LIMIT.");
		return false;
	}
	if (CURLE_OK != curl_easy_setopt(pCurlHandle, CURLOPT_LOW_SPEED_TIME, 10))
	{
		wprintf(L"curl_easy_setopt() Failed for CURLOPT_LOW_SPEED_TIME.");
		return false;
	}
	if (CURLE_OK != curl_easy_setopt(pCurlHandle, CURLOPT_HTTPHEADER, HeaderData))
	{
		wprintf(L"curl_easy_setopt() Failed for CURLOPT_HTTPHEADER.");
		return false;
	}

	iRetVal = curl_easy_perform(pCurlHandle);
	if (CURLE_OK != iRetVal)
	{
		std::string strLog = curl_easy_strerror((CURLcode)iRetVal);
		strLog = "curl_easy_perform() Failed : " + strLog + "";
		wprintf(L"%S", strLog.c_str());
		strLog = std::string(chCurlErrorBuffer) + "";
		wprintf(L"%S", strLog.c_str());
		return false;
	}

	return true;
}

bool URLListener::QueryURLInfo()
{
	int iRet = _waccess_s(m_configFilePath.c_str(), 0);
	if (0 != iRet)
	{
		wprintf(L"QueryURLInfo: Config file (%s) is not present.", m_configFilePath.c_str());
		return false;
	}

	std::wstring tempStr;
	bool boRet = GetPrivateProfileStringExW(URL_LISTENER_SECTION_NAME, URL_LISTENER_KEY_NAME_API_ID, m_configFilePath, tempStr);
	if (false == boRet)
	{
		wprintf(L"ParseZoneIdentifier: GetPrivateProfileStringExW failed with error (%u) for key(%s).", GetLastError(), URL_LISTENER_KEY_NAME_API_ID);
		return false;
	}
	m_apiId = ConvertWstringToString(tempStr);

	boRet = GetPrivateProfileStringExW(URL_LISTENER_SECTION_NAME, URL_LISTENER_KEY_NAME_TOKEN_URL, m_configFilePath, tempStr);
	if (false == boRet)
	{
		wprintf(L"ParseZoneIdentifier: GetPrivateProfileStringExW failed with error (%u) for key(%s).", GetLastError(), URL_LISTENER_KEY_NAME_TOKEN_URL);
		return false;
	}
	m_tokenUrl = ConvertWstringToString(tempStr);

	boRet = GetPrivateProfileStringExW(URL_LISTENER_SECTION_NAME, URL_LISTENER_KEY_NAME_REQUEST_URL, m_configFilePath, tempStr);
	if (false == boRet)
	{
		wprintf(L"ParseZoneIdentifier: GetPrivateProfileStringExW failed with error (%u) for key(%s).", GetLastError(), URL_LISTENER_KEY_NAME_REQUEST_URL);
		return false;
	}
	m_requestUrl = ConvertWstringToString(tempStr);

	return true;
}

bool URLListener::Deserialize(std::string& jsonProcInfo)
{
	rapidjson::Document document;
	document.Parse(jsonProcInfo.c_str());

	if (!document.IsArray())
	{
		return false;
	}

	for (rapidjson::SizeType i = 0; i < document.Size(); i++)
	{
		const rapidjson::Value &procEntry = document[i];
		DWORD dwProcessId = procEntry[PROCESS_ID].GetInt();
		const char *processName = procEntry[PROCESS_NAME].GetString();
		std::string processNameA = processName;
		std::wstring processNameW = ConvertStringToWstring(processNameA);

		m_runningProcessList.push_back(std::make_shared<ProcessInfo>(dwProcessId, processNameW));

		wprintf(L"\n Process ID: %u \t Process Name(%s)", dwProcessId, processNameW.c_str());
	}

	return true;
}

size_t CurlUpdateCallback(void* ptr, size_t size, size_t nmemb, void* userData)
{
	size_t realSize = size * nmemb;

	((std::string*)userData)->append((char*)ptr, realSize);

	return realSize;
}

size_t CurlUpdateHttpHeaderCallback(void* ptr, size_t size, size_t nmemb, void* userData)
{
	UNREFERENCED_PARAMETER(userData);

	char* header = (char*)ptr;
	if (header != NULL)
	{
		//printf("header = %S", header);
	}
	return size * nmemb;
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

bool GetPrivateProfileStringExW(const std::wstring sectionName, const std::wstring keyName, const std::wstring filePath, std::wstring& valueBuffer, size_t bufferSize)
{
	bool bRes = false;
	std::vector<WCHAR> buffer(bufferSize);

	for (size_t i = 1; i <= 3; i++)
	{
		int iRet = GetPrivateProfileStringW(sectionName.c_str(), keyName.c_str(), NULL, &buffer[0], (DWORD)buffer.capacity(), filePath.c_str());
		if (0 == iRet)
		{
			wprintf(L"GetPrivateProfileStringW failed with error (%u) for key(%s).", GetLastError(), keyName.c_str());
			return false;
		}

		if (iRet == (buffer.capacity() - 1))
		{
			wprintf(L"Buffer overflow condition for key (%s) from stream(%s).", keyName.c_str(), filePath.c_str());
			buffer.resize(2 * buffer.capacity());
			continue;
		}

		bRes = true;
		valueBuffer = &buffer[0];
		break;
	}

	return bRes;
}

std::string ConvertWstringToString(std::wstring& wstring)
{
	int len;
	int stringLen = (int)wstring.length() + 1;
	std::string convertedString;

	len = WideCharToMultiByte(CP_ACP, 0, wstring.c_str(), stringLen, 0, 0, 0, 0);
	if (0 == len)
	{
		return std::string();
	}

	convertedString.resize((len / sizeof(CHAR)));

	len = WideCharToMultiByte(CP_ACP, 0, wstring.c_str(), stringLen, &convertedString[0], len, 0, 0);
	if (0 == len)
	{
		return std::string();
	}

	if ('\0' == convertedString.back())
	{
		convertedString.erase(convertedString.length() - 1);
	}

	return convertedString;
}

std::wstring ConvertStringToWstring(std::string& string)
{
	int len;
	int stringLen = (int)string.length() + 1;
	std::wstring convertedString;

	len = MultiByteToWideChar(CP_ACP, 0, string.c_str(), stringLen, 0, 0);
	if (0 == len)
	{
		return std::wstring();
	}

	convertedString.resize(len);

	len = MultiByteToWideChar(CP_ACP, 0, string.c_str(), stringLen, &convertedString[0], len);
	if (0 == len)
	{
		return std::wstring();
	}

	return convertedString;
}


