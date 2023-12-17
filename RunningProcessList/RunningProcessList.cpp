#include "pch.h"


int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	UNREFERENCED_PARAMETER(hInstance);
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(lpCmdLine);
	UNREFERENCED_PARAMETER(nCmdShow);


	ProcessManager ProcManagerObj;

	ProcManagerObj.StartWorkerThread();

	MessageBoxA(0, "RunningProcessList", "RunningProcessList", 0);

	//system("pause");

	return 0;
}

ProcessManager::ProcessManager()
{
	m_hThreadStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
}

ProcessManager::~ProcessManager()
{
	if (m_hThreadStopEvent)
	{
		CloseHandle(m_hThreadStopEvent);
		m_hThreadStopEvent = nullptr;
	}

	if (!m_runningProcessList.empty())
	{
		m_runningProcessList.clear();
	}
}

bool ProcessManager::StartWorkerThread()
{
	HANDLE hThread = CreateThread(NULL, 0, this->WorkerThread, this, 0, NULL);
	if (NULL == hThread)
	{
		wprintf(L"\n CreateThread failed with Error(%u)", GetLastError());
		return false;
	}

	WaitForSingleObject(hThread, INFINITE);

	return true;
}

DWORD __stdcall ProcessManager::WorkerThread(void* parameter)
{
	if (nullptr == parameter)
	{
		return 0;
	}

	ProcessManager* pProcManagerObj = reinterpret_cast<ProcessManager*>(parameter);

	pProcManagerObj->WorkerThreadImplementation();

	return 0;
}

bool ProcessManager::WorkerThreadImplementation()
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

		boRes = SendRunningProcessList();
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

bool ProcessManager::SendRunningProcessList()
{
	std::string processListBuffer;
	bool boRet = Serialize(processListBuffer);
	if (false == boRet)
	{
		return boRet;
	}

	boRet = SendProcessEventToServer(SERVER_URL, processListBuffer);
	if (false == boRet)
	{
		return boRet;
	}

	return true;
}


bool ProcessManager::Serialize(std::string& serializeBuffer)
{
	rapidjson::Document document;
	rapidjson::Document::AllocatorType& allocator = document.GetAllocator();
	document.SetArray();

	for (const auto& procEntry : m_runningProcessList)
	{
		rapidjson::Value strVal;

		std::string processNameA = ConvertWstringToString(procEntry->m_processName);
		rapidjson::Value JsonProcEntry(rapidjson::kObjectType);
		int processId = (int)procEntry->m_dwProcessId;
		JsonProcEntry.AddMember(PROCESS_ID, processId, allocator);
		strVal.SetString(processNameA.c_str(), allocator);
		JsonProcEntry.AddMember(PROCESS_NAME, strVal, allocator);

		document.PushBack(JsonProcEntry, allocator);
	}

	rapidjson::StringBuffer stringBuffer;
	rapidjson::Writer<rapidjson::StringBuffer> JsonWriter(stringBuffer);

	document.Accept(JsonWriter);

	serializeBuffer = stringBuffer.GetString();

	return true;
}

bool ProcessManager::SendProcessEventToServer(std::string URL, std::string jsonData)
{
	CURLcode CurlError;
	CURL* pCurlHandle = NULL;
	struct curl_slist* HeaderData = NULL;
	char chCurlErrorBuffer[CURL_ERROR_SIZE + 1];

	CurlError = curl_global_init(CURL_GLOBAL_DEFAULT);
	if (CURLE_OK != CurlError)
	{
		std::string strLog = curl_easy_strerror(CurlError);
		return false;
	}

	pCurlHandle = curl_easy_init();
	if (NULL == pCurlHandle)
	{
		curl_global_cleanup();
		return false;
	}

	if (0 != curl_easy_setopt(pCurlHandle, CURLOPT_ERRORBUFFER, chCurlErrorBuffer))
	{
		curl_easy_cleanup(pCurlHandle);
		curl_global_cleanup();
		return false;
	}

	if (0 != curl_easy_setopt(pCurlHandle, CURLOPT_VERBOSE, 0L))
	{
		curl_easy_cleanup(pCurlHandle);
		curl_global_cleanup();
		return false;
	}

	if (0 != curl_easy_setopt(pCurlHandle, CURLOPT_CONNECTTIMEOUT, 30))
	{
		curl_easy_cleanup(pCurlHandle);
		curl_global_cleanup();
		return false;
	}

	if (0 != curl_easy_setopt(pCurlHandle, CURLOPT_URL, URL.c_str()))
	{
		curl_easy_cleanup(pCurlHandle);
		curl_global_cleanup();
		return false;
	}

	if (0 != curl_easy_setopt(pCurlHandle, CURLOPT_SSL_VERIFYPEER, false))
	{
		curl_easy_cleanup(pCurlHandle);
		curl_global_cleanup();
		return false;
	}
	if (0 != curl_easy_setopt(pCurlHandle, CURLOPT_SSL_VERIFYHOST, 0L))
	{
		curl_easy_cleanup(pCurlHandle);
		curl_global_cleanup();
		return false;
	}
	if (0 != curl_easy_setopt(pCurlHandle, CURLOPT_NOSIGNAL, 1))
	{
		curl_easy_cleanup(pCurlHandle);
		curl_global_cleanup();
		return false;
	}
	if (0 != curl_easy_setopt(pCurlHandle, CURLOPT_POST, 1L))
	{
		curl_easy_cleanup(pCurlHandle);
		curl_global_cleanup();
		return false;
	}
	if (0 != curl_easy_setopt(pCurlHandle, CURLOPT_POSTFIELDS, jsonData.c_str()))
	{
		curl_easy_cleanup(pCurlHandle);
		curl_global_cleanup();
		return false;
	}
	if (0 != curl_easy_setopt(pCurlHandle, CURLOPT_HEADERDATA, (void*)NULL))
	{
		curl_easy_cleanup(pCurlHandle);
		curl_global_cleanup();
		return false;
	}
	if (0 != curl_easy_setopt(pCurlHandle, CURLOPT_LOW_SPEED_LIMIT, 10))
	{
		curl_easy_cleanup(pCurlHandle);
		curl_global_cleanup();
		return false;
	}
	if (0 != curl_easy_setopt(pCurlHandle, CURLOPT_LOW_SPEED_TIME, 10))
	{
		curl_easy_cleanup(pCurlHandle);
		curl_global_cleanup();
		return false;
	}
	if (0 != curl_easy_setopt(pCurlHandle, CURLOPT_HTTPHEADER, HeaderData))
	{
		curl_easy_cleanup(pCurlHandle);
		curl_global_cleanup();
		return false;
	}

	int iRetVal = curl_easy_perform(pCurlHandle);
	if (0 != iRetVal)
	{
		std::string strLog = curl_easy_strerror((CURLcode)iRetVal);
		strLog = "curl_easy_perform() Failed : " + strLog + "";
		strLog = std::string(chCurlErrorBuffer) + "";

		curl_easy_cleanup(pCurlHandle);
		curl_global_cleanup();
		return false;
	}

	return true;
}

bool ProcessManager::GetRunningProcessList()
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        wprintf(L"\n CreateToolhelp32Snapshot failed with Error(%u)", GetLastError());
        return false;
    }

	bool boRet;
	std::wstring processPath;
	PROCESSENTRY32 processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &processEntry) == TRUE)
    {
        do
        {
			boRet = GetProcessPathFromPid(processEntry.th32ProcessID, processPath);
			if (false == boRet)
			{
				processPath = processEntry.szExeFile;
			}

            wprintf(L"\n Process ID: %u \t Process Name(%s)", processEntry.th32ProcessID, processPath.c_str());

			m_runningProcessList.push_back(std::make_shared<ProcessInfo>(processEntry.th32ProcessID, processPath));

        } while (Process32Next(hSnapshot, &processEntry) == TRUE);
    }
    else
    {
        wprintf(L"\n Process32First failed with Error(%u)", GetLastError());
    }

    CloseHandle(hSnapshot);

    return true;
}


bool ProcessManager::GetProcessPathFromPid(DWORD dwProcessId, std::wstring& processName)
{
	DWORD dwRetVal;
	HANDLE hProcess;
	WCHAR procPath[MAX_PATH];

	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dwProcessId);
	if (NULL == hProcess)
	{
		return false;
	}

	dwRetVal = GetModuleFileNameEx(hProcess, NULL, procPath, MAX_PATH);
	if (0 == dwRetVal)
	{
		//wprintf(L"GetModuleFileNameEx failed with error(%d)", GetLastError());
		CloseHandle(hProcess);
		return false;
	}

	//	Fill out parameter.
	processName.assign(procPath);

	CloseHandle(hProcess);
	return true;
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

