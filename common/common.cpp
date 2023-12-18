#include <Windows.h>
#include <iostream>
#include <vector>

#include "common.h"

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

