#pragma once

std::string ConvertWstringToString(std::wstring& wstring);

std::wstring ConvertStringToWstring(std::string& string);

bool GetWorkingDirPathW(std::wstring& folderPath, bool bIncludeLastBackslash);

bool GetPrivateProfileStringExW(
	const std::wstring sectionName,
	const std::wstring keyName,
	const std::wstring filePath,
	std::wstring& valueBuffer,
	size_t bufferSize = 1024);

