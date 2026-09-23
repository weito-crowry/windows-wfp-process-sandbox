#pragma once

#include <windows.h>

#include <string>
#include <vector>

bool RunProcessAndWait(const std::wstring& applicationPath,
                       const std::vector<std::wstring>& arguments,
                       DWORD& exitCode);
