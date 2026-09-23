#include "process_runner.h"

#include <iostream>

namespace {

void PrintWindowsError(const wchar_t* apiName, DWORD errorCode) {
    std::wcerr << apiName << " failed: Win32 error code=" << errorCode
               << " (0x" << std::hex << errorCode << std::dec << ")";

    LPWSTR message = nullptr;
    const DWORD length = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        errorCode,
        0,
        reinterpret_cast<LPWSTR>(&message),
        0,
        nullptr);
    if (length != 0 && message != nullptr) {
        DWORD trimmedLength = length;
        while (trimmedLength > 0 &&
               (message[trimmedLength - 1] == L'\r' || message[trimmedLength - 1] == L'\n')) {
            message[--trimmedLength] = L'\0';
        }
        std::wcerr << L": " << message;
    }
    std::wcerr << L'\n';
    if (message != nullptr) {
        LocalFree(message);
    }
}

std::wstring QuoteArgument(const std::wstring& argument) {
    std::wstring quoted;
    quoted.push_back(L'"');

    size_t backslashCount = 0;
    for (const wchar_t character : argument) {
        if (character == L'\\') {
            ++backslashCount;
            continue;
        }
        if (character == L'"') {
            quoted.append(backslashCount * 2 + 1, L'\\');
            quoted.push_back(L'"');
            backslashCount = 0;
            continue;
        }
        quoted.append(backslashCount, L'\\');
        backslashCount = 0;
        quoted.push_back(character);
    }

    quoted.append(backslashCount * 2, L'\\');
    quoted.push_back(L'"');
    return quoted;
}

class ProcessHandles final {
public:
    PROCESS_INFORMATION value{};

    ~ProcessHandles() {
        if (value.hThread != nullptr) {
            CloseHandle(value.hThread);
        }
        if (value.hProcess != nullptr) {
            CloseHandle(value.hProcess);
        }
    }
};

}  // namespace

bool RunProcessAndWait(const std::wstring& applicationPath,
                       const std::vector<std::wstring>& arguments,
                       DWORD& exitCode) {
    std::wstring commandLine = QuoteArgument(applicationPath);
    for (const std::wstring& argument : arguments) {
        commandLine.push_back(L' ');
        commandLine += QuoteArgument(argument);
    }

    STARTUPINFOW startupInfo{};
    startupInfo.cb = sizeof(startupInfo);
    startupInfo.dwFlags = STARTF_USESTDHANDLES;
    startupInfo.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    startupInfo.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    startupInfo.hStdError = GetStdHandle(STD_ERROR_HANDLE);

    ProcessHandles process;
    if (!CreateProcessW(applicationPath.c_str(),
                        commandLine.data(),
                        nullptr,
                        nullptr,
                        TRUE,
                        0,
                        nullptr,
                        nullptr,
                        &startupInfo,
                        &process.value)) {
        PrintWindowsError(L"CreateProcessW", GetLastError());
        return false;
    }

    const DWORD waitResult = WaitForSingleObject(process.value.hProcess, INFINITE);
    if (waitResult != WAIT_OBJECT_0) {
        if (waitResult == WAIT_FAILED) {
            PrintWindowsError(L"WaitForSingleObject", GetLastError());
        } else {
            std::wcerr << L"WaitForSingleObject returned unexpected value " << waitResult << L".\n";
        }
        return false;
    }

    if (!GetExitCodeProcess(process.value.hProcess, &exitCode)) {
        PrintWindowsError(L"GetExitCodeProcess", GetLastError());
        return false;
    }
    return true;
}
