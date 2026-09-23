#include "process_runner.h"
#include "user_identity.h"
#include "wfp_session.h"

#include <windows.h>

#include <iostream>
#include <string>
#include <vector>

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

bool IsAdministrator() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        PrintWindowsError(L"OpenProcessToken", GetLastError());
        return false;
    }

    TOKEN_ELEVATION elevation{};
    DWORD returnedSize = 0;
    const BOOL querySucceeded = GetTokenInformation(token,
                                                    TokenElevation,
                                                    &elevation,
                                                    sizeof(elevation),
                                                    &returnedSize);
    const DWORD errorCode = querySucceeded ? ERROR_SUCCESS : GetLastError();
    CloseHandle(token);
    if (!querySucceeded) {
        PrintWindowsError(L"GetTokenInformation", errorCode);
        return false;
    }
    return elevation.TokenIsElevated != 0;
}

bool NormalizeExecutablePath(const std::wstring& input, std::wstring& absolutePath) {
    DWORD capacity = GetFullPathNameW(input.c_str(), 0, nullptr, nullptr);
    if (capacity == 0) {
        PrintWindowsError(L"GetFullPathNameW", GetLastError());
        return false;
    }

    std::vector<wchar_t> buffer(capacity);
    DWORD length = GetFullPathNameW(input.c_str(), capacity, buffer.data(), nullptr);
    if (length == 0) {
        PrintWindowsError(L"GetFullPathNameW", GetLastError());
        return false;
    }
    if (length >= capacity) {
        buffer.resize(static_cast<size_t>(length) + 1);
        length = GetFullPathNameW(input.c_str(), static_cast<DWORD>(buffer.size()), buffer.data(), nullptr);
        if (length == 0 || length >= buffer.size()) {
            PrintWindowsError(L"GetFullPathNameW", GetLastError());
            return false;
        }
    }
    absolutePath.assign(buffer.data(), length);

    const DWORD attributes = GetFileAttributesW(absolutePath.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        PrintWindowsError(L"GetFileAttributesW", GetLastError());
        return false;
    }
    if ((attributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
        std::wcerr << L"--app must name an executable file, not a directory.\n";
        return false;
    }
    return true;
}

bool MakeAbsolutePath(const std::wstring& input, std::wstring& absolutePath) {
    DWORD capacity = GetFullPathNameW(input.c_str(), 0, nullptr, nullptr);
    if (capacity == 0) {
        PrintWindowsError(L"GetFullPathNameW", GetLastError());
        return false;
    }

    std::vector<wchar_t> buffer(capacity);
    DWORD length = GetFullPathNameW(input.c_str(), capacity, buffer.data(), nullptr);
    if (length == 0) {
        PrintWindowsError(L"GetFullPathNameW", GetLastError());
        return false;
    }
    if (length >= capacity) {
        buffer.resize(static_cast<size_t>(length) + 1);
        length = GetFullPathNameW(input.c_str(), static_cast<DWORD>(buffer.size()), buffer.data(), nullptr);
        if (length == 0 || length >= buffer.size()) {
            PrintWindowsError(L"GetFullPathNameW", GetLastError());
            return false;
        }
    }
    absolutePath.assign(buffer.data(), length);
    return true;
}

bool VerifyAllowedExecutableExists(const std::wstring& absolutePath) {
    const DWORD attributes = GetFileAttributesW(absolutePath.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        const DWORD errorCode = GetLastError();
        if (errorCode == ERROR_FILE_NOT_FOUND || errorCode == ERROR_PATH_NOT_FOUND) {
            std::wcerr << L"app not found: " << absolutePath << L'\n';
        }
        PrintWindowsError(L"GetFileAttributesW", errorCode);
        return false;
    }
    if ((attributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
        std::wcerr << L"app not found: --allow-app must name an executable file, not a directory.\n";
        return false;
    }
    return true;
}

bool GetComputerNameString(std::wstring& computerName) {
    wchar_t buffer[MAX_COMPUTERNAME_LENGTH + 1]{};
    DWORD length = ARRAYSIZE(buffer);
    if (!GetComputerNameW(buffer, &length)) {
        PrintWindowsError(L"GetComputerNameW", GetLastError());
        return false;
    }
    computerName.assign(buffer, length);
    return true;
}

std::wstring MakeResolvedUserDisplayName(const UserIdentity& identity,
                                         const std::wstring& computerName) {
    const std::wstring& resolvedDomain = identity.resolvedDomain();
    const bool isLocalComputerDomain = resolvedDomain.empty() ||
        CompareStringOrdinal(resolvedDomain.c_str(), -1, computerName.c_str(), -1, TRUE) == CSTR_EQUAL;
    const std::wstring& domain = isLocalComputerDomain ? computerName : resolvedDomain;
    return domain + L"\\" + identity.resolvedAccountName();
}

void PrintUsage() {
    std::wcerr << L"Usage:\n"
               << L"  WfpProcessSandbox.exe run --app <EXE_PATH> -- <arguments...>\n"
               << L"  WfpProcessSandbox.exe hold --app <EXE_PATH>\n";
}

void PrintUserHoldUsage() {
    std::wcerr << L"Usage:\n"
               << L"  WfpProcessSandbox.exe user-hold --user <USERNAME> --allow-app <EXE_PATH>\n";
}

bool IsOption(const wchar_t* value, const wchar_t* expected) {
    return value != nullptr && std::wstring(value) == expected;
}

HANDLE g_controlEvent = nullptr;

BOOL WINAPI ConsoleControlHandler(DWORD controlType) {
    if (controlType == CTRL_C_EVENT || controlType == CTRL_BREAK_EVENT) {
        if (g_controlEvent != nullptr) {
            return SetEvent(g_controlEvent) ? TRUE : FALSE;
        }
        return FALSE;
    }
    return FALSE;
}

int RunMode(const std::wstring& appArgument, const std::vector<std::wstring>& arguments) {
    if (!IsAdministrator()) {
        std::wcerr << L"Administrator privileges are required for WFP management.\n";
        return 1;
    }

    std::wstring appPath;
    if (!NormalizeExecutablePath(appArgument, appPath)) {
        return 1;
    }

    WfpSession session;
    if (!session.OpenDynamic() || !session.AddPocSublayer() ||
        !session.AddTcpBlockFilters(appPath)) {
        return 1;
    }

    DWORD targetExitCode = 0;
    const bool processSucceeded = RunProcessAndWait(appPath, arguments, targetExitCode);
    const bool cleanupSucceeded = session.Close();
    if (!processSucceeded || !cleanupSucceeded) {
        return 1;
    }

    std::wcout << L"TARGET_EXIT_CODE=" << targetExitCode << L'\n';
    return static_cast<int>(targetExitCode);
}

int HoldMode(const std::wstring& appArgument) {
    if (!IsAdministrator()) {
        std::wcerr << L"Administrator privileges are required for WFP management.\n";
        return 1;
    }

    std::wstring appPath;
    if (!NormalizeExecutablePath(appArgument, appPath)) {
        return 1;
    }

    WfpSession session;
    if (!session.OpenDynamic() || !session.AddPocSublayer() ||
        !session.AddTcpBlockFilters(appPath)) {
        return 1;
    }

    HANDLE controlEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (controlEvent == nullptr) {
        PrintWindowsError(L"CreateEventW", GetLastError());
        return 1;
    }
    g_controlEvent = controlEvent;
    if (!SetConsoleCtrlHandler(ConsoleControlHandler, TRUE)) {
        PrintWindowsError(L"SetConsoleCtrlHandler", GetLastError());
        g_controlEvent = nullptr;
        CloseHandle(controlEvent);
        return 1;
    }

    std::wcout << L"ACTIVE: IPv4 and IPv6 TCP outbound BLOCK for " << appPath << L"\n"
               << L"Press Ctrl+C to close the dynamic WFP session.\n";
    std::wcout.flush();

    const DWORD waitResult = WaitForSingleObject(controlEvent, INFINITE);
    SetConsoleCtrlHandler(ConsoleControlHandler, FALSE);
    g_controlEvent = nullptr;
    CloseHandle(controlEvent);

    if (waitResult != WAIT_OBJECT_0) {
        if (waitResult == WAIT_FAILED) {
            PrintWindowsError(L"WaitForSingleObject", GetLastError());
        } else {
            std::wcerr << L"WaitForSingleObject returned unexpected value " << waitResult << L".\n";
        }
        return 1;
    }

    return session.Close() ? 0 : 1;
}

int UserHoldMode(const std::wstring& userArgument, const std::wstring& appArgument) {
    UserIdentity identity;
    if (!identity.Resolve(userArgument)) {
        return 1;
    }

    std::wstring computerName;
    if (!GetComputerNameString(computerName)) {
        return 1;
    }
    const std::wstring resolvedUser = MakeResolvedUserDisplayName(identity, computerName);
    std::wcout << L"Resolved user: " << resolvedUser << L'\n'
               << L"SID: " << identity.sidString() << L'\n';

    std::wstring appPath;
    if (!MakeAbsolutePath(appArgument, appPath) || !VerifyAllowedExecutableExists(appPath)) {
        return 1;
    }

    WfpAppId appId;
    if (!appId.Resolve(appPath) || appId.get() == nullptr) {
        return 1;
    }

    UserSecurityDescriptor userSecurityDescriptor;
    WfpSession session;
    if (!session.OpenDynamic() || !session.BeginUserIsolationTransaction() ||
        !session.AddUserIsolationSublayer()) {
        return 1;
    }

    if (!userSecurityDescriptor.BuildForUser(identity.sid())) {
        return 1;
    }

    UINT64 filterIds[4]{};
    const FWP_BYTE_BLOB descriptorBlob = userSecurityDescriptor.Blob();
    if (!session.AddUserIsolationFilters(*appId.get(), descriptorBlob, filterIds) ||
        !session.CommitUserIsolationTransaction()) {
        return 1;
    }

    std::wcout << L"Filter ID IPv4 PERMIT: " << filterIds[0] << L'\n'
               << L"Filter ID IPv4 BLOCK: " << filterIds[1] << L'\n'
               << L"Filter ID IPv6 PERMIT: " << filterIds[2] << L'\n'
               << L"Filter ID IPv6 BLOCK: " << filterIds[3] << L'\n';

    HANDLE controlEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (controlEvent == nullptr) {
        PrintWindowsError(L"CreateEventW", GetLastError());
        return 1;
    }
    g_controlEvent = controlEvent;
    if (!SetConsoleCtrlHandler(ConsoleControlHandler, TRUE)) {
        PrintWindowsError(L"SetConsoleCtrlHandler", GetLastError());
        g_controlEvent = nullptr;
        if (!CloseHandle(controlEvent)) {
            PrintWindowsError(L"CloseHandle(controlEvent)", GetLastError());
        }
        return 1;
    }

    std::wcout << L"USER_ISOLATION_ACTIVE\n"
               << L"User: " << resolvedUser << L'\n'
               << L"SID: " << identity.sidString() << L'\n'
               << L"Allowed app: " << appPath << L'\n'
               << L"Policy: TCP PERMIT allowed-app / BLOCK other apps\n"
               << L"IPv4: ACTIVE\n"
               << L"IPv6: ACTIVE\n"
               << L"Press Ctrl+C to close the dynamic WFP session.\n";
    std::wcout.flush();

    const DWORD waitResult = WaitForSingleObject(controlEvent, INFINITE);
    bool cleanupSucceeded = true;
    if (!SetConsoleCtrlHandler(ConsoleControlHandler, FALSE)) {
        PrintWindowsError(L"SetConsoleCtrlHandler", GetLastError());
        cleanupSucceeded = false;
    }
    g_controlEvent = nullptr;
    if (!CloseHandle(controlEvent)) {
        PrintWindowsError(L"CloseHandle(controlEvent)", GetLastError());
        cleanupSucceeded = false;
    }

    if (waitResult != WAIT_OBJECT_0) {
        if (waitResult == WAIT_FAILED) {
            PrintWindowsError(L"WaitForSingleObject", GetLastError());
        } else {
            std::wcerr << L"WaitForSingleObject returned unexpected value " << waitResult << L".\n";
        }
        return 1;
    }

    return session.Close() && cleanupSucceeded ? 0 : 1;
}

}  // namespace

int wmain(int argc, wchar_t* argv[]) {
    if (argc >= 2 && IsOption(argv[1], L"user-hold")) {
        if (!IsAdministrator()) {
            std::wcerr << L"Administrator privileges required.\n";
            return 1;
        }
        if (argc != 6 || !IsOption(argv[2], L"--user") || argv[3][0] == L'\0' ||
            !IsOption(argv[4], L"--allow-app") || argv[5][0] == L'\0') {
            PrintUserHoldUsage();
            return 2;
        }
        return UserHoldMode(argv[3], argv[5]);
    }

    if (argc >= 2 && IsOption(argv[1], L"run")) {
        if (argc < 5 || !IsOption(argv[2], L"--app") || !IsOption(argv[4], L"--") ||
            argv[3][0] == L'\0') {
            PrintUsage();
            return 2;
        }
        std::vector<std::wstring> arguments;
        for (int index = 5; index < argc; ++index) {
            arguments.emplace_back(argv[index]);
        }
        return RunMode(argv[3], arguments);
    }

    if (argc >= 2 && IsOption(argv[1], L"hold")) {
        if (argc != 4 || !IsOption(argv[2], L"--app") || argv[3][0] == L'\0') {
            PrintUsage();
            return 2;
        }
        return HoldMode(argv[3]);
    }

    PrintUsage();
    return 2;
}
