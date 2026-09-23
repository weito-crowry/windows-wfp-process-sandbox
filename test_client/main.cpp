#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

namespace {

constexpr DWORD kConnectTimeoutMs = 5000;
constexpr DWORD kCurlWaitTimeoutMs = 25000;

class WinsockLifetime final {
public:
    bool Start() {
        const int result = WSAStartup(MAKEWORD(2, 2), &data_);
        if (result != 0) {
            error_ = result;
            return false;
        }
        started_ = true;
        return true;
    }

    ~WinsockLifetime() {
        if (started_) {
            WSACleanup();
        }
    }

    int error() const { return error_; }

private:
    WSADATA data_{};
    bool started_ = false;
    int error_ = 0;
};

class SocketOwner final {
public:
    explicit SocketOwner(SOCKET socket = INVALID_SOCKET) : socket_(socket) {}
    ~SocketOwner() {
        if (socket_ != INVALID_SOCKET) {
            closesocket(socket_);
        }
    }
    SocketOwner(const SocketOwner&) = delete;
    SocketOwner& operator=(const SocketOwner&) = delete;
    SOCKET get() const { return socket_; }

private:
    SOCKET socket_;
};

int ParsePort(const wchar_t* value, unsigned short& port) {
    wchar_t* end = nullptr;
    const unsigned long parsed = wcstoul(value, &end, 10);
    if (value[0] == L'\0' || end == value || *end != L'\0' || parsed == 0 || parsed > 65535) {
        return WSAEINVAL;
    }
    port = static_cast<unsigned short>(parsed);
    return 0;
}

bool ConnectWithTimeout(SOCKET socket, const sockaddr* address, int addressLength, int& errorCode) {
    u_long nonBlocking = 1;
    if (ioctlsocket(socket, FIONBIO, &nonBlocking) == SOCKET_ERROR) {
        errorCode = WSAGetLastError();
        return false;
    }

    if (connect(socket, address, addressLength) == 0) {
        return true;
    }

    errorCode = WSAGetLastError();
    if (errorCode != WSAEWOULDBLOCK && errorCode != WSAEINPROGRESS && errorCode != WSAEINVAL) {
        return false;
    }

    fd_set writeSet;
    fd_set exceptionSet;
    FD_ZERO(&writeSet);
    FD_ZERO(&exceptionSet);
    FD_SET(socket, &writeSet);
    FD_SET(socket, &exceptionSet);

    timeval timeout{};
    timeout.tv_sec = static_cast<long>(kConnectTimeoutMs / 1000);
    timeout.tv_usec = static_cast<long>((kConnectTimeoutMs % 1000) * 1000);
    const int selectResult = select(0, nullptr, &writeSet, &exceptionSet, &timeout);
    if (selectResult == 0) {
        errorCode = WSAETIMEDOUT;
        return false;
    }
    if (selectResult == SOCKET_ERROR) {
        errorCode = WSAGetLastError();
        return false;
    }

    int socketError = 0;
    int optionLength = sizeof(socketError);
    if (getsockopt(socket, SOL_SOCKET, SO_ERROR,
                   reinterpret_cast<char*>(&socketError), &optionLength) == SOCKET_ERROR) {
        errorCode = WSAGetLastError();
        return false;
    }
    if (socketError != 0) {
        errorCode = socketError;
        return false;
    }
    return true;
}

int RunTcp(const wchar_t* addressText, const wchar_t* portText) {
    WinsockLifetime winsock;
    if (!winsock.Start()) {
        std::wcout << L"CONNECT_FAILED error=" << winsock.error() << L'\n';
        return 1;
    }

    unsigned short port = 0;
    const int portError = ParsePort(portText, port);
    if (portError != 0) {
        std::wcout << L"CONNECT_FAILED error=" << portError << L'\n';
        return 1;
    }

    sockaddr_in address4{};
    address4.sin_family = AF_INET;
    address4.sin_port = htons(port);
    if (InetPtonW(AF_INET, addressText, &address4.sin_addr) == 1) {
        SocketOwner socketOwner(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
        if (socketOwner.get() == INVALID_SOCKET) {
            std::wcout << L"CONNECT_FAILED error=" << WSAGetLastError() << L'\n';
            return 1;
        }
        int errorCode = 0;
        if (!ConnectWithTimeout(socketOwner.get(),
                                reinterpret_cast<const sockaddr*>(&address4),
                                sizeof(address4),
                                errorCode)) {
            std::wcout << L"CONNECT_FAILED error=" << errorCode << L'\n';
            return 1;
        }
        std::wcout << L"CONNECT_SUCCESS\n";
        return 0;
    }

    sockaddr_in6 address6{};
    address6.sin6_family = AF_INET6;
    address6.sin6_port = htons(port);
    if (InetPtonW(AF_INET6, addressText, &address6.sin6_addr) == 1) {
        SocketOwner socketOwner(socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP));
        if (socketOwner.get() == INVALID_SOCKET) {
            std::wcout << L"CONNECT_FAILED error=" << WSAGetLastError() << L'\n';
            return 1;
        }
        int errorCode = 0;
        if (!ConnectWithTimeout(socketOwner.get(),
                                reinterpret_cast<const sockaddr*>(&address6),
                                sizeof(address6),
                                errorCode)) {
            std::wcout << L"CONNECT_FAILED error=" << errorCode << L'\n';
            return 1;
        }
        std::wcout << L"CONNECT_SUCCESS\n";
        return 0;
    }

    std::wcout << L"CONNECT_FAILED error=" << WSAEINVAL << L'\n';
    std::wcerr << L"IP address must be a literal IPv4 or IPv6 address; DNS names are not accepted.\n";
    return 1;
}

int RunLoopback(bool ipv6) {
    WinsockLifetime winsock;
    if (!winsock.Start()) {
        std::wcout << L"LOOPBACK_CONNECT_FAILED\n";
        std::wcerr << L"WSAStartup error=" << winsock.error() << L'\n';
        return 1;
    }

    const int family = ipv6 ? AF_INET6 : AF_INET;
    SocketOwner listener(socket(family, SOCK_STREAM, IPPROTO_TCP));
    if (listener.get() == INVALID_SOCKET) {
        std::wcout << L"LOOPBACK_CONNECT_FAILED\n";
        std::wcerr << L"socket error=" << WSAGetLastError() << L'\n';
        return 1;
    }

    sockaddr_storage address{};
    int addressLength = 0;
    if (ipv6) {
        auto* address6 = reinterpret_cast<sockaddr_in6*>(&address);
        address6->sin6_family = AF_INET6;
        address6->sin6_addr = in6addr_loopback;
        addressLength = sizeof(*address6);
    } else {
        auto* address4 = reinterpret_cast<sockaddr_in*>(&address);
        address4->sin_family = AF_INET;
        address4->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addressLength = sizeof(*address4);
    }

    if (bind(listener.get(), reinterpret_cast<const sockaddr*>(&address), addressLength) == SOCKET_ERROR ||
        listen(listener.get(), SOMAXCONN) == SOCKET_ERROR) {
        const int errorCode = WSAGetLastError();
        std::wcout << L"LOOPBACK_CONNECT_FAILED\n";
        std::wcerr << L"listener setup error=" << errorCode << L'\n';
        return 1;
    }

    int boundLength = sizeof(address);
    if (getsockname(listener.get(), reinterpret_cast<sockaddr*>(&address), &boundLength) == SOCKET_ERROR) {
        const int errorCode = WSAGetLastError();
        std::wcout << L"LOOPBACK_CONNECT_FAILED\n";
        std::wcerr << L"getsockname error=" << errorCode << L'\n';
        return 1;
    }

    SocketOwner client(socket(family, SOCK_STREAM, IPPROTO_TCP));
    if (client.get() == INVALID_SOCKET) {
        std::wcout << L"LOOPBACK_CONNECT_FAILED\n";
        std::wcerr << L"socket error=" << WSAGetLastError() << L'\n';
        return 1;
    }

    int connectError = 0;
    if (!ConnectWithTimeout(client.get(),
                            reinterpret_cast<const sockaddr*>(&address),
                            boundLength,
                            connectError)) {
        std::wcout << L"LOOPBACK_CONNECT_FAILED\n";
        std::wcerr << L"connect error=" << connectError << L'\n';
        return 1;
    }

    fd_set readSet;
    FD_ZERO(&readSet);
    FD_SET(listener.get(), &readSet);
    timeval timeout{};
    timeout.tv_sec = static_cast<long>(kConnectTimeoutMs / 1000);
    timeout.tv_usec = static_cast<long>((kConnectTimeoutMs % 1000) * 1000);
    const int selectResult = select(0, &readSet, nullptr, nullptr, &timeout);
    if (selectResult <= 0) {
        const int errorCode = selectResult == 0 ? WSAETIMEDOUT : WSAGetLastError();
        std::wcout << L"LOOPBACK_CONNECT_FAILED\n";
        std::wcerr << L"accept wait error=" << errorCode << L'\n';
        return 1;
    }

    SocketOwner accepted(accept(listener.get(), nullptr, nullptr));
    if (accepted.get() == INVALID_SOCKET) {
        std::wcout << L"LOOPBACK_CONNECT_FAILED\n";
        std::wcerr << L"accept error=" << WSAGetLastError() << L'\n';
        return 1;
    }

    std::wcout << L"LOOPBACK_CONNECT_SUCCESS\n";
    return 0;
}

std::wstring QuoteArgument(const std::wstring& argument) {
    std::wstring quoted(1, L'"');
    size_t backslashCount = 0;
    for (wchar_t character : argument) {
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
        if (value.hThread != nullptr) CloseHandle(value.hThread);
        if (value.hProcess != nullptr) CloseHandle(value.hProcess);
    }
};

int RunSpawnCurl(const wchar_t* url) {
    wchar_t systemDirectory[MAX_PATH + 1]{};
    const UINT length = GetSystemDirectoryW(systemDirectory, ARRAYSIZE(systemDirectory));
    if (length == 0 || length >= ARRAYSIZE(systemDirectory)) {
        const DWORD errorCode = length == 0 ? GetLastError() : ERROR_INSUFFICIENT_BUFFER;
        std::wcerr << L"GetSystemDirectoryW failed: Win32 error code=" << errorCode << L'\n';
        return 1;
    }

    std::wstring curlPath(systemDirectory, length);
    curlPath += L"\\curl.exe";
    const DWORD attributes = GetFileAttributesW(curlPath.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
        std::wcerr << L"Windows System32 curl.exe was not found.\n";
        return 1;
    }

    std::wstring commandLine = QuoteArgument(curlPath) + L" --max-time 15 " + QuoteArgument(url);
    STARTUPINFOW startupInfo{};
    startupInfo.cb = sizeof(startupInfo);
    startupInfo.dwFlags = STARTF_USESTDHANDLES;
    startupInfo.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    startupInfo.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    startupInfo.hStdError = GetStdHandle(STD_ERROR_HANDLE);

    ProcessHandles process;
    if (!CreateProcessW(curlPath.c_str(),
                        commandLine.data(),
                        nullptr,
                        nullptr,
                        TRUE,
                        0,
                        nullptr,
                        nullptr,
                        &startupInfo,
                        &process.value)) {
        const DWORD errorCode = GetLastError();
        std::wcerr << L"CreateProcessW(curl.exe) failed: Win32 error code=" << errorCode << L'\n';
        return 1;
    }

    const DWORD waitResult = WaitForSingleObject(process.value.hProcess, kCurlWaitTimeoutMs);
    if (waitResult == WAIT_TIMEOUT) {
        TerminateProcess(process.value.hProcess, ERROR_TIMEOUT);
        WaitForSingleObject(process.value.hProcess, 5000);
        std::wcerr << L"curl.exe exceeded its finite wait timeout.\n";
        return 1;
    }
    if (waitResult != WAIT_OBJECT_0) {
        const DWORD errorCode = waitResult == WAIT_FAILED ? GetLastError() : ERROR_GEN_FAILURE;
        std::wcerr << L"WaitForSingleObject(curl.exe) failed: Win32 error code=" << errorCode << L'\n';
        return 1;
    }

    DWORD exitCode = 0;
    if (!GetExitCodeProcess(process.value.hProcess, &exitCode)) {
        std::wcerr << L"GetExitCodeProcess(curl.exe) failed: Win32 error code=" << GetLastError() << L'\n';
        return 1;
    }
    std::wcout << L"CURL_EXIT_CODE=" << exitCode << L'\n';
    return static_cast<int>(exitCode);
}

void PrintUsage() {
    std::wcerr << L"Usage:\n"
               << L"  WfpTestClient.exe tcp <IP_ADDRESS> <PORT>\n"
               << L"  WfpTestClient.exe loopback4\n"
               << L"  WfpTestClient.exe loopback6\n"
               << L"  WfpTestClient.exe spawn-curl <URL>\n";
}

}  // namespace

int wmain(int argc, wchar_t* argv[]) {
    if (argc == 4 && std::wstring(argv[1]) == L"tcp") {
        return RunTcp(argv[2], argv[3]);
    }
    if (argc == 2 && std::wstring(argv[1]) == L"loopback4") {
        return RunLoopback(false);
    }
    if (argc == 2 && std::wstring(argv[1]) == L"loopback6") {
        return RunLoopback(true);
    }
    if (argc == 3 && std::wstring(argv[1]) == L"spawn-curl") {
        return RunSpawnCurl(argv[2]);
    }

    PrintUsage();
    return 2;
}
