#include <winsock2.h>

#include "wfp_session.h"

#include <fwpmu.h>
#include <rpcdce.h>

#include <iostream>

namespace {

// Fixed PoC-only Sublayer GUID: 2dfa9fcd-e74e-43fe-92e7-5b78c3e93e32
const GUID kPocSublayerKey = {
    0x2dfa9fcd,
    0xe74e,
    0x43fe,
    {0x92, 0xe7, 0x5b, 0x78, 0xc3, 0xe9, 0x3e, 0x32},
};

// Fixed Phase 2-only Sublayer GUID: 8ae41945-9f24-4e51-b356-8c3be4467e29
const GUID kUserIsolationSublayerKey = {
    0x8ae41945,
    0x9f24,
    0x4e51,
    {0xb3, 0x56, 0x8c, 0x3b, 0xe4, 0x46, 0x7e, 0x29},
};

constexpr UINT64 kUserIsolationPermitWeight = 0xF000000000000000ULL;
constexpr UINT64 kUserIsolationBlockWeight = 0x1000000000000000ULL;

void PrintWfpError(const wchar_t* apiName, DWORD errorCode) {
    std::wcerr << apiName << " failed: Win32 error code=" << errorCode
               << " (0x" << std::hex << errorCode << std::dec << ")";

    HMODULE fwpuclnt = LoadLibraryW(L"fwpuclnt.dll");
    LPWSTR message = nullptr;
    DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS;
    DWORD length = 0;
    if (fwpuclnt != nullptr) {
        length = FormatMessageW(flags | FORMAT_MESSAGE_FROM_HMODULE,
                                fwpuclnt,
                                errorCode,
                                0,
                                reinterpret_cast<LPWSTR>(&message),
                                0,
                                nullptr);
    }
    if (length == 0) {
        length = FormatMessageW(flags | FORMAT_MESSAGE_FROM_SYSTEM,
                                nullptr,
                                errorCode,
                                0,
                                reinterpret_cast<LPWSTR>(&message),
                                0,
                                nullptr);
    }
    if (length != 0 && message != nullptr) {
        while (length > 0 && (message[length - 1] == L'\r' || message[length - 1] == L'\n')) {
            message[--length] = L'\0';
        }
        std::wcerr << ": " << message;
    }
    std::wcerr << L'\n';

    if (message != nullptr) {
        LocalFree(message);
    }
    if (fwpuclnt != nullptr) {
        FreeLibrary(fwpuclnt);
    }
}

struct AppIdOwner final {
    FWP_BYTE_BLOB* value = nullptr;

    ~AppIdOwner() {
        if (value != nullptr) {
            FwpmFreeMemory0(reinterpret_cast<void**>(&value));
        }
    }
};

bool AddTcpBlockFilter(HANDLE engine,
                       const GUID& layerKey,
                       const GUID& sublayerKey,
                       FWP_BYTE_BLOB* appId,
                       const wchar_t* displayName) {
    FWPM_FILTER_CONDITION0 conditions[2]{};

    conditions[0].fieldKey = FWPM_CONDITION_ALE_APP_ID;
    conditions[0].matchType = FWP_MATCH_EQUAL;
    conditions[0].conditionValue.type = FWP_BYTE_BLOB_TYPE;
    conditions[0].conditionValue.byteBlob = appId;

    conditions[1].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
    conditions[1].matchType = FWP_MATCH_EQUAL;
    conditions[1].conditionValue.type = FWP_UINT8;
    conditions[1].conditionValue.uint8 = IPPROTO_TCP;

    FWPM_FILTER0 filter{};
    filter.displayData.name = const_cast<wchar_t*>(displayName);
    filter.layerKey = layerKey;
    filter.subLayerKey = sublayerKey;
    filter.weight.type = FWP_EMPTY;
    filter.numFilterConditions = ARRAYSIZE(conditions);
    filter.filterCondition = conditions;
    filter.action.type = FWP_ACTION_BLOCK;

    const DWORD status = FwpmFilterAdd0(engine, &filter, nullptr, nullptr);
    if (status != ERROR_SUCCESS) {
        PrintWfpError(L"FwpmFilterAdd0", status);
        return false;
    }
    return true;
}

bool AddUserIsolationFilter(HANDLE engine,
                            const GUID& layerKey,
                            const FWP_BYTE_BLOB& userSecurityDescriptor,
                            const FWP_BYTE_BLOB* appId,
                            FWP_ACTION_TYPE actionType,
                            UINT64 weight,
                            const wchar_t* displayName,
                            const wchar_t* filterLabel,
                            UINT64* filterId) {
    FWPM_FILTER_CONDITION0 conditions[3]{};
    UINT32 conditionCount = 0;

    conditions[conditionCount].fieldKey = FWPM_CONDITION_ALE_USER_ID;
    conditions[conditionCount].matchType = FWP_MATCH_EQUAL;
    conditions[conditionCount].conditionValue.type = FWP_SECURITY_DESCRIPTOR_TYPE;
    conditions[conditionCount].conditionValue.sd =
        const_cast<FWP_BYTE_BLOB*>(&userSecurityDescriptor);
    ++conditionCount;

    if (appId != nullptr) {
        conditions[conditionCount].fieldKey = FWPM_CONDITION_ALE_APP_ID;
        conditions[conditionCount].matchType = FWP_MATCH_EQUAL;
        conditions[conditionCount].conditionValue.type = FWP_BYTE_BLOB_TYPE;
        conditions[conditionCount].conditionValue.byteBlob = const_cast<FWP_BYTE_BLOB*>(appId);
        ++conditionCount;
    }

    conditions[conditionCount].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
    conditions[conditionCount].matchType = FWP_MATCH_EQUAL;
    conditions[conditionCount].conditionValue.type = FWP_UINT8;
    conditions[conditionCount].conditionValue.uint8 = IPPROTO_TCP;
    ++conditionCount;

    FWPM_FILTER0 filter{};
    filter.displayData.name = const_cast<wchar_t*>(displayName);
    filter.layerKey = layerKey;
    filter.subLayerKey = kUserIsolationSublayerKey;
    filter.weight.type = FWP_UINT64;
    filter.weight.uint64 = &weight;
    filter.numFilterConditions = conditionCount;
    filter.filterCondition = conditions;
    filter.action.type = actionType;

    const DWORD status = FwpmFilterAdd0(engine, &filter, nullptr, filterId);
    if (status != ERROR_SUCCESS) {
        std::wcerr << filterLabel << L" filter failure.\n";
        PrintWfpError(L"FwpmFilterAdd0", status);
        return false;
    }
    return true;
}

}  // namespace

WfpAppId::~WfpAppId() {
    if (value_ != nullptr) {
        FwpmFreeMemory0(reinterpret_cast<void**>(&value_));
    }
}

bool WfpAppId::Resolve(const std::wstring& absoluteAppPath) {
    if (value_ != nullptr) {
        FwpmFreeMemory0(reinterpret_cast<void**>(&value_));
    }

    const DWORD status = FwpmGetAppIdFromFileName0(absoluteAppPath.c_str(), &value_);
    if (status != ERROR_SUCCESS) {
        if (status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND) {
            std::wcerr << L"app not found: " << absoluteAppPath << L'\n';
        }
        PrintWfpError(L"FwpmGetAppIdFromFileName0", status);
        return false;
    }
    return true;
}

const FWP_BYTE_BLOB* WfpAppId::get() const {
    return value_;
}

WfpSession::~WfpSession() {
    Close();
}

bool WfpSession::OpenDynamic() {
    if (engine_ != nullptr) {
        std::wcerr << L"FwpmEngineOpen0 was requested while a session is already open.\n";
        return false;
    }

    FWPM_SESSION0 session{};
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;

    const DWORD status = FwpmEngineOpen0(
        nullptr, RPC_C_AUTHN_WINNT, nullptr, &session, &engine_);
    if (status != ERROR_SUCCESS) {
        PrintWfpError(L"FwpmEngineOpen0", status);
        return false;
    }
    return true;
}

bool WfpSession::AddPocSublayer() {
    if (engine_ == nullptr) {
        std::wcerr << L"FwpmSubLayerAdd0 failed: dynamic WFP session is not open.\n";
        return false;
    }

    FWPM_SUBLAYER0 sublayer{};
    sublayer.subLayerKey = kPocSublayerKey;
    sublayer.displayData.name = const_cast<wchar_t*>(L"WfpProcessSandbox PoC Sublayer");
    sublayer.weight = 0x100;

    const DWORD status = FwpmSubLayerAdd0(engine_, &sublayer, nullptr);
    if (status != ERROR_SUCCESS) {
        PrintWfpError(L"FwpmSubLayerAdd0", status);
        return false;
    }
    return true;
}

bool WfpSession::AddTcpBlockFilters(const std::wstring& appPath) {
    if (engine_ == nullptr) {
        std::wcerr << L"FwpmGetAppIdFromFileName0 failed: dynamic WFP session is not open.\n";
        return false;
    }

    AppIdOwner appId;
    const DWORD appIdStatus = FwpmGetAppIdFromFileName0(appPath.c_str(), &appId.value);
    if (appIdStatus != ERROR_SUCCESS) {
        PrintWfpError(L"FwpmGetAppIdFromFileName0", appIdStatus);
        return false;
    }

    if (!AddTcpBlockFilter(engine_,
                           FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                           kPocSublayerKey,
                           appId.value,
                           L"WfpProcessSandbox IPv4 TCP BLOCK")) {
        return false;
    }

    return AddTcpBlockFilter(engine_,
                             FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                             kPocSublayerKey,
                             appId.value,
                             L"WfpProcessSandbox IPv6 TCP BLOCK");
}

bool WfpSession::BeginUserIsolationTransaction() {
    if (engine_ == nullptr) {
        std::wcerr << L"transaction failure: dynamic WFP session is not open.\n";
        return false;
    }
    if (transactionOpen_) {
        std::wcerr << L"transaction failure: a WFP transaction is already open.\n";
        return false;
    }

    const DWORD status = FwpmTransactionBegin0(engine_, 0);
    if (status != ERROR_SUCCESS) {
        PrintWfpError(L"transaction failure: FwpmTransactionBegin0", status);
        return false;
    }
    transactionOpen_ = true;
    return true;
}

bool WfpSession::AddUserIsolationSublayer() {
    if (engine_ == nullptr || !transactionOpen_) {
        std::wcerr << L"Phase 2 Sublayer add failure: dynamic WFP transaction is not open.\n";
        return false;
    }

    FWPM_SUBLAYER0 sublayer{};
    sublayer.subLayerKey = kUserIsolationSublayerKey;
    sublayer.displayData.name =
        const_cast<wchar_t*>(L"WfpProcessSandbox User Isolation PoC Sublayer");
    sublayer.weight = 0x100;

    const DWORD status = FwpmSubLayerAdd0(engine_, &sublayer, nullptr);
    if (status != ERROR_SUCCESS) {
        std::wcerr << L"Phase 2 Sublayer add failure.\n";
        PrintWfpError(L"FwpmSubLayerAdd0", status);
        return false;
    }
    return true;
}

bool WfpSession::AddUserIsolationFilters(const FWP_BYTE_BLOB& appId,
                                         const FWP_BYTE_BLOB& userSecurityDescriptor,
                                         UINT64 filterIds[4]) {
    if (engine_ == nullptr || !transactionOpen_) {
        std::wcerr << L"Phase 2 filter add failure: dynamic WFP transaction is not open.\n";
        return false;
    }

    return AddUserIsolationFilter(engine_,
                                  FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                                  userSecurityDescriptor,
                                  &appId,
                                  FWP_ACTION_PERMIT,
                                  kUserIsolationPermitWeight,
                                  L"WfpProcessSandbox IPv4 TCP PERMIT allowed app",
                                  L"IPv4 PERMIT",
                                  &filterIds[0]) &&
           AddUserIsolationFilter(engine_,
                                  FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                                  userSecurityDescriptor,
                                  nullptr,
                                  FWP_ACTION_BLOCK,
                                  kUserIsolationBlockWeight,
                                  L"WfpProcessSandbox IPv4 TCP BLOCK other apps",
                                  L"IPv4 BLOCK",
                                  &filterIds[1]) &&
           AddUserIsolationFilter(engine_,
                                  FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                                  userSecurityDescriptor,
                                  &appId,
                                  FWP_ACTION_PERMIT,
                                  kUserIsolationPermitWeight,
                                  L"WfpProcessSandbox IPv6 TCP PERMIT allowed app",
                                  L"IPv6 PERMIT",
                                  &filterIds[2]) &&
           AddUserIsolationFilter(engine_,
                                  FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                                  userSecurityDescriptor,
                                  nullptr,
                                  FWP_ACTION_BLOCK,
                                  kUserIsolationBlockWeight,
                                  L"WfpProcessSandbox IPv6 TCP BLOCK other apps",
                                  L"IPv6 BLOCK",
                                  &filterIds[3]);
}

bool WfpSession::CommitUserIsolationTransaction() {
    if (engine_ == nullptr || !transactionOpen_) {
        std::wcerr << L"transaction failure: dynamic WFP transaction is not open.\n";
        return false;
    }

    const DWORD status = FwpmTransactionCommit0(engine_);
    if (status != ERROR_SUCCESS) {
        PrintWfpError(L"transaction failure: FwpmTransactionCommit0", status);
        return false;
    }
    transactionOpen_ = false;
    return true;
}

bool WfpSession::Close() {
    if (engine_ == nullptr) {
        return true;
    }

    bool succeeded = true;
    if (transactionOpen_) {
        const DWORD abortStatus = FwpmTransactionAbort0(engine_);
        transactionOpen_ = false;
        if (abortStatus != ERROR_SUCCESS) {
            PrintWfpError(L"transaction failure: FwpmTransactionAbort0", abortStatus);
            succeeded = false;
        }
    }

    HANDLE engine = engine_;
    const DWORD status = FwpmEngineClose0(engine);
    if (status != ERROR_SUCCESS) {
        PrintWfpError(L"FwpmEngineClose0", status);
        return false;
    }
    engine_ = nullptr;
    std::wcout << L"WFP_DYNAMIC_SESSION_CLOSED\n";
    return succeeded;
}
