#pragma once

#include <windows.h>
#include <fwpmu.h>

#include <string>

class WfpSession final {
public:
    WfpSession() = default;
    ~WfpSession();

    WfpSession(const WfpSession&) = delete;
    WfpSession& operator=(const WfpSession&) = delete;

    bool OpenDynamic();
    bool AddPocSublayer();
    bool AddTcpBlockFilters(const std::wstring& appPath);
    bool BeginUserIsolationTransaction();
    bool AddUserIsolationSublayer();
    bool AddUserIsolationFilters(const FWP_BYTE_BLOB& appId,
                                 const FWP_BYTE_BLOB& userSecurityDescriptor,
                                 UINT64 filterIds[4]);
    bool CommitUserIsolationTransaction();
    bool Close();

private:
    HANDLE engine_ = nullptr;
    bool transactionOpen_ = false;
};

class WfpAppId final {
public:
    WfpAppId() = default;
    ~WfpAppId();

    WfpAppId(const WfpAppId&) = delete;
    WfpAppId& operator=(const WfpAppId&) = delete;

    bool Resolve(const std::wstring& absoluteAppPath);
    const FWP_BYTE_BLOB* get() const;

private:
    FWP_BYTE_BLOB* value_ = nullptr;
};
