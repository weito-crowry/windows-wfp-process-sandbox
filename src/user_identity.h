#pragma once

#include <windows.h>
#include <fwpmu.h>

#include <string>
#include <vector>

class UserIdentity final {
public:
    bool Resolve(const std::wstring& userName);

    PSID sid() const;
    const std::wstring& sidString() const;
    const std::wstring& resolvedDomain() const;
    const std::wstring& resolvedAccountName() const;

private:
    std::vector<BYTE> sidBytes_;
    std::wstring sidString_;
    std::wstring resolvedDomain_;
    std::wstring resolvedAccountName_;
};

class UserSecurityDescriptor final {
public:
    UserSecurityDescriptor() = default;
    ~UserSecurityDescriptor();

    UserSecurityDescriptor(const UserSecurityDescriptor&) = delete;
    UserSecurityDescriptor& operator=(const UserSecurityDescriptor&) = delete;

    bool BuildForUser(PSID userSid);
    FWP_BYTE_BLOB Blob() const;

private:
    PSECURITY_DESCRIPTOR descriptor_ = nullptr;
    ULONG descriptorSize_ = 0;
};
