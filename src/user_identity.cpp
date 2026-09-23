#include "user_identity.h"

#include <accctrl.h>
#include <aclapi.h>
#include <fwpmu.h>
#include <sddl.h>

#include <iostream>
#include <vector>

namespace {

void PrintWindowsError(const wchar_t* context, const wchar_t* apiName, DWORD errorCode) {
    std::wcerr << context << L": " << apiName << L" failed: Win32 error code=" << errorCode
               << L" (0x" << std::hex << errorCode << std::dec << L")";

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

}  // namespace

bool UserIdentity::Resolve(const std::wstring& userName) {
    DWORD sidSize = 0;
    DWORD domainSize = 0;
    SID_NAME_USE sidNameUse = SidTypeUnknown;

    SetLastError(ERROR_SUCCESS);
    const BOOL firstLookupSucceeded = LookupAccountNameW(nullptr,
                                                         userName.c_str(),
                                                         nullptr,
                                                         &sidSize,
                                                         nullptr,
                                                         &domainSize,
                                                         &sidNameUse);
    const DWORD firstLookupError = firstLookupSucceeded ? ERROR_SUCCESS : GetLastError();
    if (!firstLookupSucceeded && firstLookupError != ERROR_INSUFFICIENT_BUFFER) {
        if (firstLookupError == ERROR_NONE_MAPPED) {
            std::wcerr << L"user not found: " << userName << L'\n';
            PrintWindowsError(L"SID resolution failure", L"LookupAccountNameW", firstLookupError);
        } else {
            PrintWindowsError(L"SID resolution failure", L"LookupAccountNameW", firstLookupError);
        }
        return false;
    }

    if (sidSize == 0) {
        std::wcerr << L"SID resolution failure: LookupAccountNameW returned an empty SID size.\n";
        return false;
    }

    std::vector<BYTE> sidBytes(sidSize);
    std::vector<wchar_t> domainBuffer(domainSize == 0 ? 1 : domainSize, L'\0');
    if (!LookupAccountNameW(nullptr,
                            userName.c_str(),
                            sidBytes.data(),
                            &sidSize,
                            domainBuffer.data(),
                            &domainSize,
                            &sidNameUse)) {
        const DWORD errorCode = GetLastError();
        if (errorCode == ERROR_NONE_MAPPED) {
            std::wcerr << L"user not found: " << userName << L'\n';
            PrintWindowsError(L"SID resolution failure", L"LookupAccountNameW", errorCode);
        } else {
            PrintWindowsError(L"SID resolution failure", L"LookupAccountNameW", errorCode);
        }
        return false;
    }

    if (sidNameUse != SidTypeUser || !IsValidSid(sidBytes.data())) {
        std::wcerr << L"SID resolution failure: the account did not resolve to a valid user SID.\n";
        return false;
    }

    LPWSTR sidText = nullptr;
    if (!ConvertSidToStringSidW(sidBytes.data(), &sidText)) {
        PrintWindowsError(L"SID resolution failure", L"ConvertSidToStringSidW", GetLastError());
        return false;
    }

    sidBytes_.assign(sidBytes.begin(), sidBytes.begin() + sidSize);
    sidString_.assign(sidText);
    LocalFree(sidText);

    resolvedDomain_.assign(domainBuffer.data());
    const size_t separator = userName.find_last_of(L"\\/");
    resolvedAccountName_ = separator == std::wstring::npos
                               ? userName
                               : userName.substr(separator + 1);
    return true;
}

PSID UserIdentity::sid() const {
    return sidBytes_.empty() ? nullptr : const_cast<BYTE*>(sidBytes_.data());
}

const std::wstring& UserIdentity::sidString() const {
    return sidString_;
}

const std::wstring& UserIdentity::resolvedDomain() const {
    return resolvedDomain_;
}

const std::wstring& UserIdentity::resolvedAccountName() const {
    return resolvedAccountName_;
}

UserSecurityDescriptor::~UserSecurityDescriptor() {
    if (descriptor_ != nullptr) {
        LocalFree(descriptor_);
    }
}

bool UserSecurityDescriptor::BuildForUser(PSID userSid) {
    if (userSid == nullptr || !IsValidSid(userSid)) {
        std::wcerr << L"Security Descriptor build failure: invalid user SID.\n";
        return false;
    }

    EXPLICIT_ACCESS_W access{};
    access.grfAccessPermissions = FWP_ACTRL_MATCH_FILTER;
    access.grfAccessMode = GRANT_ACCESS;
    access.grfInheritance = NO_INHERITANCE;
    access.Trustee.pMultipleTrustee = nullptr;
    access.Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
    access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    access.Trustee.TrusteeType = TRUSTEE_IS_USER;
    access.Trustee.ptstrName = reinterpret_cast<LPWSTR>(userSid);

    const DWORD status = BuildSecurityDescriptorW(nullptr,
                                                   nullptr,
                                                   1,
                                                   &access,
                                                   0,
                                                   nullptr,
                                                   nullptr,
                                                   &descriptorSize_,
                                                   &descriptor_);
    if (status != ERROR_SUCCESS) {
        PrintWindowsError(L"Security Descriptor build failure",
                          L"BuildSecurityDescriptorW",
                          status);
        if (descriptor_ != nullptr) {
            LocalFree(descriptor_);
            descriptor_ = nullptr;
        }
        descriptorSize_ = 0;
        return false;
    }
    return true;
}

FWP_BYTE_BLOB UserSecurityDescriptor::Blob() const {
    FWP_BYTE_BLOB blob{};
    blob.size = descriptorSize_;
    blob.data = reinterpret_cast<UINT8*>(descriptor_);
    return blob;
}
