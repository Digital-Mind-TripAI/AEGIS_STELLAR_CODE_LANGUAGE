#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>
#include <vector>

namespace stellar::service {
struct ModuleIdentity { std::wstring name; std::wstring path; std::wstring version; std::wstring sha256; DWORD volumeSerial{}; FILE_ID_128 fileId{}; };
bool HardenDllSearch();
bool IsAbsoluteFixedPath(const std::wstring& path);
bool VerifyNoReparseAncestors(const std::wstring& path);
bool VerifyProtectedNtfsRoot(const std::wstring& path, const std::wstring& brokerSid);
bool VerifySystemModule(const wchar_t* name, ModuleIdentity& result);
bool VerifyDynamicModuleAllowlist(std::vector<ModuleIdentity>& evidence);
std::wstring ServiceSidSddl(const wchar_t* serviceName, bool includeAdministrators);
bool BuildServiceSecurityDescriptor(const wchar_t* serviceName, bool includeAdministrators, PSECURITY_DESCRIPTOR* descriptor, DWORD* bytes);
}
