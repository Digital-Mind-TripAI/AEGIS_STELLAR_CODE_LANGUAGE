#include "scm_readiness.h"
#include <aclapi.h>
#include <algorithm>
#include <vector>
#include <windows.h>
#include <winsvc.h>
#pragma comment(lib, "advapi32.lib")

namespace stellar::service {
namespace {
struct Expected { const wchar_t *name, *account, *path; };
constexpr Expected expected[] = {
  {L"AegisStellarCustodian", L"NT SERVICE\\AegisStellarCustodian",
   L"\"C:\\Program Files\\AEGIS\\Stellar\\v0.1\\bin\\AegisStellarCustodian.exe\""},
  {L"AegisStellarExecutionBroker", L"NT SERVICE\\AegisStellarExecutionBroker",
   L"\"C:\\Program Files\\AEGIS\\Stellar\\v0.1\\bin\\AegisStellarExecutionBroker.exe\""}};
bool Config2(SC_HANDLE service, DWORD level, std::vector<BYTE> &data) {
  DWORD bytes = 0;
  QueryServiceConfig2W(service, level, nullptr, 0, &bytes);
  if (!bytes || GetLastError() != ERROR_INSUFFICIENT_BUFFER) return false;
  data.resize(bytes);
  return QueryServiceConfig2W(service, level, data.data(), bytes, &bytes) != FALSE;
}
bool ExactDacl(SC_HANDLE service) {
  DWORD bytes = 0;
  QueryServiceObjectSecurity(service, DACL_SECURITY_INFORMATION, nullptr, 0, &bytes);
  if (!bytes || GetLastError() != ERROR_INSUFFICIENT_BUFFER) return false;
  std::vector<BYTE> data(bytes);
  if (!QueryServiceObjectSecurity(service, DACL_SECURITY_INFORMATION,
      reinterpret_cast<PSECURITY_DESCRIPTOR>(data.data()), bytes, &bytes)) return false;
  BOOL defaulted = FALSE, present = FALSE;
  PACL acl{};
  if (!GetSecurityDescriptorDacl(data.data(), &present, &acl, &defaulted) ||
      !present || !acl || acl->AceCount != 2) return false;
  bool system = false, admins = false;
  for (DWORD index = 0; index < 2; ++index) {
    void *raw{};
    if (!GetAce(acl, index, &raw)) return false;
    const auto *ace = static_cast<ACCESS_ALLOWED_ACE *>(raw);
    if (ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE ||
        ace->Header.AceFlags != 0 || ace->Mask != SERVICE_ALL_ACCESS) return false;
    PSID sid = const_cast<DWORD *>(&ace->SidStart);
    if (IsWellKnownSid(sid, WinLocalSystemSid)) system = true;
    else if (IsWellKnownSid(sid, WinBuiltinAdministratorsSid)) admins = true;
    else return false;
  }
  return system && admins;
}
class Win32ScmConfigurationOs final : public ScmConfigurationOs {
public:
  Win32ScmConfigurationOs() : manager_(OpenSCManagerW(nullptr, nullptr,
                                                       SC_MANAGER_CONNECT)) {}
  ~Win32ScmConfigurationOs() override { if (manager_) CloseServiceHandle(manager_); }
  bool Read(const wchar_t *name, ScmDecodedConfiguration &out) override {
    if (!manager_) return false;
    SC_HANDLE service = OpenServiceW(manager_, name,
      SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | READ_CONTROL);
    if (!service) return false;
    DWORD bytes = 0;
    QueryServiceConfigW(service, nullptr, 0, &bytes);
    std::vector<BYTE> data(bytes);
    auto *config = reinterpret_cast<QUERY_SERVICE_CONFIGW *>(data.data());
    bool ok = bytes && QueryServiceConfigW(service, config, bytes, &bytes);
    if (ok) {
      out.serviceType = config->dwServiceType;
      out.startType = config->dwStartType;
      out.errorControl = config->dwErrorControl;
      out.account = config->lpServiceStartName ? config->lpServiceStartName : L"";
      out.binaryPath = config->lpBinaryPathName ? config->lpBinaryPathName : L"";
      for (const wchar_t *p = config->lpDependencies; p && *p; p += wcslen(p) + 1)
        out.dependencies.emplace_back(p);
    }
    std::vector<BYTE> sid, delayed, failureFlag, privileges, failures;
    if (ok) ok = Config2(service, SERVICE_CONFIG_SERVICE_SID_INFO, sid) &&
      Config2(service, SERVICE_CONFIG_DELAYED_AUTO_START_INFO, delayed) &&
      Config2(service, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, failureFlag) &&
      Config2(service, SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO, privileges) &&
      Config2(service, SERVICE_CONFIG_FAILURE_ACTIONS, failures);
    if (ok) {
      out.serviceSidType = reinterpret_cast<SERVICE_SID_INFO *>(sid.data())->dwServiceSidType;
      out.delayedAutoStart = reinterpret_cast<SERVICE_DELAYED_AUTO_START_INFO *>(delayed.data())->fDelayedAutostart == TRUE;
      out.failureOnNonCrash = reinterpret_cast<SERVICE_FAILURE_ACTIONS_FLAG *>(failureFlag.data())->fFailureActionsOnNonCrashFailures == TRUE;
      const auto *p = reinterpret_cast<SERVICE_REQUIRED_PRIVILEGES_INFOW *>(privileges.data())->pmszRequiredPrivileges;
      for (; p && *p; p += wcslen(p) + 1) out.requiredPrivileges.emplace_back(p);
      const auto *value = reinterpret_cast<SERVICE_FAILURE_ACTIONSW *>(failures.data());
      out.failureResetSeconds = value->dwResetPeriod;
      if (!value->lpsaActions && value->cActions) ok = false;
      for (DWORD index = 0; ok && index < value->cActions; ++index)
        out.failureActions.push_back({static_cast<unsigned long>(value->lpsaActions[index].Type),
                                      value->lpsaActions[index].Delay});
    }
    SERVICE_STATUS_PROCESS status{};
    if (ok) ok = QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
      reinterpret_cast<BYTE *>(&status), sizeof(status), &bytes) != FALSE;
    if (ok) out.runtimeStateValid = status.dwServiceType == SERVICE_WIN32_OWN_PROCESS &&
      ((status.dwCurrentState == SERVICE_STOPPED && status.dwProcessId == 0) ||
       (status.dwCurrentState == SERVICE_START_PENDING && status.dwProcessId != 0) ||
       (status.dwCurrentState == SERVICE_RUNNING && status.dwProcessId != 0));
    if (ok) out.exactDacl = ExactDacl(service);
    CloseServiceHandle(service);
    return ok;
  }
private:
  SC_HANDLE manager_{};
};
bool Exact(const ScmDecodedConfiguration &value, const Expected &want) {
  auto privileges = value.requiredPrivileges;
  std::sort(privileges.begin(), privileges.end());
  const std::vector<std::wstring> exactPrivileges = {
    L"SeChangeNotifyPrivilege", L"SeImpersonatePrivilege"};
  return value.serviceType == SERVICE_WIN32_OWN_PROCESS &&
    value.startType == SERVICE_AUTO_START && value.errorControl == SERVICE_ERROR_NORMAL &&
    _wcsicmp(value.account.c_str(), want.account) == 0 &&
    value.binaryPath == want.path && value.dependencies.empty() &&
    value.serviceSidType == SERVICE_SID_TYPE_UNRESTRICTED &&
    value.delayedAutoStart && value.failureOnNonCrash && value.runtimeStateValid &&
    privileges == exactPrivileges && value.failureResetSeconds == 86400 &&
    value.failureActions.size() == 3 &&
    value.failureActions[0].type == SC_ACTION_RESTART && value.failureActions[0].delayMs == 5000 &&
    value.failureActions[1].type == SC_ACTION_RESTART && value.failureActions[1].delayMs == 15000 &&
    value.failureActions[2].type == SC_ACTION_NONE && value.failureActions[2].delayMs == 0 &&
    value.exactDacl;
}
} // namespace
bool VerifyBothServiceScmConfigurationWithOs(ScmConfigurationOs &os) {
  for (const auto &want : expected) {
    ScmDecodedConfiguration value;
    if (!os.Read(want.name, value) || !Exact(value, want)) return false;
  }
  return true;
}
bool VerifyBothServiceScmConfiguration() {
  Win32ScmConfigurationOs os;
  return VerifyBothServiceScmConfigurationWithOs(os);
}
} // namespace stellar::service
