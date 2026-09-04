#pragma once
#include <string>
#include <vector>

namespace stellar::service {
struct ScmDecodedConfiguration {
  unsigned long serviceType{}, startType{}, errorControl{}, serviceSidType{};
  std::wstring account, binaryPath;
  std::vector<std::wstring> dependencies, requiredPrivileges;
  bool delayedAutoStart{}, failureOnNonCrash{}, runtimeStateValid{}, exactDacl{};
  unsigned long failureResetSeconds{};
  struct FailureAction { unsigned long type{}, delayMs{}; };
  std::vector<FailureAction> failureActions;
};
class ScmConfigurationOs {
public:
  virtual ~ScmConfigurationOs() = default;
  virtual bool Read(const wchar_t *serviceName,
                    ScmDecodedConfiguration &configuration) = 0;
};
bool VerifyBothServiceScmConfigurationWithOs(ScmConfigurationOs &os);
bool VerifyBothServiceScmConfiguration();
} // namespace stellar::service
