#pragma once
#include <windows.h>
#include <ncrypt.h>
#include <string>
#include <vector>

namespace stellar::service {
struct ProvisionedKeyEvidence {
  std::wstring provider, keyName, kid, dacl;
  bool tpmBound{}, privateExportRefused{};
};
class KeyCustodyOs {
public:
  virtual ~KeyCustodyOs() = default;
  virtual SECURITY_STATUS OpenProvider(NCRYPT_PROV_HANDLE *provider,
                                       const wchar_t *name) = 0;
  virtual SECURITY_STATUS OpenKey(NCRYPT_PROV_HANDLE provider,
                                  NCRYPT_KEY_HANDLE *key,
                                  const wchar_t *name) = 0;
  virtual SECURITY_STATUS Property(NCRYPT_HANDLE object, const wchar_t *name,
                                   PBYTE output, DWORD capacity,
                                   DWORD *bytes, DWORD flags) = 0;
  virtual SECURITY_STATUS Export(NCRYPT_KEY_HANDLE key, const wchar_t *type,
                                 PBYTE output, DWORD capacity,
                                 DWORD *bytes) = 0;
  virtual SECURITY_STATUS Sign(NCRYPT_KEY_HANDLE key, PBYTE hash,
                               DWORD hashBytes, PBYTE output,
                               DWORD capacity, DWORD *bytes) = 0;
  virtual bool ResolveAccountSid(const wchar_t *account,
                                 std::vector<BYTE> &sid) = 0;
  virtual void Free(NCRYPT_HANDLE object) = 0;
};
SECURITY_STATUS OpenAndVerifyProvisionedP256KeyWithOs(
    const wchar_t *providerName, const wchar_t *keyName,
    const wchar_t *expectedKid, const wchar_t *expectedServiceAccount,
    bool softwareCustodyAllowed, NCRYPT_KEY_HANDLE *key,
    ProvisionedKeyEvidence &evidence, KeyCustodyOs &os);
SECURITY_STATUS OpenAndVerifyProvisionedP256Key(
    const wchar_t *providerName, const wchar_t *keyName,
    const wchar_t *expectedKid, const wchar_t *expectedServiceAccount,
    bool softwareCustodyAllowed, NCRYPT_KEY_HANDLE *key,
    ProvisionedKeyEvidence &evidence);
SECURITY_STATUS SignP256HashWithOs(NCRYPT_KEY_HANDLE key,
                                  const std::vector<BYTE> &hash,
                                  std::vector<BYTE> &p1363Signature,
                                  KeyCustodyOs &os);
SECURITY_STATUS SignP256Hash(NCRYPT_KEY_HANDLE key,
                            const std::vector<BYTE> &hash,
                            std::vector<BYTE> &p1363Signature);
} // namespace stellar::service
