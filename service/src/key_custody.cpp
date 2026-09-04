#include "key_custody.h"
#include <aclapi.h>
#include <bcrypt.h>
#include <iomanip>
#include <sddl.h>
#include <sstream>
#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "advapi32.lib")

namespace stellar::service {
namespace {
class Win32KeyCustodyOs final : public KeyCustodyOs {
public:
  SECURITY_STATUS OpenProvider(NCRYPT_PROV_HANDLE *provider,
                               const wchar_t *name) override {
    return NCryptOpenStorageProvider(provider, name, 0);
  }
  SECURITY_STATUS OpenKey(NCRYPT_PROV_HANDLE provider, NCRYPT_KEY_HANDLE *key,
                          const wchar_t *name) override {
    return NCryptOpenKey(provider, key, name, 0, NCRYPT_MACHINE_KEY_FLAG);
  }
  SECURITY_STATUS Property(NCRYPT_HANDLE object, const wchar_t *name,
                           PBYTE output, DWORD capacity, DWORD *bytes,
                           DWORD flags) override {
    return NCryptGetProperty(object, name, output, capacity, bytes, flags);
  }
  SECURITY_STATUS Export(NCRYPT_KEY_HANDLE key, const wchar_t *type,
                         PBYTE output, DWORD capacity, DWORD *bytes) override {
    if (wcscmp(type, BCRYPT_ECCPUBLIC_BLOB) == 0)
      return NCryptExportKey(key, 0, BCRYPT_ECCPUBLIC_BLOB, nullptr, output,
                             capacity, bytes, 0);
    if (wcscmp(type, NCRYPT_PKCS8_PRIVATE_KEY_BLOB) == 0)
      return NCryptExportKey(key, 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, nullptr,
                             output, capacity, bytes, 0);
    return NTE_NOT_SUPPORTED;
  }
  SECURITY_STATUS Sign(NCRYPT_KEY_HANDLE key, PBYTE hash, DWORD hashBytes,
                       PBYTE output, DWORD capacity, DWORD *bytes) override {
    return NCryptSignHash(key, nullptr, hash, hashBytes, output, capacity,
                          bytes, 0);
  }
  bool ResolveAccountSid(const wchar_t *account,
                         std::vector<BYTE> &sid) override {
    DWORD sidBytes = 0, domainBytes = 0;
    SID_NAME_USE use{};
    LookupAccountNameW(nullptr, account, nullptr, &sidBytes, nullptr,
                       &domainBytes, &use);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) return false;
    sid.resize(sidBytes);
    std::vector<wchar_t> domain(domainBytes);
    return LookupAccountNameW(nullptr, account, sid.data(), &sidBytes,
                              domain.data(), &domainBytes, &use) != FALSE;
  }
  void Free(NCRYPT_HANDLE object) override { if (object) NCryptFreeObject(object); }
};
std::wstring Hex(const BYTE *data, DWORD bytes) {
  std::wostringstream out;
  out << std::hex << std::setfill(L'0');
  for (DWORD i = 0; i < bytes; ++i)
    out << std::setw(2) << static_cast<unsigned>(data[i]);
  return out.str();
}
bool Sha256(const std::vector<BYTE> &input, std::wstring &kid) {
  BCRYPT_ALG_HANDLE algorithm{};
  BCRYPT_HASH_HANDLE hash{};
  DWORD objectBytes = 0, done = 0;
  if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr,
                                  0) != 0) return false;
  bool ok = BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
      reinterpret_cast<PUCHAR>(&objectBytes), sizeof(objectBytes), &done, 0) == 0;
  std::vector<BYTE> object(objectBytes), digest(32);
  ok = ok && BCryptCreateHash(algorithm, &hash, object.data(), objectBytes,
                             nullptr, 0, 0) == 0 &&
       BCryptHashData(hash, const_cast<PUCHAR>(input.data()),
                      static_cast<ULONG>(input.size()), 0) == 0 &&
       BCryptFinishHash(hash, digest.data(),
                        static_cast<ULONG>(digest.size()), 0) == 0;
  if (hash) BCryptDestroyHash(hash);
  BCryptCloseAlgorithmProvider(algorithm, 0);
  if (ok) kid = L"sha256:" + Hex(digest.data(), static_cast<DWORD>(digest.size()));
  return ok;
}
bool SubjectPublicKeyInfo(NCRYPT_KEY_HANDLE key, KeyCustodyOs &os,
                          std::vector<BYTE> &spki) {
  DWORD bytes = 0;
  if (os.Export(key, BCRYPT_ECCPUBLIC_BLOB, nullptr, 0, &bytes) != ERROR_SUCCESS ||
      bytes != sizeof(BCRYPT_ECCKEY_BLOB) + 64) return false;
  std::vector<BYTE> blob(bytes);
  if (os.Export(key, BCRYPT_ECCPUBLIC_BLOB, blob.data(), bytes, &bytes) !=
      ERROR_SUCCESS) return false;
  const auto *header = reinterpret_cast<const BCRYPT_ECCKEY_BLOB *>(blob.data());
  if (header->dwMagic != BCRYPT_ECDSA_PUBLIC_P256_MAGIC || header->cbKey != 32 ||
      bytes != sizeof(*header) + 2 * header->cbKey) return false;
  static constexpr BYTE prefix[] = {0x30,0x59,0x30,0x13,0x06,0x07,0x2a,0x86,
    0x48,0xce,0x3d,0x02,0x01,0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,
    0x07,0x03,0x42,0x00,0x04};
  spki.assign(prefix, prefix + sizeof(prefix));
  spki.insert(spki.end(), blob.begin() + sizeof(*header), blob.end());
  return true;
}
bool ExactKeyDacl(PSECURITY_DESCRIPTOR descriptor, const wchar_t *account,
                  KeyCustodyOs &os) {
  PSID owner{};
  PACL dacl{};
  BOOL defaulted = FALSE, present = FALSE;
  if (!GetSecurityDescriptorOwner(descriptor, &owner, &defaulted) ||
      !IsWellKnownSid(owner, WinLocalSystemSid) ||
      !GetSecurityDescriptorDacl(descriptor, &present, &dacl, &defaulted) ||
      !present || !dacl || dacl->AceCount != 2) return false;
  std::vector<BYTE> expected;
  if (!os.ResolveAccountSid(account, expected)) return false;
  bool system = false, service = false;
  for (DWORD index = 0; index < dacl->AceCount; ++index) {
    void *raw{};
    if (!GetAce(dacl, index, &raw)) return false;
    const auto *ace = static_cast<ACCESS_ALLOWED_ACE *>(raw);
    if (ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE ||
        ace->Header.AceFlags != 0 || ace->Mask != GENERIC_ALL) return false;
    PSID sid = const_cast<DWORD *>(&ace->SidStart);
    if (IsWellKnownSid(sid, WinLocalSystemSid)) system = true;
    else if (EqualSid(sid, expected.data())) service = true;
    else return false;
  }
  return system && service;
}
} // namespace

SECURITY_STATUS OpenAndVerifyProvisionedP256KeyWithOs(
    const wchar_t *providerName, const wchar_t *keyName,
    const wchar_t *expectedKid, const wchar_t *expectedServiceAccount,
    bool softwareAllowed, NCRYPT_KEY_HANDLE *key,
    ProvisionedKeyEvidence &evidence, KeyCustodyOs &os) {
  if (!providerName || !keyName || !expectedServiceAccount || !key ||
      (!softwareAllowed && wcscmp(providerName, MS_PLATFORM_CRYPTO_PROVIDER)))
    return NTE_PERM;
  *key = 0;
  NCRYPT_PROV_HANDLE provider{};
  SECURITY_STATUS status = os.OpenProvider(&provider, providerName);
  if (status != ERROR_SUCCESS) return status;
  status = os.OpenKey(provider, key, keyName);
  if (status != ERROR_SUCCESS) { os.Free(provider); return status; }
  DWORD policy = ~0u, bytes = 0, implementation = 0;
  wchar_t algorithm[64]{};
  status = os.Property(*key, NCRYPT_EXPORT_POLICY_PROPERTY,
      reinterpret_cast<PBYTE>(&policy), sizeof(policy), &bytes, 0);
  if (status == ERROR_SUCCESS) status = os.Property(*key,
      NCRYPT_ALGORITHM_PROPERTY, reinterpret_cast<PBYTE>(algorithm),
      sizeof(algorithm), &bytes, 0);
  if (status == ERROR_SUCCESS) status = os.Property(*key,
      NCRYPT_IMPL_TYPE_PROPERTY, reinterpret_cast<PBYTE>(&implementation),
      sizeof(implementation), &bytes, 0);
  DWORD privateBytes = 0;
  const auto privateExport = os.Export(*key, NCRYPT_PKCS8_PRIVATE_KEY_BLOB,
                                      nullptr, 0, &privateBytes);
  const bool privateRefused = privateExport == NTE_PERM ||
                              privateExport == NTE_NOT_SUPPORTED;
  DWORD sdBytes = 0;
  std::vector<BYTE> descriptor;
  const DWORD securityFlags = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
  if (os.Property(*key, NCRYPT_SECURITY_DESCR_PROPERTY, nullptr, 0, &sdBytes,
                  securityFlags) == ERROR_SUCCESS && sdBytes) {
    descriptor.resize(sdBytes);
    status = os.Property(*key, NCRYPT_SECURITY_DESCR_PROPERTY,
                         descriptor.data(), sdBytes, &sdBytes, securityFlags);
  } else status = NTE_PERM;
  std::vector<BYTE> spki;
  std::wstring kid;
  const bool hardware = (implementation & NCRYPT_IMPL_HARDWARE_FLAG) != 0;
  const bool publicKeyValid = SubjectPublicKeyInfo(*key, os, spki) && Sha256(spki, kid);
  LPWSTR sddl{};
  if (status == ERROR_SUCCESS && !ConvertSecurityDescriptorToStringSecurityDescriptorW(
      reinterpret_cast<PSECURITY_DESCRIPTOR>(descriptor.data()), SDDL_REVISION_1,
      securityFlags, &sddl, nullptr)) status = NTE_PERM;
  evidence = {providerName, keyName, kid, sddl ? sddl : L"", hardware,
              privateRefused};
  if (sddl) LocalFree(sddl);
  const bool kidMatches = !expectedKid || !*expectedKid || kid == expectedKid;
  const bool accepted = status == ERROR_SUCCESS && policy == 0 &&
    (hardware || softwareAllowed) && privateRefused &&
    wcscmp(algorithm, NCRYPT_ECDSA_P256_ALGORITHM) == 0 && publicKeyValid &&
    kidMatches && ExactKeyDacl(
      reinterpret_cast<PSECURITY_DESCRIPTOR>(descriptor.data()),
      expectedServiceAccount, os);
  os.Free(provider);
  if (!accepted) {
    os.Free(*key);
    *key = 0;
    return publicKeyValid && !kidMatches ? NTE_BAD_SIGNATURE : NTE_PERM;
  }
  return ERROR_SUCCESS;
}
SECURITY_STATUS OpenAndVerifyProvisionedP256Key(const wchar_t *providerName,
    const wchar_t *keyName, const wchar_t *expectedKid,
    const wchar_t *expectedServiceAccount, bool softwareAllowed,
    NCRYPT_KEY_HANDLE *key, ProvisionedKeyEvidence &evidence) {
  Win32KeyCustodyOs os;
  return OpenAndVerifyProvisionedP256KeyWithOs(providerName, keyName,
      expectedKid, expectedServiceAccount, softwareAllowed, key, evidence, os);
}
SECURITY_STATUS SignP256HashWithOs(NCRYPT_KEY_HANDLE key,
    const std::vector<BYTE> &hash, std::vector<BYTE> &signature,
    KeyCustodyOs &os) {
  signature.clear();
  if (hash.size() != 32) return NTE_INVALID_PARAMETER;
  DWORD bytes = 0;
  auto status = os.Sign(key, const_cast<PBYTE>(hash.data()), 32, nullptr, 0,
                        &bytes);
  if (status != ERROR_SUCCESS || bytes != 64)
    return status == ERROR_SUCCESS ? NTE_BAD_LEN : status;
  signature.resize(64);
  status = os.Sign(key, const_cast<PBYTE>(hash.data()), 32, signature.data(),
                   64, &bytes);
  if (status != ERROR_SUCCESS || bytes != 64) {
    signature.clear();
    return status == ERROR_SUCCESS ? NTE_BAD_LEN : status;
  }
  return ERROR_SUCCESS;
}
SECURITY_STATUS SignP256Hash(NCRYPT_KEY_HANDLE key,
    const std::vector<BYTE> &hash, std::vector<BYTE> &signature) {
  Win32KeyCustodyOs os;
  return SignP256HashWithOs(key, hash, signature, os);
}
} // namespace stellar::service
