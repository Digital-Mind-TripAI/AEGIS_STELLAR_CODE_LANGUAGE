#include "key_custody.h"
#include <bcrypt.h>
#include <sddl.h>
#include <cstring>
using namespace stellar::service;
namespace {
struct Mock final : KeyCustodyOs {
  DWORD exportPolicy{}, implementation{NCRYPT_IMPL_HARDWARE_FLAG};
  std::wstring algorithm{NCRYPT_ECDSA_P256_ALGORITHM};
  std::vector<BYTE> descriptor, accountSid, publicBlob;
  DWORD signBytes{64};
  bool privateRefused{true};
  Mock() {
    PSECURITY_DESCRIPTOR sd{};
    ConvertStringSecurityDescriptorToSecurityDescriptorW(
      L"O:SYD:(A;;GA;;;SY)(A;;GA;;;S-1-5-21-1-2-3-4)", SDDL_REVISION_1,
      &sd, nullptr);
    descriptor.assign(static_cast<BYTE *>(sd),
      static_cast<BYTE *>(sd) + GetSecurityDescriptorLength(sd));
    LocalFree(sd);
    PSID sid{};
    ConvertStringSidToSidW(L"S-1-5-21-1-2-3-4", &sid);
    accountSid.assign(static_cast<BYTE *>(sid),
      static_cast<BYTE *>(sid) + GetLengthSid(sid));
    LocalFree(sid);
    publicBlob.resize(sizeof(BCRYPT_ECCKEY_BLOB) + 64);
    auto *header = reinterpret_cast<BCRYPT_ECCKEY_BLOB *>(publicBlob.data());
    header->dwMagic = BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
    header->cbKey = 32;
    for (size_t i = sizeof(*header); i < publicBlob.size(); ++i)
      publicBlob[i] = static_cast<BYTE>(i);
  }
  SECURITY_STATUS OpenProvider(NCRYPT_PROV_HANDLE *p, const wchar_t *) override {
    *p = 1; return ERROR_SUCCESS;
  }
  SECURITY_STATUS OpenKey(NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE *k,
                          const wchar_t *) override { *k = 2; return ERROR_SUCCESS; }
  SECURITY_STATUS Property(NCRYPT_HANDLE, const wchar_t *name, PBYTE out,
                           DWORD capacity, DWORD *bytes, DWORD) override {
    auto copy = [&](const void *value, DWORD count) {
      *bytes = count;
      if (out) { if (capacity < count) return NTE_BUFFER_TOO_SMALL;
        memcpy(out, value, count); }
      return static_cast<SECURITY_STATUS>(ERROR_SUCCESS);
    };
    if (!wcscmp(name, NCRYPT_EXPORT_POLICY_PROPERTY))
      return copy(&exportPolicy, sizeof(exportPolicy));
    if (!wcscmp(name, NCRYPT_IMPL_TYPE_PROPERTY))
      return copy(&implementation, sizeof(implementation));
    if (!wcscmp(name, NCRYPT_ALGORITHM_PROPERTY))
      return copy(algorithm.c_str(), static_cast<DWORD>((algorithm.size()+1)*sizeof(wchar_t)));
    if (!wcscmp(name, NCRYPT_SECURITY_DESCR_PROPERTY))
      return copy(descriptor.data(), static_cast<DWORD>(descriptor.size()));
    return NTE_NOT_FOUND;
  }
  SECURITY_STATUS Export(NCRYPT_KEY_HANDLE, const wchar_t *type, PBYTE out,
                         DWORD capacity, DWORD *bytes) override {
    if (!wcscmp(type, NCRYPT_PKCS8_PRIVATE_KEY_BLOB))
      return privateRefused ? NTE_PERM : ERROR_SUCCESS;
    *bytes = static_cast<DWORD>(publicBlob.size());
    if (out) { if (capacity < publicBlob.size()) return NTE_BUFFER_TOO_SMALL;
      memcpy(out, publicBlob.data(), publicBlob.size()); }
    return ERROR_SUCCESS;
  }
  SECURITY_STATUS Sign(NCRYPT_KEY_HANDLE, PBYTE hash, DWORD hashBytes,
                       PBYTE out, DWORD capacity, DWORD *bytes) override {
    if (hashBytes != 32) return NTE_INVALID_PARAMETER;
    *bytes = signBytes;
    if (out) { if (capacity < signBytes) return NTE_BUFFER_TOO_SMALL;
      for (DWORD i=0;i<signBytes;++i) out[i]=hash[i%hashBytes]; }
    return ERROR_SUCCESS;
  }
  bool ResolveAccountSid(const wchar_t *, std::vector<BYTE> &sid) override {
    sid = accountSid; return true;
  }
  void Free(NCRYPT_HANDLE) override {}
};
bool Open(Mock &os, const wchar_t *kid = nullptr) {
  NCRYPT_KEY_HANDLE key{};
  ProvisionedKeyEvidence evidence;
  return OpenAndVerifyProvisionedP256KeyWithOs(MS_PLATFORM_CRYPTO_PROVIDER,
    L"test", kid, L"service", false, &key, evidence, os) == ERROR_SUCCESS && key == 2;
}
} // namespace
int main() {
  Mock valid;
  if (!Open(valid)) return 1;
  NCRYPT_KEY_HANDLE key{};
  ProvisionedKeyEvidence evidence;
  if (OpenAndVerifyProvisionedP256KeyWithOs(MS_PLATFORM_CRYPTO_PROVIDER,L"test",
      nullptr,L"service",false,&key,evidence,valid)!=ERROR_SUCCESS || evidence.kid.empty()) return 2;
  if (!Open(valid, evidence.kid.c_str())) return 3;
  if (Open(valid, L"sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")) return 4;
  { Mock bad; bad.exportPolicy=1; if(Open(bad))return 5; }
  { Mock bad; bad.implementation=0; if(Open(bad))return 6; }
  { Mock bad; bad.algorithm=L"RSA"; if(Open(bad))return 7; }
  { Mock bad; reinterpret_cast<BCRYPT_ECCKEY_BLOB*>(bad.publicBlob.data())->cbKey=31; if(Open(bad))return 8; }
  { Mock bad; bad.privateRefused=false; if(Open(bad))return 9; }
  { Mock bad; bad.accountSid.back()^=1; if(Open(bad))return 10; }
  std::vector<BYTE> hash(32,7), signature;
  if(SignP256HashWithOs(2,hash,signature,valid)!=ERROR_SUCCESS || signature.size()!=64)return 11;
  if(SignP256HashWithOs(2,std::vector<BYTE>(31),signature,valid)!=NTE_INVALID_PARAMETER)return 12;
  for(DWORD size:{63u,65u}){Mock bad;bad.signBytes=size;if(SignP256HashWithOs(2,hash,signature,bad)!=NTE_BAD_LEN)return 13;}
  return 0;
}
