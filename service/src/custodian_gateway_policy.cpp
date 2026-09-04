#include "custodian_gateway_policy.h"
#include "canonical_json.h"
#include <wincrypt.h>
#include <array>
#include <iomanip>
#include <sstream>
#include <string_view>
#pragma comment(lib, "crypt32.lib")

namespace stellar::service {
namespace {
constexpr char kAuthorityKid[] =
    "sha256:1a872137fab095b0d220fafb4e666b0c3867989d80556856ad27debab954cf5c";
constexpr char kAuthoritySpki[] =
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1afolgZnehFDR3-MZ7SGIVYBDPdLWtO2nzIlDd7hzZLD1IwaOhAB-dnKuGoqNeKpba4P2Jn8f3miTVZQ2vh7UA";
constexpr unsigned long long kMaximumPolicyLifetimeMs = 31536000000ULL;

std::string Sha256Kid(const std::vector<unsigned char> &value) {
  BCRYPT_ALG_HANDLE algorithm{};
  BCRYPT_HASH_HANDLE hash{};
  DWORD objectBytes = 0, got = 0;
  std::array<BYTE, 32> digest{};
  if (value.empty() || BCryptOpenAlgorithmProvider(
      &algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0)
    return {};
  if (BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
                        reinterpret_cast<PUCHAR>(&objectBytes),
                        sizeof(objectBytes), &got, 0) < 0) {
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return {};
  }
  std::vector<BYTE> object(objectBytes);
  bool ok = BCryptCreateHash(algorithm, &hash, object.data(), objectBytes,
                             nullptr, 0, 0) >= 0 &&
            BCryptHashData(hash, const_cast<PUCHAR>(value.data()),
                           static_cast<ULONG>(value.size()), 0) >= 0 &&
            BCryptFinishHash(hash, digest.data(),
                             static_cast<ULONG>(digest.size()), 0) >= 0;
  if (hash) BCryptDestroyHash(hash);
  BCryptCloseAlgorithmProvider(algorithm, 0);
  if (!ok) return {};
  std::ostringstream text;
  text << "sha256:" << std::hex << std::setfill('0');
  for (BYTE byte : digest) text << std::setw(2) << static_cast<unsigned>(byte);
  return text.str();
}

bool VerifyWithCompiledAuthority(const std::string &kid,
                                 const std::vector<BYTE> &signedBytes,
                                 const std::vector<BYTE> &signature) {
  if (kid != kAuthorityKid || signature.size() != 64 || signedBytes.empty())
    return false;
  std::vector<unsigned char> der;
  if (!json::DecodeCanonicalBase64Url(kAuthoritySpki, der) || der.empty())
    return false;
  if (Sha256Kid(der) != kAuthorityKid)
    return false;
  CERT_PUBLIC_KEY_INFO *info = nullptr;
  DWORD infoBytes = 0;
  if (!CryptDecodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, der.data(),
                           static_cast<DWORD>(der.size()),
                           CRYPT_DECODE_ALLOC_FLAG, nullptr, &info,
                           &infoBytes) || !info)
    return false;
  BCRYPT_KEY_HANDLE key{};
  const bool imported = CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING, info, 0,
                                                     nullptr, &key) == TRUE;
  LocalFree(info);
  if (!imported)
    return false;
  const bool valid = VerifyEs256WithCng(key, signedBytes, signature);
  BCryptDestroyKey(key);
  return valid;
}
bool Same(const json::CustodianGatewayPolicy &policy,
          const CustodianGatewayPolicyBinding &expected) {
  return policy.installId == expected.installId &&
         policy.machineId == expected.machineId &&
         policy.custodianAccount == expected.custodianAccount &&
         policy.cngKeyReference == expected.cngKeyReference &&
         policy.pipe == expected.pipe;
}
} // namespace

bool LoadCustodianGatewayPolicyWithVerifier(
    const std::vector<BYTE> &canonicalEnvelope,
    const CustodianGatewayPolicyBinding &expected,
    unsigned long long nowUnixMilliseconds,
    const CustodianPolicySignatureVerifier &verify,
    PipePeerPolicy &gatewayPolicy) {
  gatewayPolicy = {};
  if (canonicalEnvelope.empty() || !verify || expected.installId.empty() ||
      expected.machineId.empty() || expected.custodianAccount.empty() ||
      expected.cngKeyReference.empty() || expected.pipe.empty())
    return false;
  json::CustodianGatewayPolicyEnvelope envelope;
  const std::string text(canonicalEnvelope.begin(), canonicalEnvelope.end());
  if (!json::ParseCanonicalCustodianGatewayPolicy(text, &envelope).accepted ||
      !Same(envelope.policy, expected) ||
      envelope.policy.issuedAt > nowUnixMilliseconds ||
      envelope.policy.expiresAt <= nowUnixMilliseconds ||
      envelope.policy.expiresAt <= envelope.policy.issuedAt ||
      envelope.policy.expiresAt - envelope.policy.issuedAt >
          kMaximumPolicyLifetimeMs)
    return false;
  std::vector<unsigned char> requestSignerSpki;
  if (!json::DecodeCanonicalBase64Url(envelope.policy.requestSignerSpki,
                                      requestSignerSpki) ||
      Sha256Kid(requestSignerSpki) != envelope.policy.requestSignerKid)
    return false;
  const std::string signingInput =
      envelope.protectedBase64 + "." + envelope.payloadBase64;
  const std::vector<BYTE> bytes(signingInput.begin(), signingInput.end());
  if (!verify(envelope.kid, bytes, envelope.signature))
    return false;
  gatewayPolicy.account.assign(envelope.policy.gateway.account.begin(),
                               envelope.policy.gateway.account.end());
  gatewayPolicy.serviceName.assign(envelope.policy.gateway.serviceName.begin(),
                                   envelope.policy.gateway.serviceName.end());
  gatewayPolicy.imagePath.assign(envelope.policy.gateway.imagePath.begin(),
                                 envelope.policy.gateway.imagePath.end());
  gatewayPolicy.imageSha256.assign(envelope.policy.gateway.imageSha256.begin(),
                                   envelope.policy.gateway.imageSha256.end());
  gatewayPolicy.imageFileId.assign(envelope.policy.gateway.imageFileId.begin(),
                                   envelope.policy.gateway.imageFileId.end());
  gatewayPolicy.imageVolumeSerial = envelope.policy.gateway.imageVolumeSerial;
  gatewayPolicy.signerThumbprint.assign(
      envelope.policy.gateway.signerThumbprint.begin(),
      envelope.policy.gateway.signerThumbprint.end());
  return !gatewayPolicy.account.empty() && !gatewayPolicy.serviceName.empty() &&
         !gatewayPolicy.imagePath.empty() && !gatewayPolicy.imageSha256.empty() &&
         !gatewayPolicy.imageFileId.empty() && !gatewayPolicy.signerThumbprint.empty();
}

bool LoadCustodianGatewayPolicy(const std::vector<BYTE> &canonicalEnvelope,
                                const CustodianGatewayPolicyBinding &expected,
                                unsigned long long nowUnixMilliseconds,
                                PipePeerPolicy &gatewayPolicy) {
  return LoadCustodianGatewayPolicyWithVerifier(
      canonicalEnvelope, expected, nowUnixMilliseconds,
      VerifyWithCompiledAuthority, gatewayPolicy);
}
} // namespace stellar::service
