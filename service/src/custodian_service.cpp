#include "service_common.h"
#include "service_runtime.h"
#include "canonical_json.h"
#include "scm_readiness.h"
#include "key_custody.h"
#include <ncrypt.h>
#include <sddl.h>
#pragma comment(lib, "ncrypt.lib")
static constexpr wchar_t kServiceName[] = L"AegisStellarCustodian";
static constexpr wchar_t kPipeName[] =
    L"\\\\.\\pipe\\AegisStellarCustodian.v0.1";
static constexpr wchar_t kIssuerKey[] = L"AegisStellarCustodian-Issuer-P256-v1";
static constexpr wchar_t kOwnerAccount[] = L"NT SERVICE\\AegisStellarCustodian";
static constexpr wchar_t kGatewayAccount[] =
    L"NT SERVICE\\AegisStellarLabGateway";
static constexpr wchar_t kRequiredPrivileges[] =
    L"SeChangeNotifyPrivilege/SeImpersonatePrivilege";
// OpenAndVerifyProvisionedP256Key centrally enforces
// NCRYPT_EXPORT_POLICY_PROPERTY == 0, NCRYPT_ALGORITHM_PROPERTY ==
// NCRYPT_ECDSA_P256_ALGORITHM, and opens with NCryptOpenKey only.
struct KeyEvidence {
  std::wstring provider;
  std::wstring custody;
  std::wstring kid;
  bool exportable = false;
};
static SECURITY_STATUS OpenProvisionedIssuerKey(NCRYPT_KEY_HANDLE *key,
                                                KeyEvidence &evidence) {
  stellar::service::ProvisionedKeyEvidence observed;
  const SECURITY_STATUS status =
      stellar::service::OpenAndVerifyProvisionedP256Key(
          MS_PLATFORM_CRYPTO_PROVIDER, kIssuerKey, L"", kOwnerAccount, false,
          key, observed);
  evidence = {observed.provider, observed.tpmBound ? L"TPM_BOUND" : L"",
              observed.kid, !observed.privateExportRefused};
  return status;
}
// Issuance pipe accepts strict canonical JSON only. Its protected DACL is
// SYSTEM plus NT SERVICE\AegisStellarCustodian; Steward authentication is
// rechecked by the issuer. Rotation publishes {kid, publicKey, notBefore,
// revokedAt}; private material never leaves NCrypt.
class ClosedRegistryVerifier final
    : public stellar::service::SignedRequestVerifier {
public:
  Result VerifyAndConsumeStrictCanonicalEs256(
      const std::string &envelope, const std::string &, const std::string &,
      const stellar::service::PipePeer &, unsigned long long,
      unsigned long long, unsigned long long) override {
    return stellar::service::json::ParseCanonicalSignedRequest(envelope).accepted
               ? Result::unknown_key
               : Result::malformed;
  }
};
// revocationRegistry and rotation remain authenticated protected-config gates;
// D2 does not synthesize them.
static bool
LoadGatewayPolicyFromAuthenticatedConfig(stellar::service::PipePeerPolicy &) {
  return false;
} // D2 never invents an installed key/hash/file-id/signer pin.
static DWORD Worker(HANDLE stop,
                    stellar::service::StartupReadiness &readiness) {
  stellar::service::PipePeerPolicy gateway;
  const bool configReady = LoadGatewayPolicyFromAuthenticatedConfig(gateway);
  if (!readiness.Checkpoint(L"config", configReady))
    return ERROR_INVALID_DATA;
  if (!readiness.Checkpoint(L"release-manifest", configReady))
    return ERROR_OPERATION_ABORTED;
  NCRYPT_KEY_HANDLE key{};
  KeyEvidence evidence;
  if (OpenProvisionedIssuerKey(&key, evidence) != ERROR_SUCCESS)
    return ERROR_ACCESS_DENIED;
  if (!readiness.Checkpoint(L"key-registry", key != 0) ||
      !readiness.Checkpoint(L"protected-acl-roots", configReady)) {
    NCryptFreeObject(key);
    return ERROR_ACCESS_DENIED;
  }
  HANDLE pipe = stellar::service::CreateAuthenticatedPipe(
      kPipeName, kOwnerAccount, kGatewayAccount);
  if (pipe == INVALID_HANDLE_VALUE) {
    NCryptFreeObject(key);
    return GetLastError();
  }
  if (!readiness.Checkpoint(L"pipe-dacl-create", pipe != INVALID_HANDLE_VALUE) ||
      !readiness.Checkpoint(L"self-attestation-static-imports", stellar::service::VerifyBothServiceScmConfiguration()) ||
      !readiness.Checkpoint(L"worker-ready", key != 0 && configReady) || !readiness.Running()) {
    CloseHandle(pipe);
    NCryptFreeObject(key);
    return ERROR_OPERATION_ABORTED;
  }
  ClosedRegistryVerifier verifier;
  while (!stellar::service::ServiceStopRequested(stop)) {
    if (stellar::service::ConnectAuthenticatedPipe(pipe, stop)) {
      stellar::service::PipePeer peer;
      std::vector<BYTE> request;
      stellar::service::HandshakeState state{};
      if (stellar::service::PerformAuthenticatedHandshake(
              pipe, stop, kPipeName, kServiceName, gateway, verifier,
              "issue-after-verified-steward-authority", peer, request, state)) {
        const std::string response =
            "{\"code\":\"T7C_SCHEMA_OR_COMMAND_REFUSED\",\"s7001\":\"CLOSED\","
            "\"schema\":\"stellar.t7d-d2-error/v0.1\"}";
        stellar::service::WriteBoundedFrame(
            pipe, stop, std::vector<BYTE>(response.begin(), response.end()));
      }
      DisconnectNamedPipe(pipe);
    }
  }
  CancelIoEx(pipe, nullptr);
  CloseHandle(pipe);
  NCryptFreeObject(key);
  return NO_ERROR;
}
int wmain(int argc, wchar_t **argv) {
  if (!stellar::service::HardenDllSearch())
    return 70;
  if (argc == 2 && wcscmp(argv[1], L"--offline-self-test") == 0)
    return (kPipeName[0] && kServiceName[0] && kGatewayAccount[0] &&
            kRequiredPrivileges[0])
               ? 0
               : 71;
  return stellar::service::RunWindowsService(kServiceName, Worker);
}
