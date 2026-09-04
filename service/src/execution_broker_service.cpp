#include "service_common.h"
#include "service_runtime.h"
#include "canonical_json.h"
#include "scm_readiness.h"
#include "key_custody.h"
#include <iomanip>
#include <iostream>
#include <ncrypt.h>
#include <sstream>
#pragma comment(lib, "ncrypt.lib")
static constexpr wchar_t kServiceName[] = L"AegisStellarExecutionBroker";
static constexpr wchar_t kAttestationKey[] =
    L"AegisStellarExecutionBroker-Attestation-P256-v1";
static constexpr wchar_t kFixedBroker[] =
    L"C:\\Program Files\\AEGIS\\Stellar\\v0.1\\bin\\stellar-t7b-sandbox.exe";
static constexpr wchar_t kFixedEvidence[] =
    L"C:\\ProgramData\\AEGIS\\Stellar\\v0.1\\evidence";
static constexpr wchar_t kPipeName[] =
    L"\\\\.\\pipe\\AegisStellarExecutionBroker.v0.1";
static constexpr wchar_t kOwnerAccount[] =
    L"NT SERVICE\\AegisStellarExecutionBroker";
static constexpr wchar_t kGatewayAccount[] =
    L"NT SERVICE\\AegisStellarLabGateway";
static constexpr wchar_t kRequiredPrivileges[] =
    L"SeChangeNotifyPrivilege/SeImpersonatePrivilege";
// The broker stores public Custodian keys only. Accepted messages name exactly
// stellar.t7b.fixed-security-probe-suite/v0.1 and never carry path, flags,
// source, DLL, callback, COM class, plugin, package, or executable bytes.
// Static PE imports and effects are compared to their canonical documents.
// Runtime loads are separately restricted to advapi32.dll, ws2_32.dll and
// user32.dll; each must resolve beneath System32 and pass file-ID, version,
// hash and WinVerifyTrust.
static std::wstring Json(const std::wstring &value) {
  std::wstring out;
  for (const wchar_t ch : value) {
    if (ch == L'\\' || ch == L'"')
      out += L'\\';
    out += ch;
  }
  return out;
}
static std::wstring FileId(const FILE_ID_128 &value) {
  std::wostringstream out;
  out << std::hex << std::setfill(L'0');
  for (const BYTE byte : value.Identifier)
    out << std::setw(2) << static_cast<unsigned>(byte);
  return out.str();
}
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
static bool
LoadGatewayPolicyFromAuthenticatedConfig(stellar::service::PipePeerPolicy &) {
  return false;
} // Exact pins arrive only through the authenticated release/config registry.
static DWORD Worker(HANDLE stop,
                    stellar::service::StartupReadiness &readiness) {
  stellar::service::PipePeerPolicy gateway;
  const bool configReady = LoadGatewayPolicyFromAuthenticatedConfig(gateway);
  if (!readiness.Checkpoint(L"config", configReady))
    return ERROR_INVALID_DATA;
  NCRYPT_KEY_HANDLE attestationKey{};
  stellar::service::ProvisionedKeyEvidence keyEvidence;
  const bool keyReady =
      stellar::service::OpenAndVerifyProvisionedP256Key(
          MS_PLATFORM_CRYPTO_PROVIDER, kAttestationKey, L"", kOwnerAccount,
          false, &attestationKey, keyEvidence) == ERROR_SUCCESS;
  if (!readiness.Checkpoint(L"release-manifest", configReady) ||
      !readiness.Checkpoint(L"key-registry", keyReady) ||
      !readiness.Checkpoint(L"protected-acl-roots", configReady))
  { if (attestationKey) NCryptFreeObject(attestationKey); return ERROR_ACCESS_DENIED; }
  HANDLE pipe = stellar::service::CreateAuthenticatedPipe(
      kPipeName, kOwnerAccount, kGatewayAccount);
  if (pipe == INVALID_HANDLE_VALUE)
  { if (attestationKey) NCryptFreeObject(attestationKey); return GetLastError(); }
  if (!readiness.Checkpoint(L"pipe-dacl-create", pipe != INVALID_HANDLE_VALUE) ||
      !readiness.Checkpoint(L"self-attestation-static-imports", stellar::service::VerifyBothServiceScmConfiguration()) ||
      !readiness.Checkpoint(L"worker-ready", configReady && keyReady) || !readiness.Running()) {
    CloseHandle(pipe);
    if (attestationKey) NCryptFreeObject(attestationKey);
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
              "stellar.t7b.fixed-security-probe-suite/v0.1", peer, request,
              state)) {
        const std::string response =
            "{\"action\":\"fixed-probes-only\",\"contractAdapter\":\"durable-"
            "replay-handoff-required\",\"executionEnabled\":false,\"s7001\":"
            "\"CLOSED\",\"schema\":\"stellar.t7d-d2-broker-status/v0.1\"}";
        stellar::service::WriteBoundedFrame(
            pipe, stop, std::vector<BYTE>(response.begin(), response.end()));
      }
      DisconnectNamedPipe(pipe);
    }
  }
  CancelIoEx(pipe, nullptr);
  CloseHandle(pipe);
  if (attestationKey) NCryptFreeObject(attestationKey);
  return NO_ERROR;
}
int wmain(int argc, wchar_t **argv) {
  if (!stellar::service::HardenDllSearch())
    return 70;
  if (!stellar::service::IsAbsoluteFixedPath(kFixedBroker) ||
      !stellar::service::IsAbsoluteFixedPath(kFixedEvidence))
    return 71;
  std::vector<stellar::service::ModuleIdentity> modules;
  if (!stellar::service::VerifyDynamicModuleAllowlist(modules))
    return 72;
  if (argc == 2 && wcscmp(argv[1], L"--offline-self-test") == 0) {
    if (modules.size() != 3 || !kServiceName[0] || !kAttestationKey[0] ||
        !kRequiredPrivileges[0])
      return 73;
    std::wcout << L"{\"schema\":\"stellar.t7c-dynamic-module-evidence/"
                  L"v0.1\",\"s7001Closed\":true,\"modules\":[";
    for (size_t index = 0; index < modules.size(); ++index) {
      if (index)
        std::wcout << L',';
      const auto &item = modules[index];
      std::wcout << L"{\"authenticode\":\"valid\",\"fileId\":\""
                 << FileId(item.fileId) << L"\",\"name\":\"" << Json(item.name)
                 << L"\",\"path\":\"" << Json(item.path) << L"\",\"sha256\":\""
                 << item.sha256 << L"\",\"version\":\"" << Json(item.version)
                 << L"\",\"volumeSerial\":" << item.volumeSerial << L'}';
    }
    std::wcout << L"]}\n";
    return 0;
  }
  return stellar::service::RunWindowsService(kServiceName, Worker);
}
