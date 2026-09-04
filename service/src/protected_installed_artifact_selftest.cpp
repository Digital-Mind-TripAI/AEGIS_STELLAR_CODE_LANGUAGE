#include "protected_installed_artifact.h"

#include <string>
#include <utility>
#include <vector>

namespace {
using stellar::service::ProtectedInstalledArtifactFacts;
using stellar::service::ProtectedInstalledArtifactFilesystem;
using stellar::service::ProtectedInstalledArtifactIdentity;
using stellar::service::ProtectedInstalledArtifactPath;
using stellar::service::ProtectedInstalledArtifactStatus;

class FakeFilesystem final : public ProtectedInstalledArtifactFilesystem {
public:
  bool available{true};
  std::vector<unsigned char> payload;
  ProtectedInstalledArtifactFacts facts{true, true, false, false, true, true, 0,
                                        "NT SERVICE\\AegisStellarCustodian",
                                        {"NT SERVICE\\AegisStellarCustodian"}};
  bool ReadExact(const std::wstring &, std::size_t maximum,
                 std::vector<unsigned char> &bytes,
                 ProtectedInstalledArtifactFacts &out) const override {
    out = facts; out.byteCount = payload.size();
    if (!available || payload.size() > maximum) return false;
    bytes = payload; return true;
  }
};
class FakeIdentity final : public ProtectedInstalledArtifactIdentity {
public:
  bool owner{true}, acl{true};
  bool IsExpectedOwner(const std::string &) const override { return owner; }
  bool IsAllowedMutationPrincipal(const std::string &) const override { return acl; }
};
bool Accept(const std::vector<unsigned char> &value) { return value == std::vector<unsigned char>{'o','k'}; }
std::string B64(const std::string &value) {
  static constexpr char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  std::string out; unsigned accumulator = 0, bits = 0;
  for (unsigned char ch : value) { accumulator = (accumulator << 8) | ch; bits += 8;
    while (bits >= 6) { bits -= 6; out.push_back(alphabet[(accumulator >> bits) & 63]); } }
  if (bits) out.push_back(alphabet[(accumulator << (6 - bits)) & 63]);
  return out;
}
const std::string kHash = "sha256:" + std::string(64, 'a');
const std::string kRegistryKid = "sha256:1a872137fab095b0d220fafb4e666b0c3867989d80556856ad27debab954cf5c";
const std::string kRegistrySpki = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1afolgZnehFDR3-MZ7SGIVYBDPdLWtO2nzIlDd7hzZLD1IwaOhAB-dnKuGoqNeKpba4P2Jn8f3miTVZQ2vh7UA";
std::vector<unsigned char> PolicyEnvelope() {
  const std::string header = "{\"alg\":\"ES256\",\"kid\":\"" + kHash +
      "\",\"typ\":\"stellar-custodian-gateway-policy+json\",\"version\":1}";
  const std::string payload = "{\"audience\":{\"installId\":\"install-1\",\"machineId\":\"machine-1\"},"
      "\"custodian\":{\"account\":\"NT SERVICE\\\\AegisStellarCustodian\",\"cngKeyReference\":\"Microsoft Platform Crypto Provider\\\\key\",\"pipe\":\"\\\\\\\\.\\\\pipe\\\\AegisStellarCustodian.v0.1\"},"
      "\"expiresAt\":\"2026-09-02T00:00:00.000Z\",\"gateway\":{\"account\":\"NT SERVICE\\\\AegisStellarLabGateway\",\"imageFileId\":\"00000000000000000000000000000000\",\"imagePath\":\"C:\\\\gateway.exe\",\"imageSha256\":\"" + kHash + "\",\"imageVolumeSerial\":1,\"serviceName\":\"AegisStellarLabGateway\",\"signerThumbprint\":\"" + std::string(40, 'A') + "\"},\"issuedAt\":\"2026-09-01T00:00:00.000Z\",\"policyId\":\"policy-1\",\"requestSigner\":{\"kid\":\"" + kHash + "\",\"publicKeySpki\":\"YQ\"},\"schema\":\"stellar.custodian-gateway-policy/v0.1\"}";
  const auto out = "{\"payload\":\"" + B64(payload) + "\",\"protected\":\"" + B64(header) +
      "\",\"schema\":\"stellar.custodian-gateway-policy-envelope/v0.1\",\"signature\":\"" + B64(std::string(64, '\0')) + "\"}";
  return {out.begin(), out.end()};
}
std::vector<unsigned char> Registry() {
  const std::string document = "{\"registryId\":\"registry-1\",\"schema\":\"stellar.request-signer-registry/v0.1\",\"signers\":[{\"kid\":\"" + kRegistryKid + "\",\"publicKeySpki\":\"" + kRegistrySpki + "\"}]}";
  return {document.begin(), document.end()};
}
} // namespace

int main() {
  FakeFilesystem filesystem; filesystem.payload = {'o','k'};
  FakeIdentity identity; std::vector<unsigned char> output;
  if (stellar::service::ReadProtectedInstalledArtifact(
          L"C:\\ProgramData\\AEGIS\\Stellar\\policy.json", 8, filesystem,
          identity, Accept, output) != ProtectedInstalledArtifactStatus::accepted ||
      output != filesystem.payload) return 1;
  if (stellar::service::ReadProtectedInstalledArtifact(
          L"policy.json", 8, filesystem, identity, Accept, output) !=
      ProtectedInstalledArtifactStatus::invalid_path || !output.empty()) return 2;
  filesystem.available = false;
  if (stellar::service::ReadProtectedInstalledArtifact(
          L"C:\\ProgramData\\AEGIS\\Stellar\\policy.json", 8, filesystem,
          identity, Accept, output) != ProtectedInstalledArtifactStatus::unavailable) return 3;
  filesystem.available = true; filesystem.facts.fileReparsePoint = true;
  if (stellar::service::ReadProtectedInstalledArtifact(
          L"C:\\ProgramData\\AEGIS\\Stellar\\policy.json", 8, filesystem,
          identity, Accept, output) != ProtectedInstalledArtifactStatus::hostile_file_state) return 4;
  filesystem.facts.fileReparsePoint = false; filesystem.facts.ancestorReparsePoint = true;
  if (stellar::service::ReadProtectedInstalledArtifact(
          L"C:\\ProgramData\\AEGIS\\Stellar\\policy.json", 8, filesystem,
          identity, Accept, output) != ProtectedInstalledArtifactStatus::hostile_file_state) return 5;
  filesystem.facts.ancestorReparsePoint = false; identity.owner = false;
  if (stellar::service::ReadProtectedInstalledArtifact(
          L"C:\\ProgramData\\AEGIS\\Stellar\\policy.json", 8, filesystem,
          identity, Accept, output) != ProtectedInstalledArtifactStatus::owner_refused) return 6;
  identity.owner = true; identity.acl = false;
  if (stellar::service::ReadProtectedInstalledArtifact(
          L"C:\\ProgramData\\AEGIS\\Stellar\\policy.json", 8, filesystem,
          identity, Accept, output) != ProtectedInstalledArtifactStatus::acl_refused) return 7;
  identity.acl = true; filesystem.payload = {'n','o'};
  if (stellar::service::ReadProtectedInstalledArtifact(
          L"C:\\ProgramData\\AEGIS\\Stellar\\policy.json", 8, filesystem,
          identity, Accept, output) != ProtectedInstalledArtifactStatus::noncanonical) return 8;
  const ProtectedInstalledArtifactPath paths{
      L"C:\\ProgramData\\AEGIS\\Stellar\\policy-envelope.json",
      L"C:\\ProgramData\\AEGIS\\Stellar\\request-signers.json"};
  filesystem.payload = PolicyEnvelope();
  if (stellar::service::ReadProtectedCustodianPolicyEnvelope(paths, filesystem, identity,
                                                              output) != ProtectedInstalledArtifactStatus::accepted) return 9;
  filesystem.payload = Registry();
  if (stellar::service::ReadProtectedRequestSignerRegistry(paths, filesystem, identity,
                                                            output) != ProtectedInstalledArtifactStatus::accepted) return 10;
  filesystem.payload.back() = ' ';
  if (stellar::service::ReadProtectedRequestSignerRegistry(paths, filesystem, identity,
                                                            output) != ProtectedInstalledArtifactStatus::noncanonical) return 11;
  filesystem.payload = Registry();
  std::string mismatched(filesystem.payload.begin(), filesystem.payload.end());
  const auto kid = mismatched.find(kRegistryKid);
  if (kid == std::string::npos) return 12;
  mismatched.replace(kid, kRegistryKid.size(), kHash);
  filesystem.payload.assign(mismatched.begin(), mismatched.end());
  if (stellar::service::ReadProtectedRequestSignerRegistry(paths, filesystem, identity,
                                                            output) != ProtectedInstalledArtifactStatus::noncanonical) return 13;
  return 0;
}
