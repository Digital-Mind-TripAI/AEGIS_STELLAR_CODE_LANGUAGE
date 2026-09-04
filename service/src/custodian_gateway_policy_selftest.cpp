#include "custodian_gateway_policy.h"
#include "canonical_json.h"
#include <array>
#include <string>
#include <string_view>
#include <vector>

namespace {
std::string B64(std::string_view value) {
  static constexpr char alphabet[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  std::string out;
  unsigned accumulator = 0, bits = 0;
  for (unsigned char ch : value) {
    accumulator = (accumulator << 8) | ch;
    bits += 8;
    while (bits >= 6) {
      bits -= 6;
      out.push_back(alphabet[(accumulator >> bits) & 63]);
    }
  }
  if (bits) out.push_back(alphabet[(accumulator << (6 - bits)) & 63]);
  return out;
}
const std::string kHash = "sha256:" + std::string(64, 'a');
const std::string kAuthorityKid =
    "sha256:1a872137fab095b0d220fafb4e666b0c3867989d80556856ad27debab954cf5c";
const std::string kRequestSignerKid =
    "sha256:ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb";
std::string Envelope() {
  const std::string header =
      "{\"alg\":\"ES256\",\"kid\":\"" + kAuthorityKid +
      "\",\"typ\":\"stellar-custodian-gateway-policy+json\",\"version\":1}";
  const std::string payload =
      "{\"audience\":{\"installId\":\"install-1\",\"machineId\":\"machine-1\"},"
      "\"custodian\":{\"account\":\"NT SERVICE\\\\AegisStellarCustodian\","
      "\"cngKeyReference\":\"Microsoft Platform Crypto Provider\\\\AegisStellarCustodian-Issuer-P256-v1\","
      "\"pipe\":\"\\\\\\\\.\\\\pipe\\\\AegisStellarCustodian.v0.1\"},"
      "\"expiresAt\":\"2026-09-02T00:00:00.000Z\","
      "\"gateway\":{\"account\":\"NT SERVICE\\\\AegisStellarLabGateway\","
      "\"imageFileId\":\"00000000000000000000000000000000\",\"imagePath\":\"C:\\\\Program Files\\\\AEGIS\\\\gateway.exe\","
      "\"imageSha256\":\"" + kHash + "\",\"imageVolumeSerial\":1,\"serviceName\":\"AegisStellarLabGateway\",\"signerThumbprint\":\"" + std::string(40, 'A') + "\"},"
      "\"issuedAt\":\"2026-09-01T00:00:00.000Z\",\"policyId\":\"policy-1\","
      "\"requestSigner\":{\"kid\":\"" + kRequestSignerKid + "\",\"publicKeySpki\":\"YQ\"},"
      "\"schema\":\"stellar.custodian-gateway-policy/v0.1\"}";
  const std::string signature(64, '\0');
  return "{\"payload\":\"" + B64(payload) + "\",\"protected\":\"" + B64(header) +
      "\",\"schema\":\"stellar.custodian-gateway-policy-envelope/v0.1\",\"signature\":\"" + B64(signature) + "\"}";
}
stellar::service::CustodianGatewayPolicyBinding Binding() {
  return {"install-1", "machine-1", "NT SERVICE\\AegisStellarCustodian",
          "Microsoft Platform Crypto Provider\\AegisStellarCustodian-Issuer-P256-v1",
          "\\\\.\\pipe\\AegisStellarCustodian.v0.1"};
}
} // namespace

int main() {
  const auto source = Envelope();
  stellar::service::json::CustodianGatewayPolicyEnvelope parsed;
  if (!stellar::service::json::ParseCanonicalCustodianGatewayPolicy(source, &parsed).accepted ||
      parsed.policy.gateway.serviceName != "AegisStellarLabGateway") return 1;
  const std::vector<BYTE> bytes(source.begin(), source.end());
  stellar::service::PipePeerPolicy pin;
  bool observed = false;
  const std::string expectedInput = parsed.protectedBase64 + "." + parsed.payloadBase64;
  const auto verifier = [&](const std::string &kid, const std::vector<BYTE> &input,
                            const std::vector<BYTE> &signature) {
    observed = kid == kAuthorityKid && signature.size() == 64 &&
               input == std::vector<BYTE>(expectedInput.begin(), expectedInput.end());
    return observed;
  };
  if (!stellar::service::LoadCustodianGatewayPolicyWithVerifier(
          bytes, Binding(), 1788264000000ULL, verifier, pin) || !observed ||
      pin.account != L"NT SERVICE\\AegisStellarLabGateway" ||
      pin.imageSha256 != std::wstring(kHash.begin(), kHash.end())) return 2;
  auto wrong = Binding(); wrong.machineId = "other";
  if (stellar::service::LoadCustodianGatewayPolicyWithVerifier(
          bytes, wrong, 1788264000000ULL, verifier, pin)) return 3;
  if (stellar::service::LoadCustodianGatewayPolicyWithVerifier(
          bytes, Binding(), 1788393600000ULL, verifier, pin)) return 4;
  if (stellar::service::LoadCustodianGatewayPolicyWithVerifier(
          bytes, Binding(), 1788264000000ULL,
          [](const std::string &, const std::vector<BYTE> &, const std::vector<BYTE> &) { return false; }, pin)) return 5;
  if (stellar::service::LoadCustodianGatewayPolicy(bytes, Binding(), 1788264000000ULL, pin)) return 6;
  std::string noncanonical = source;
  const auto payload = noncanonical.find("\"payload\"");
  const auto protectedField = noncanonical.find("\"protected\"");
  if (payload == std::string::npos || protectedField == std::string::npos) return 7;
  noncanonical.replace(payload, std::string("\"payload\"").size(), "\"zayload\"");
  if (stellar::service::json::ParseCanonicalCustodianGatewayPolicy(noncanonical).accepted) return 8;
  return 0;
}
