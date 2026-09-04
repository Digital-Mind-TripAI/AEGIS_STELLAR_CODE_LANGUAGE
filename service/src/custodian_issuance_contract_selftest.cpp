#include "canonical_json.h"
#include "custodian_request_signer_registry.h"
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
    while (bits >= 6) { bits -= 6; out.push_back(alphabet[(accumulator >> bits) & 63]); }
  }
  if (bits) out.push_back(alphabet[(accumulator << (6 - bits)) & 63]);
  return out;
}
const std::string kHash = "sha256:" + std::string(64, 'a');
std::string Request() {
  return "{\"action\":\"issue-capability-contract\",\"requestId\":\"request-1\",\"schema\":\"stellar.custodian-issuance-request/v0.1\",\"signingInput\":\"YQ\",\"signingInputHash\":\"" + kHash + "\"}";
}
std::string Result(std::string_view status) {
  const bool issued = status == "issued";
  return "{\"keyId\":\"" + kHash + "\",\"refusalCode\":\"" + (issued ? "" : "registry-unavailable") + "\",\"requestId\":\"request-1\",\"schema\":\"stellar.custodian-issuance-result/v0.1\",\"signature\":\"" + (issued ? B64(std::string(64, '\0')) : "") + "\",\"signingInputHash\":\"" + kHash + "\",\"status\":\"" + std::string(status) + "\"}";
}
} // namespace

int main() {
  stellar::service::json::CustodianIssuanceRequest request;
  if (!stellar::service::json::ParseCanonicalCustodianIssuanceRequest(Request(), &request).accepted ||
      request.requestId != "request-1" || request.signingInput != "YQ") return 1;
  stellar::service::json::CustodianIssuanceResult issued;
  if (!stellar::service::json::ParseCanonicalCustodianIssuanceResult(Result("issued"), &issued).accepted ||
      issued.status != "issued" || issued.signature.size() != 64) return 2;
  stellar::service::json::CustodianIssuanceResult refused;
  if (!stellar::service::json::ParseCanonicalCustodianIssuanceResult(Result("refused"), &refused).accepted ||
      refused.status != "refused" || !refused.signature.empty()) return 3;
  std::string noncanonical = Request();
  noncanonical.replace(noncanonical.find("\"action\""), 8, "\"zction\"");
  if (stellar::service::json::ParseCanonicalCustodianIssuanceRequest(noncanonical).accepted) return 4;
  std::string invalid = Result("issued");
  const auto signature = invalid.find("\"signature\":\"");
  if (signature == std::string::npos) return 5;
  invalid.replace(signature + 13, 86, "YQ");
  if (stellar::service::json::ParseCanonicalCustodianIssuanceResult(invalid).accepted) return 6;
  stellar::service::ClosedCustodianRequestSignerRegistry registry;
  std::vector<unsigned char> spki{1};
  if (registry.ResolveActiveP256Signer(kHash, 1, spki) !=
          stellar::service::CustodianRequestSignerStatus::unavailable || !spki.empty()) return 7;
  return 0;
}
