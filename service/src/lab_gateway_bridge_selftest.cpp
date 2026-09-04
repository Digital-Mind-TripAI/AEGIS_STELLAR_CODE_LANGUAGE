#include "lab_gateway_bridge.h"
#include <string>

namespace {
const std::string kHash = "sha256:" + std::string(64, 'a');
std::string Request() {
  return "{\"action\":\"sign-capability-contract\",\"bridge\":{\"account\":\"NT SERVICE\\\\AegisStellarLabGateway\",\"executablePath\":\"C:\\\\Program Files\\\\AEGIS\\\\Stellar\\\\v0.1\\\\bin\\\\AegisStellarLabGateway.exe\",\"pipe\":\"\\\\\\\\.\\\\pipe\\\\AegisStellarLabGateway.v0.1\",\"serviceName\":\"AegisStellarLabGateway\"},\"cngKeyReference\":\"Microsoft Platform Crypto Provider\\\\AegisStellarCustodian-Issuer-P256-v1\",\"installId\":\"install-1\",\"machineId\":\"machine-1\",\"requestId\":\"request-1\",\"schema\":\"stellar.lab-gateway-bridge-request/v0.1\",\"signingInput\":\"YQ\",\"signingInputHash\":\"" + kHash + "\"}";
}
stellar::service::LabGatewayBridgeBinding Binding() {
  return {{"NT SERVICE\\AegisStellarLabGateway", "C:\\Program Files\\AEGIS\\Stellar\\v0.1\\bin\\AegisStellarLabGateway.exe", "\\\\.\\pipe\\AegisStellarLabGateway.v0.1", "AegisStellarLabGateway"}, "Microsoft Platform Crypto Provider\\AegisStellarCustodian-Issuer-P256-v1", "install-1", "machine-1", kHash};
}
} // namespace

int main() {
  stellar::service::json::LabGatewayBridgeRequest request;
  if (!stellar::service::json::ParseCanonicalLabGatewayBridgeRequest(Request(), &request).accepted ||
      request.bridge.serviceName != "AegisStellarLabGateway") return 1;
  stellar::service::ClosedLabGatewayCustodianChannel channel;
  stellar::service::json::LabGatewayBridgeResult result;
  if (!stellar::service::DispatchLabGatewayBridgeRequest(request, Binding(), channel, result) ||
      result.status != "refused" || result.refusalCode != "custodian-unavailable" ||
      !result.signature.empty()) return 2;
  const std::string refused = "{\"keyId\":\"" + kHash + "\",\"refusalCode\":\"custodian-unavailable\",\"requestId\":\"request-1\",\"schema\":\"stellar.lab-gateway-bridge-result/v0.1\",\"signature\":\"\",\"signingInputHash\":\"" + kHash + "\",\"status\":\"refused\"}";
  if (!stellar::service::json::ParseCanonicalLabGatewayBridgeResult(refused).accepted) return 3;
  auto wrong = request; wrong.machineId = "machine-2";
  if (stellar::service::DispatchLabGatewayBridgeRequest(wrong, Binding(), channel, result)) return 4;
  std::string noncanonical = Request();
  noncanonical.replace(noncanonical.find("\"action\""), 8, "\"zction\"");
  if (stellar::service::json::ParseCanonicalLabGatewayBridgeRequest(noncanonical).accepted) return 5;
  return 0;
}
