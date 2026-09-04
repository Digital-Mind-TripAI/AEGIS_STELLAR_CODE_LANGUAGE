#include "lab_gateway_bridge.h"
#include <utility>

namespace stellar::service {
namespace {
bool Same(const json::LabGatewayBridgeIdentity &a,
          const json::LabGatewayBridgeIdentity &b) {
  return a.account == b.account && a.executablePath == b.executablePath &&
         a.pipe == b.pipe && a.serviceName == b.serviceName;
}
void Refuse(const json::LabGatewayBridgeRequest &request,
            const LabGatewayBridgeBinding &binding, const char *reason,
            json::LabGatewayBridgeResult &result) {
  result = {binding.issuerKeyId, reason, request.requestId,
            request.signingInputHash, "refused", {}};
}
} // namespace

bool DispatchLabGatewayBridgeRequest(const json::LabGatewayBridgeRequest &request,
                                     const LabGatewayBridgeBinding &binding,
                                     LabGatewayCustodianChannel &channel,
                                     json::LabGatewayBridgeResult &result) {
  result = {};
  if (binding.issuerKeyId.empty() || !Same(request.bridge, binding.identity) ||
      request.cngKeyReference != binding.cngKeyReference ||
      request.installId != binding.installId || request.machineId != binding.machineId)
    return false;
  json::CustodianIssuanceRequest custodian{request.requestId,
                                            request.signingInput,
                                            request.signingInputHash};
  json::CustodianIssuanceResult custodianResult;
  if (!channel.Issue(custodian, custodianResult)) {
    Refuse(request, binding, "custodian-unavailable", result);
    return true;
  }
  if (custodianResult.requestId != request.requestId ||
      custodianResult.signingInputHash != request.signingInputHash ||
      custodianResult.keyId != binding.issuerKeyId ||
      (custodianResult.status != "issued" && custodianResult.status != "refused")) {
    Refuse(request, binding, "custodian-result-invalid", result);
    return true;
  }
  if (custodianResult.status == "issued" && custodianResult.signature.size() != 64) {
    Refuse(request, binding, "custodian-result-invalid", result);
    return true;
  }
  if (custodianResult.status == "refused" &&
      (!custodianResult.signature.empty() || custodianResult.refusalCode.empty())) {
    Refuse(request, binding, "custodian-result-invalid", result);
    return true;
  }
  result = {custodianResult.keyId, custodianResult.refusalCode,
            custodianResult.requestId, custodianResult.signingInputHash,
            custodianResult.status, std::move(custodianResult.signature)};
  return true;
}
} // namespace stellar::service
