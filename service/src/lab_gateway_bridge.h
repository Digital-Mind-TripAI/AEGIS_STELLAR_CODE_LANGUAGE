#pragma once
#include "canonical_json.h"

namespace stellar::service {
struct LabGatewayBridgeBinding {
  json::LabGatewayBridgeIdentity identity;
  std::string cngKeyReference, installId, machineId, issuerKeyId;
};

// The native Custodian is intentionally not opened by this interface. A
// production channel must be installed and mutually authenticated separately.
class LabGatewayCustodianChannel {
public:
  virtual ~LabGatewayCustodianChannel() = default;
  virtual bool Issue(const json::CustodianIssuanceRequest &request,
                     json::CustodianIssuanceResult &result) = 0;
};
class ClosedLabGatewayCustodianChannel final : public LabGatewayCustodianChannel {
public:
  bool Issue(const json::CustodianIssuanceRequest &,
             json::CustodianIssuanceResult &) override { return false; }
};

// Returns false only for malformed/unbound input. A valid request directed at
// an unavailable Custodian receives a canonical refused result; it never uses
// an in-process key or synthetic signature.
bool DispatchLabGatewayBridgeRequest(const json::LabGatewayBridgeRequest &request,
                                     const LabGatewayBridgeBinding &binding,
                                     LabGatewayCustodianChannel &channel,
                                     json::LabGatewayBridgeResult &result);
} // namespace stellar::service
