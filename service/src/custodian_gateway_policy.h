#pragma once
#include "service_runtime.h"
#include <functional>
#include <string>
#include <vector>

namespace stellar::service {
struct CustodianGatewayPolicyBinding {
  std::string installId, machineId, custodianAccount, cngKeyReference, pipe;
};
using CustodianPolicySignatureVerifier = std::function<bool(
    const std::string &kid, const std::vector<BYTE> &signedBytes,
    const std::vector<BYTE> &p1363Signature)>;

// Verifies an exact canonical envelope and every deployment binding before
// converting its gateway pins to the pipe identity policy. There is no
// permissive/default policy when the artifact, authority, or any binding is
// unavailable.
bool LoadCustodianGatewayPolicyWithVerifier(
    const std::vector<BYTE> &canonicalEnvelope,
    const CustodianGatewayPolicyBinding &expected,
    unsigned long long nowUnixMilliseconds,
    const CustodianPolicySignatureVerifier &verify,
    PipePeerPolicy &gatewayPolicy);

// Production wrapper: accepts only the compiled immutable policy authority.
bool LoadCustodianGatewayPolicy(const std::vector<BYTE> &canonicalEnvelope,
                                const CustodianGatewayPolicyBinding &expected,
                                unsigned long long nowUnixMilliseconds,
                                PipePeerPolicy &gatewayPolicy);
} // namespace stellar::service
