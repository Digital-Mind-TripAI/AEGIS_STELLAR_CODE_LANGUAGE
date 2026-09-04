#include "custodian_request_signer_registry.h"

namespace stellar::service {
CustodianRequestSignerStatus
ClosedCustodianRequestSignerRegistry::ResolveActiveP256Signer(
    const std::string &, std::uint64_t,
    std::vector<unsigned char> &subjectPublicKeyInfo) const {
  subjectPublicKeyInfo.clear();
  return CustodianRequestSignerStatus::unavailable;
}
} // namespace stellar::service
