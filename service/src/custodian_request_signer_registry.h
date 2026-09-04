#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace stellar::service {
enum class CustodianRequestSignerStatus { accepted, unknown_key, revoked, unavailable };

// The installed authenticated registry is deliberately not synthesized by the
// offline source tranche.  A future implementation must return a canonical
// P-256 SPKI only after validating protected registry state and rotation.
class CustodianRequestSignerRegistry {
public:
  virtual ~CustodianRequestSignerRegistry() = default;
  virtual CustodianRequestSignerStatus ResolveActiveP256Signer(
      const std::string &keyId, std::uint64_t nowUnixMilliseconds,
      std::vector<unsigned char> &subjectPublicKeyInfo) const = 0;
};

class ClosedCustodianRequestSignerRegistry final : public CustodianRequestSignerRegistry {
public:
  CustodianRequestSignerStatus ResolveActiveP256Signer(
      const std::string &, std::uint64_t,
      std::vector<unsigned char> &subjectPublicKeyInfo) const override;
};
} // namespace stellar::service
