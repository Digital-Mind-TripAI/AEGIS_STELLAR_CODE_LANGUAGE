#pragma once
#include <string>

namespace stellar::discovery {
class ObservationProvider {
public:
  virtual ~ObservationProvider() = default;
  virtual bool Observe(std::string &canonicalSnapshots,
                       std::string &error) const = 0;
};

std::string Sha256(std::string_view bytes);
bool BuildEvidence(const ObservationProvider &provider, std::string &canonical,
                   std::string &error);
int RunSelfTest();
} // namespace stellar::discovery
