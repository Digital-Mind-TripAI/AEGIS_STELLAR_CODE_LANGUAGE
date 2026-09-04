#pragma once
#include <cstddef>
#include <string_view>
namespace stellar::service {
class StartupGateSequence {
public:
  bool Checkpoint(std::wstring_view gate, bool passed);
  bool Ready() const;
private:
  std::size_t next_{};
  bool failed_{};
};
} // namespace stellar::service
