#include "startup_gate_sequence.h"
#include <array>
namespace stellar::service {
bool StartupGateSequence::Checkpoint(std::wstring_view gate, bool passed) {
  static constexpr std::array<std::wstring_view, 7> gates = {
    L"config", L"release-manifest", L"key-registry", L"protected-acl-roots",
    L"pipe-dacl-create", L"self-attestation-static-imports", L"worker-ready"};
  if (failed_ || !passed || next_ >= gates.size() || gate != gates[next_]) {
    failed_ = true;
    return false;
  }
  ++next_;
  return true;
}
bool StartupGateSequence::Ready() const { return !failed_ && next_ == 7; }
} // namespace stellar::service
