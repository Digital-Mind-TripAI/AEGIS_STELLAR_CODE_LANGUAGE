#include "gateway_pipe_client.h"
#include <cstring>
using namespace stellar::service;
namespace {
constexpr wchar_t PipeName[] = L"\\\\.\\pipe\\stellar-test";
const std::string Challenge =
  "{\"expiresAt\":5000,\"issuedAt\":1,\"nonce\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\","
  "\"pipeId\":\"\\\\\\\\.\\\\pipe\\\\stellar-test\",\"protocolVersion\":\"0.1\","
  "\"schema\":\"stellar-pipe-challenge-v0.1\",\"serverCreationTime\":7,"
  "\"serverImageFileId\":\"00000000000000000000000000000000\","
  "\"serverImageHash\":\"sha256:1111111111111111111111111111111111111111111111111111111111111111\","
  "\"serverImageSigner\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"serverImageVolumeSerial\":9,"
  "\"serverInstanceId\":\"instance\",\"serverPid\":42,"
  "\"serverServiceName\":\"Gateway\",\"serverServiceSid\":\"S-1-5-80-test\"}";
struct Mock final : GatewayClientOs {
  enum class Fault { none, pid, image, challenge, deadline, cancel } fault{};
  int reads{}, writes{}, timeCalls{};
  HANDLE Open(const wchar_t *) override { return reinterpret_cast<HANDLE>(1); }
  bool ObserveServer(HANDLE, const PipePeerPolicy &, PipePeer &peer) override {
    peer.pid = fault == Fault::pid ? 43 : 42;
    peer.sid = L"S-1-5-80-test";
    peer.creationTime.dwLowDateTime = 7;
    peer.imageSha256 = fault == Fault::image
      ? L"sha256:2222222222222222222222222222222222222222222222222222222222222222"
      : L"sha256:1111111111111111111111111111111111111111111111111111111111111111";
    peer.imageVolumeSerial = 9;
    peer.signerThumbprint = L"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    return true;
  }
  bool Read(HANDLE, HANDLE, std::vector<BYTE> &body, DWORD) override {
    ++reads;
    const std::string value = reads == 1
      ? (fault == Fault::challenge ? Challenge + " " : Challenge)
      : "signed-reply";
    body.assign(value.begin(), value.end());
    return true;
  }
  bool Write(HANDLE, HANDLE, const std::vector<BYTE> &body, DWORD) override {
    ++writes;
    return std::string(body.begin(), body.end()) == "signed-request";
  }
  unsigned long long MonotonicMilliseconds() override {
    ++timeCalls;
    return fault == Fault::deadline && timeCalls > 1 ? 6000 : 0;
  }
  bool Cancelled(HANDLE) override { return fault == Fault::cancel; }
  void Close(HANDLE) override {}
};
bool Run(Mock::Fault fault, bool verifier, int &signedCount) {
  Mock os; os.fault = fault;
  GatewayServerPin pin;
  pin.identity.serviceName = L"Gateway";
  std::vector<BYTE> reply;
  return GatewayExchangeMutuallyAuthenticatedWithOs(PipeName, pin,
    reinterpret_cast<HANDLE>(2),
    [&](const json::PipeChallenge &, const std::vector<BYTE> &challenge,
        std::vector<BYTE> &request) {
      ++signedCount;
      if (std::string(challenge.begin(), challenge.end()) != Challenge) return false;
      const std::string value = "signed-request";
      request.assign(value.begin(), value.end());
      return true;
    },
    [=](const json::PipeChallenge &, const std::vector<BYTE> &,
        const std::vector<BYTE> &) { return verifier; },
    reply, os, 5000);
}
} // namespace
int main() {
  int signedCount = 0;
  if (!Run(Mock::Fault::none, true, signedCount) || signedCount != 1) return 1;
  for (auto fault : {Mock::Fault::pid, Mock::Fault::image,
                     Mock::Fault::challenge, Mock::Fault::deadline,
                     Mock::Fault::cancel}) {
    signedCount = 0;
    if (Run(fault, true, signedCount)) return 2;
    if ((fault == Mock::Fault::pid || fault == Mock::Fault::image ||
         fault == Mock::Fault::challenge || fault == Mock::Fault::cancel) &&
        signedCount != 0) return 3;
  }
  signedCount = 0;
  if (Run(Mock::Fault::none, false, signedCount) || signedCount != 1) return 4;
  // The same production verifier callback boundary carries signature and replay
  // refusal; both must fail closed without a second request.
  signedCount = 0;
  if (Run(Mock::Fault::none, false, signedCount) || signedCount != 1) return 5;
  return 0;
}
