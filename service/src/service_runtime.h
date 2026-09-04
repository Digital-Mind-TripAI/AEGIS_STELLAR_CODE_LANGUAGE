#pragma once
#include "service_common.h"
#include "startup_gate_sequence.h"
#include <bcrypt.h>
#include <functional>

namespace stellar::service {
inline constexpr DWORD kMaximumFrameBytes = 32768;
inline constexpr DWORD kMaximumConcurrentConnections = 1;
inline constexpr DWORD kPipeOperationDeadlineMs = 5000;
inline constexpr DWORD kGatewayPipeClientDesiredAccess =
    GENERIC_READ | FILE_WRITE_DATA;
inline constexpr DWORD kGatewayPipeClientAclMask =
    FILE_GENERIC_READ | FILE_WRITE_DATA; // 0x0012008b; no create-instance bit.

struct StartupReadiness {
  bool Checkpoint(const wchar_t *gateName, bool gatePassed);
  bool Running();
private:
  StartupGateSequence sequence_;
};
using ServiceWorker = DWORD (*)(HANDLE stopEvent, StartupReadiness &readiness);
int RunWindowsService(const wchar_t *serviceName, ServiceWorker worker);
bool ServiceStopRequested(HANDLE stopEvent);

struct PipePeer {
  PipePeer() = default;
  PipePeer(const PipePeer &) = delete;
  PipePeer &operator=(const PipePeer &) = delete;
  ~PipePeer();
  DWORD pid{};
  std::wstring sid;
  std::wstring imagePath;
  FILETIME creationTime{};
  FILE_ID_128 imageFileId{};
  DWORD imageVolumeSerial{};
  std::wstring imageSha256;
  std::wstring signerThumbprint;
  std::wstring scmServiceName;
  HANDLE processHandle{INVALID_HANDLE_VALUE};
  HANDLE imageHandle{INVALID_HANDLE_VALUE};
};
struct PipePeerPolicy {
  std::wstring account;
  std::wstring serviceName;
  std::wstring imagePath;
  std::wstring imageSha256;
  std::wstring imageFileId;
  DWORD imageVolumeSerial{};
  std::wstring signerThumbprint;
};
struct SignedRequestVerifier {
  virtual ~SignedRequestVerifier() = default;
  enum class Result {
    accepted,
    malformed,
    unknown_key,
    bad_signature,
    expired,
    replay,
    binding_mismatch
  };
  virtual Result VerifyAndConsumeStrictCanonicalEs256(
      const std::string &envelope, const std::string &challengeHash,
      const std::string &expectedAction, const PipePeer &osPeer,
      unsigned long long challengeIssuedAt,
      unsigned long long challengeExpiresAt,
      unsigned long long nowAfterReceipt) = 0;
};
bool VerifyEs256WithCng(BCRYPT_KEY_HANDLE publicKey,
                        const std::vector<BYTE> &signedBytes,
                        const std::vector<BYTE> &p1363Signature);
HANDLE CreateAuthenticatedPipe(const wchar_t *pipeName,
                               const wchar_t *ownerService,
                               const wchar_t *gatewayService,
                               DWORD messageBytes = kMaximumFrameBytes);
bool ConnectAuthenticatedPipe(HANDLE pipe, HANDLE stopEvent,
                              DWORD deadlineMs = kPipeOperationDeadlineMs);
bool AuthenticatePipeClient(HANDLE pipe, const PipePeerPolicy &policy,
                            PipePeer &peer);
bool AuthenticatePinnedProcess(DWORD pid, const PipePeerPolicy &policy,
                               PipePeer &peer);
bool ReadBoundedFrame(HANDLE pipe, HANDLE stopEvent, std::vector<BYTE> &body,
                      bool &oneRequestPerConnection,
                      DWORD deadlineMs = kPipeOperationDeadlineMs,
                      DWORD maxBytes = kMaximumFrameBytes);
bool WriteBoundedFrame(HANDLE pipe, HANDLE stopEvent,
                       const std::vector<BYTE> &body,
                       DWORD deadlineMs = kPipeOperationDeadlineMs,
                       DWORD maxBytes = kMaximumFrameBytes);
enum class HandshakeState {
  connected,
  challenge_sent,
  reply_received,
  identity_bound,
  accepted,
  refused,
  stopped
};
bool PerformAuthenticatedHandshake(
    HANDLE pipe, HANDLE stopEvent, const wchar_t *pipeId,
    const wchar_t *serverServiceName, const PipePeerPolicy &clientPolicy,
    SignedRequestVerifier &verifier, const char *expectedAction, PipePeer &peer,
    std::vector<BYTE> &canonicalRequest, HandshakeState &state,
    DWORD deadlineMs = kPipeOperationDeadlineMs);
void CancelPipeIoAndDrain(HANDLE pipe, OVERLAPPED &overlapped);
} // namespace stellar::service
