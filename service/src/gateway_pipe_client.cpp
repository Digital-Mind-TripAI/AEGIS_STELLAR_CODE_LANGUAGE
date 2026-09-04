#include "gateway_pipe_client.h"
#include <sstream>
#include <wincrypt.h>
#pragma comment(lib, "crypt32.lib")

namespace stellar::service {
namespace {
std::string Wide(const std::wstring &value) {
  if (value.empty()) return {};
  const int bytes = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
      value.data(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
  std::string out(static_cast<size_t>(bytes), '\0');
  return bytes > 0 && WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
      value.data(), static_cast<int>(value.size()), out.data(), bytes, nullptr,
      nullptr) == bytes ? out : std::string{};
}
std::string FileId(const FILE_ID_128 &id) {
  static constexpr char hex[] = "0123456789abcdef";
  std::string out;
  out.reserve(32);
  for (BYTE byte : id.Identifier) {
    out.push_back(hex[byte >> 4]);
    out.push_back(hex[byte & 15]);
  }
  return out;
}
bool ChallengeMatches(const json::PipeChallenge &challenge,
                      const wchar_t *pipeName, const PipePeer &peer,
                      const PipePeerPolicy &pin) {
  ULARGE_INTEGER created{};
  created.LowPart = peer.creationTime.dwLowDateTime;
  created.HighPart = peer.creationTime.dwHighDateTime;
  return challenge.pipeId == Wide(pipeName) &&
         challenge.serverServiceName == Wide(pin.serviceName) &&
         challenge.serverServiceSid == Wide(peer.sid) &&
         challenge.serverPid == peer.pid &&
         challenge.serverCreationTime == created.QuadPart &&
         challenge.serverImageHash == Wide(peer.imageSha256) &&
         challenge.serverImageFileId == FileId(peer.imageFileId) &&
         challenge.serverImageVolumeSerial == peer.imageVolumeSerial &&
         challenge.serverImageSigner == Wide(peer.signerThumbprint);
}
class Win32GatewayClientOs final : public GatewayClientOs {
public:
  HANDLE Open(const wchar_t *name) override {
    return CreateFileW(name, GENERIC_READ | FILE_WRITE_DATA, 0, nullptr,
                       OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr);
  }
  bool ObserveServer(HANDLE pipe, const PipePeerPolicy &pin,
                     PipePeer &peer) override {
    ULONG pid = 0;
    return GetNamedPipeServerProcessId(pipe, &pid) &&
           AuthenticatePinnedProcess(pid, pin, peer);
  }
  bool Read(HANDLE pipe, HANDLE stop, std::vector<BYTE> &body,
            DWORD deadline) override {
    bool consumed = false;
    return ReadBoundedFrame(pipe, stop, body, consumed, deadline);
  }
  bool Write(HANDLE pipe, HANDLE stop, const std::vector<BYTE> &body,
             DWORD deadline) override {
    return WriteBoundedFrame(pipe, stop, body, deadline);
  }
  unsigned long long MonotonicMilliseconds() override { return GetTickCount64(); }
  bool Cancelled(HANDLE stop) override {
    return WaitForSingleObject(stop, 0) == WAIT_OBJECT_0;
  }
  void Close(HANDLE pipe) override {
    CancelIoEx(pipe, nullptr);
    CloseHandle(pipe);
  }
};
} // namespace

bool VerifyRegistrySignedRequest(const std::vector<BYTE> &canonicalEnvelope,
    const SignedKeyRegistryFile &registry, unsigned long long registryTime,
    json::SignedEnvelope *decoded) {
  if (canonicalEnvelope.empty()) return false;
  json::SignedEnvelope envelope;
  if (!json::ParseCanonicalSignedRequest(std::string_view(
          reinterpret_cast<const char *>(canonicalEnvelope.data()),
          canonicalEnvelope.size()), &envelope).accepted) return false;
  const auto record = registry.Resolve(envelope.kid, registryTime);
  if (!record) return false;
  std::vector<unsigned char> der;
  if (!json::DecodeCanonicalBase64Url(record->spki, der)) return false;
  CERT_PUBLIC_KEY_INFO *info = nullptr;
  DWORD infoBytes = 0;
  if (!CryptDecodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, der.data(),
      static_cast<DWORD>(der.size()), CRYPT_DECODE_ALLOC_FLAG, nullptr, &info,
      &infoBytes) || !info) return false;
  BCRYPT_KEY_HANDLE publicKey{};
  const bool imported = CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING, info, 0,
                                                     nullptr, &publicKey) == TRUE;
  LocalFree(info);
  if (!imported) return false;
  const std::string input = envelope.protectedBase64 + "." + envelope.payloadBase64;
  const std::vector<BYTE> bytes(input.begin(), input.end());
  const std::vector<BYTE> signature(envelope.signature.begin(), envelope.signature.end());
  const bool valid = VerifyEs256WithCng(publicKey, bytes, signature);
  BCryptDestroyKey(publicKey);
  if (valid && decoded) *decoded = std::move(envelope);
  return valid;
}
bool VerifyRegistryBrokerReceipt(const std::vector<BYTE> &canonicalEnvelope,
    const SignedKeyRegistryFile &registry, unsigned long long registryTime,
    json::BrokerReceiptEnvelope *decoded) {
  if (canonicalEnvelope.empty()) return false;
  json::BrokerReceiptEnvelope envelope;
  if (!json::ParseCanonicalBrokerReceipt(std::string_view(
          reinterpret_cast<const char *>(canonicalEnvelope.data()),
          canonicalEnvelope.size()), &envelope).accepted) return false;
  const auto record = registry.Resolve(envelope.kid, registryTime);
  if (!record) return false;
  std::vector<unsigned char> der;
  if (!json::DecodeCanonicalBase64Url(record->spki, der)) return false;
  CERT_PUBLIC_KEY_INFO *info = nullptr;
  DWORD infoBytes = 0;
  if (!CryptDecodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, der.data(),
      static_cast<DWORD>(der.size()), CRYPT_DECODE_ALLOC_FLAG, nullptr, &info,
      &infoBytes) || !info) return false;
  BCRYPT_KEY_HANDLE publicKey{};
  const bool imported = CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING, info, 0,
                                                     nullptr, &publicKey) == TRUE;
  LocalFree(info);
  if (!imported) return false;
  const std::string input = envelope.protectedBase64 + "." + envelope.payloadBase64;
  const std::vector<BYTE> bytes(input.begin(), input.end());
  const std::vector<BYTE> signature(envelope.signature.begin(), envelope.signature.end());
  const bool valid = VerifyEs256WithCng(publicKey, bytes, signature);
  BCryptDestroyKey(publicKey);
  if (valid && decoded) *decoded = std::move(envelope);
  return valid;
}
bool BrokerReceiptMatches(const json::BrokerReceipt &r,
                          const BrokerReceiptBinding &e,
                          unsigned long long now) {
  return r.requestId == e.requestId && r.requestHash == e.requestHash &&
    r.contractId == e.contractId && r.contractHash == e.contractHash &&
    r.nonce == e.nonce && r.operationId == e.operationId &&
    r.releaseHash == e.releaseHash && r.action == e.action &&
    r.evidenceHash == e.evidenceHash && r.cleanupEvidenceHash == e.cleanupEvidenceHash &&
    r.hostId == e.hostId && r.targetService == e.targetService &&
    r.brokerService == e.brokerService && r.brokerImageHash == e.brokerImageHash &&
    r.runnerHash == e.runnerHash && r.issuedAt <= now && now <= r.expiresAt &&
    (r.status == "completed" || r.status == "refused");
}

bool GatewayExchangeMutuallyAuthenticatedWithOs(const wchar_t *pipeName,
    const GatewayServerPin &pin, HANDLE stopEvent,
    const GatewayRequestSigner &signRequest,
    const GatewayReplyVerifier &verifyReply, std::vector<BYTE> &reply,
    GatewayClientOs &os, DWORD deadlineMs) {
  reply.clear();
  if (!pipeName || !stopEvent || !signRequest || !verifyReply ||
      !deadlineMs || deadlineMs > kPipeOperationDeadlineMs) return false;
  const auto started = os.MonotonicMilliseconds();
  auto remaining = [&]() -> DWORD {
    const auto elapsed = os.MonotonicMilliseconds() - started;
    return elapsed >= deadlineMs ? 0u : static_cast<DWORD>(deadlineMs - elapsed);
  };
  HANDLE pipe = os.Open(pipeName);
  if (pipe == INVALID_HANDLE_VALUE) return false;
  PipePeer peer;
  bool ok = !os.Cancelled(stopEvent) && os.ObserveServer(pipe, pin.identity, peer);
  std::vector<BYTE> challenge, request;
  DWORD budget = remaining();
  if (ok) ok = budget && os.Read(pipe, stopEvent, challenge, budget);
  json::PipeChallenge decoded;
  if (ok) ok = json::ParseCanonicalChallenge(std::string_view(
      reinterpret_cast<const char *>(challenge.data()), challenge.size()),
      &decoded).accepted && ChallengeMatches(decoded, pipeName, peer, pin.identity);
  // No request bytes exist until a verified, server-originated challenge is read.
  if (ok) ok = !os.Cancelled(stopEvent) && signRequest(decoded, challenge, request) &&
               !request.empty();
  budget = remaining();
  if (ok) ok = budget && os.Write(pipe, stopEvent, request, budget);
  budget = remaining();
  if (ok) ok = budget && os.Read(pipe, stopEvent, reply, budget);
  if (ok) ok = !os.Cancelled(stopEvent) && remaining() &&
               verifyReply(decoded, request, reply);
  os.Close(pipe);
  if (!ok) reply.clear();
  return ok;
}
bool GatewayExchangeMutuallyAuthenticated(const wchar_t *pipeName,
    const GatewayServerPin &pin, HANDLE stopEvent,
    const GatewayRequestSigner &signRequest,
    const GatewayReplyVerifier &verifyReply, std::vector<BYTE> &reply,
    DWORD deadlineMs) {
  Win32GatewayClientOs os;
  return GatewayExchangeMutuallyAuthenticatedWithOs(pipeName, pin, stopEvent,
      signRequest, verifyReply, reply, os, deadlineMs);
}
} // namespace stellar::service
