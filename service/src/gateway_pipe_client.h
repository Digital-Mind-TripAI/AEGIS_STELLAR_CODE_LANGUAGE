#pragma once
#include "canonical_json.h"
#include "durable_state.h"
#include "service_runtime.h"
#include <functional>

namespace stellar::service {
struct GatewayServerPin { PipePeerPolicy identity; };
struct BrokerReceiptBinding {
  std::string requestId, requestHash, contractId, contractHash, nonce,
      operationId, releaseHash, action, evidenceHash, cleanupEvidenceHash,
      hostId, targetService, brokerService, brokerImageHash, runnerHash;
};
using GatewayRequestSigner = std::function<bool(
    const json::PipeChallenge &, const std::vector<BYTE> &,
    std::vector<BYTE> &)>;
using GatewayReplyVerifier = std::function<bool(
    const json::PipeChallenge &, const std::vector<BYTE> &,
    const std::vector<BYTE> &)>;

class GatewayClientOs {
public:
  virtual ~GatewayClientOs() = default;
  virtual HANDLE Open(const wchar_t *pipeName) = 0;
  virtual bool ObserveServer(HANDLE pipe, const PipePeerPolicy &pin,
                             PipePeer &peer) = 0;
  virtual bool Read(HANDLE pipe, HANDLE stopEvent, std::vector<BYTE> &body,
                    DWORD deadlineMs) = 0;
  virtual bool Write(HANDLE pipe, HANDLE stopEvent,
                     const std::vector<BYTE> &body, DWORD deadlineMs) = 0;
  virtual unsigned long long MonotonicMilliseconds() = 0;
  virtual bool Cancelled(HANDLE stopEvent) = 0;
  virtual void Close(HANDLE pipe) = 0;
};

bool VerifyRegistrySignedRequest(const std::vector<BYTE> &canonicalEnvelope,
                                 const SignedKeyRegistryFile &registry,
                                 unsigned long long registryTime,
                                 json::SignedEnvelope *decoded = nullptr);
bool VerifyRegistryBrokerReceipt(const std::vector<BYTE> &canonicalEnvelope,
                                 const SignedKeyRegistryFile &registry,
                                 unsigned long long registryTime,
                                 json::BrokerReceiptEnvelope *decoded = nullptr);
bool BrokerReceiptMatches(const json::BrokerReceipt &receipt,
                          const BrokerReceiptBinding &expected,
                          unsigned long long now);
bool GatewayExchangeMutuallyAuthenticatedWithOs(
    const wchar_t *pipeName, const GatewayServerPin &pin, HANDLE stopEvent,
    const GatewayRequestSigner &signRequest,
    const GatewayReplyVerifier &verifyReply,
    std::vector<BYTE> &canonicalSignedReply, GatewayClientOs &os,
    DWORD deadlineMs = kPipeOperationDeadlineMs);
bool GatewayExchangeMutuallyAuthenticated(
    const wchar_t *pipeName, const GatewayServerPin &pin, HANDLE stopEvent,
    const GatewayRequestSigner &signRequest,
    const GatewayReplyVerifier &verifyReply,
    std::vector<BYTE> &canonicalSignedReply,
    DWORD deadlineMs = kPipeOperationDeadlineMs);
} // namespace stellar::service
