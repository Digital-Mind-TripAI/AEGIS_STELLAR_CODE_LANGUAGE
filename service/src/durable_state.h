#pragma once
#include "canonical_json.h"
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace stellar::service {
using RecordSignatureVerifier = std::function<bool(
    const std::string &kid, const std::string &canonicalUnsigned,
    const std::string &signature)>;
using RecordSignatureSigner = std::function<std::string(
    const std::string &kid, const std::string &canonicalUnsigned)>;
class SignedKeyRegistryFile {
public:
  explicit SignedKeyRegistryFile(std::wstring path) : path_(std::move(path)) {}
  bool RecoverAndLoad(const std::string &rootKid,
                      const RecordSignatureVerifier &verify);
  bool Apply(const std::string &canonicalSignedRecord,
             const RecordSignatureVerifier &verify);
  std::optional<json::KeyRegistryRecord> Resolve(const std::string &kid,
                                                 unsigned long long now) const;
  std::optional<json::KeyRegistryRecord>
  ActiveIssuer(unsigned long long now) const;

private:
  bool LoadCandidate(const std::wstring &path, const std::string &rootKid,
                     const RecordSignatureVerifier &verify,
                     std::vector<json::KeyRegistryRecord> &out) const;
  bool PersistAndReopen(const std::vector<json::KeyRegistryRecord> &records,
                        const std::string &rootKid,
                        const RecordSignatureVerifier &verify);
  std::wstring path_;
  std::string rootKid_;
  std::vector<json::KeyRegistryRecord> records_;
};
enum class OperationState {
  ISSUED,
  RESERVED,
  DISPATCHED,
  RECONCILING,
  CONSUMED,
  REFUSED
};
struct DurableReceipt {
  std::string requestId, requestHash, contractId, contractHash, nonce,
      operationId, releaseHash, action, evidenceHash, cleanupEvidenceHash,
      hostId, targetService, brokerService, brokerImageHash, runnerHash,
      brokerCanonicalReceipt, brokerSignature;
};
struct JournalRecord {
  unsigned long long sequence{};
  OperationState state{};
  std::string requestId, requestHash, contractId, contractHash, nonce,
      operationId, releaseHash, action, evidenceHash, cleanupEvidenceHash,
      hostId, targetService, brokerService, brokerImageHash, runnerHash,
      previousHash, recordHash, brokerCanonicalReceipt, brokerReceiptHash,
      brokerSignature, journalRecordSignature;
};
enum class DriveDisposition {
  DISPATCHED,
  PRIOR_RECEIPT,
  RECONCILE_REQUIRED,
  PERMANENTLY_REFUSED,
  FAILED
};
class DurableReplayJournal {
public:
  explicit DurableReplayJournal(std::wstring path) : path_(std::move(path)) {}
  bool Recover(const RecordSignatureVerifier &verify,
               const std::string &signingKid,
               const RecordSignatureSigner &signer);
  bool Issue(const JournalRecord &record);
  bool Reserve(const std::string &requestId, const std::string &requestHash);
  bool MarkDispatched(const std::string &requestId);
  bool BeginReconciliation(const std::string &requestId);
  bool Consume(const DurableReceipt &receipt,
               const SignedKeyRegistryFile &brokerRegistry,
               unsigned long long now);
  bool Refuse(const std::string &requestId, const std::string &reasonHash);
  DriveDisposition Drive(const std::string &requestId,
                         const std::string &requestHash);
  DriveDisposition DriveAndDispatch(const std::string &requestId,
                                    const std::string &requestHash,
                                    const std::function<bool()> &dispatch);
  std::optional<DurableReceipt> PriorReceipt(const std::string &requestId,
                                             const std::string &requestHash,
                                             bool &bindingConflict) const;
  OperationState State(const std::string &requestId) const;

private:
  bool Transition(const std::function<bool(const std::vector<JournalRecord> &,
                                           JournalRecord &)> &prepare);
  bool LoadBestLocked(std::vector<JournalRecord> &loaded, bool repair);
  bool LoadCandidate(const std::wstring &candidate,
                     std::vector<JournalRecord> &loaded) const;
  bool PersistAndRevalidate(const std::vector<JournalRecord> &next,
                            std::vector<JournalRecord> &reopened);
  std::wstring path_;
  std::vector<JournalRecord> records_;
  RecordSignatureVerifier verify_;
  RecordSignatureSigner signer_;
  std::string signingKid_;
};
} // namespace stellar::service
