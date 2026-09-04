#pragma once
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
namespace stellar::service::json {
enum class Error { none, maximumBytes, maximumDepth, maximumMembers, syntax, duplicate_key, noncanonical_key_order, unsupported_number, negative_zero, noncanonical_escape, non_ascii, trailing_data, schema, field_type, field_value, base64url, signature_size };
struct Result { bool accepted{}; Error error{Error::syntax}; };
struct PipeRequest { std::string action,challengeHash,requestId,requestHash,clientServiceSid,clientCreationTime,clientImageHash,clientImageFileId,clientImageSigner,keyId;std::uint32_t clientPid{},clientImageVolumeSerial{};std::uint64_t issuedAt{},expiresAt{}; };
struct BrokerReceipt { std::string action,brokerImageHash,brokerService,cleanupEvidenceHash,contractHash,contractId,evidenceHash,hostId,nonce,operationId,releaseHash,requestHash,requestId,runnerHash,status,targetService;std::uint64_t issuedAt{},expiresAt{}; };
struct SignedEnvelope { std::string protectedText,payloadText,protectedBase64,payloadBase64,kid;std::vector<unsigned char> signature;PipeRequest request; };
struct BrokerReceiptEnvelope { std::string protectedText,payloadText,protectedBase64,payloadBase64,kid;std::vector<unsigned char> signature;BrokerReceipt receipt; };
struct PipeChallenge { std::string pipeId,serverServiceName,serverServiceSid,serverImageHash,serverImageFileId,serverImageSigner,serverInstanceId,nonce;std::uint32_t serverPid{},serverImageVolumeSerial{};std::uint64_t serverCreationTime{},issuedAt{},expiresAt{}; };
struct KeyRegistryRecord { std::string canonicalSigned,canonicalUnsigned,kind,previousHash,kid,spki,signature;std::uint64_t sequence{},notBefore{},notAfter{},overlapUntil{},revokedAt{}; };
struct ReplayRecord { std::string canonicalSigned,canonicalUnsigned,state,requestId,requestHash,contractId,contractHash,nonce,operationId,releaseHash,action,evidenceHash,cleanupEvidenceHash,hostId,targetService,brokerService,brokerImageHash,runnerHash,previousHash,recordHash,brokerCanonicalReceipt,brokerReceiptHash,brokerSignature,journalRecordSignature;std::uint64_t sequence{}; };
struct CustodianGatewayPin { std::string account,imageFileId,imagePath,imageSha256,serviceName,signerThumbprint;std::uint32_t imageVolumeSerial{}; };
struct CustodianGatewayPolicy { std::string installId,machineId,custodianAccount,cngKeyReference,pipe,policyId,requestSignerKid,requestSignerSpki;std::uint64_t issuedAt{},expiresAt{};CustodianGatewayPin gateway; };
struct CustodianGatewayPolicyEnvelope { std::string protectedBase64,payloadBase64,kid;std::vector<unsigned char> signature;CustodianGatewayPolicy policy; };
// These messages are intentionally only parsed here.  They do not authorize
// CNG use or service dispatch; the Custodian command path remains closed until
// authenticated registry and durable replay integrations are installed.
struct CustodianIssuanceRequest { std::string requestId,signingInput,signingInputHash; };
struct CustodianIssuanceResult { std::string requestId,signingInputHash,keyId,status,refusalCode;std::vector<unsigned char> signature; };
// This local forwarding contract repeats every installed identity binding so
// that the Lab Gateway cannot become a generic signing oracle.
struct LabGatewayBridgeIdentity { std::string account,executablePath,pipe,serviceName; };
struct LabGatewayBridgeRequest { LabGatewayBridgeIdentity bridge;std::string cngKeyReference,installId,machineId,requestId,signingInput,signingInputHash; };
struct LabGatewayBridgeResult { std::string keyId,refusalCode,requestId,signingInputHash,status;std::vector<unsigned char> signature; };
// The installed request-signer registry is one canonical JSON document shared
// by Node and the native Custodian.  It is deliberately not the older JSONL
// rotation-log format: one configured path must have one grammar.
struct RequestSignerRegistryEntry { std::string kid,publicKeySpki; };
struct RequestSignerRegistry { std::string registryId;std::vector<RequestSignerRegistryEntry> signers; };
Result ParseCanonical(std::string_view input,std::size_t maximumBytes=32768,std::size_t maximumDepth=16);
Result ParseCanonicalChallenge(std::string_view input,PipeChallenge*decoded=nullptr);
Result ParseCanonicalSignedRequest(std::string_view input,SignedEnvelope*decoded=nullptr);
Result ParseCanonicalCapabilityContract(std::string_view input,SignedEnvelope*decoded=nullptr);
Result ParseCanonicalBrokerReceipt(std::string_view input,BrokerReceiptEnvelope*decoded=nullptr);
bool DecodeCanonicalBase64Url(std::string_view input,std::vector<unsigned char>&output,std::size_t maximumBytes=32768);
Result ParseCanonicalKeyRegistryRecord(std::string_view input,KeyRegistryRecord&record);
Result ParseCanonicalReplayRecord(std::string_view input,ReplayRecord&record);
Result ParseCanonicalCustodianGatewayPolicy(std::string_view input,CustodianGatewayPolicyEnvelope*decoded=nullptr);
Result ParseCanonicalCustodianIssuanceRequest(std::string_view input,CustodianIssuanceRequest*decoded=nullptr);
Result ParseCanonicalCustodianIssuanceResult(std::string_view input,CustodianIssuanceResult*decoded=nullptr);
Result ParseCanonicalLabGatewayBridgeRequest(std::string_view input,LabGatewayBridgeRequest*decoded=nullptr);
Result ParseCanonicalLabGatewayBridgeResult(std::string_view input,LabGatewayBridgeResult*decoded=nullptr);
Result ParseCanonicalRequestSignerRegistry(std::string_view input,RequestSignerRegistry*decoded=nullptr);
}
