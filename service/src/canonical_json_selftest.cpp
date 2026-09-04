#include "canonical_json.h"
#include <array>
#include <string>
#include <string_view>
using stellar::service::json::Error;
using stellar::service::json::ParseCanonical;
std::string B64(std::string_view value){static constexpr char alphabet[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";std::string out;unsigned accumulator=0,bits=0;for(unsigned char ch:value){accumulator=(accumulator<<8)|ch;bits+=8;while(bits>=6){bits-=6;out.push_back(alphabet[(accumulator>>bits)&63]);}}if(bits)out.push_back(alphabet[(accumulator<<(6-bits))&63]);return out;}
int main(){
  const std::array<std::pair<std::string_view,Error>,9> invalid={{
    {"{\"a\":1,\"a\":2}",Error::duplicate_key},
    {"{\"b\":1,\"a\":2}",Error::noncanonical_key_order},
    {"{\"a\":1.0}",Error::unsupported_number},
    {"{\"a\":01}",Error::unsupported_number},
    {"{\"a\":-0}",Error::negative_zero},
    {"{\"a\":\"\\/\"}",Error::noncanonical_escape},
    {"{\"a\":1}x",Error::trailing_data},
    {"[[[0]]]",Error::maximumDepth},
    {"{\"a\":1}",Error::maximumBytes}}};
  for(std::size_t i=0;i<invalid.size();++i){const auto&r=invalid[i];const auto result=i==7?ParseCanonical(r.first,32768,2):i==8?ParseCanonical(r.first,4,16):ParseCanonical(r.first);if(result.accepted||result.error!=r.second)return static_cast<int>(10+i);}
  const auto accepted=ParseCanonical("{\"a\":1,\"b\":[false,null,true]}");if(!accepted.accepted)return 30;
  const std::string hash="sha256:"+std::string(64,'a'),fileId(32,'0'),signer(64,'A'),nonce(43,'A');
  const std::string challenge="{\"expiresAt\":150000000,\"issuedAt\":100000000,\"nonce\":\""+nonce+"\",\"pipeId\":\"pipe\",\"protocolVersion\":\"0.1\",\"schema\":\"stellar-pipe-challenge-v0.1\",\"serverCreationTime\":1,\"serverImageFileId\":\""+fileId+"\",\"serverImageHash\":\""+hash+"\",\"serverImageSigner\":\""+signer+"\",\"serverImageVolumeSerial\":1,\"serverInstanceId\":\"instance\",\"serverPid\":1,\"serverServiceName\":\"service\",\"serverServiceSid\":\"S-1-5-18\"}";
  if(!stellar::service::json::ParseCanonicalChallenge(challenge).accepted)return 31;
  const std::string header="{\"alg\":\"ES256\",\"keyId\":\""+hash+"\",\"schema\":\"stellar-pipe-request-protected-v0.1\"}";
  const std::string payload="{\"action\":\"action\",\"challengeHash\":\""+hash+"\",\"clientCreationTime\":\"1\",\"clientImageFileId\":\""+fileId+"\",\"clientImageHash\":\""+hash+"\",\"clientImageSigner\":\""+signer+"\",\"clientImageVolumeSerial\":1,\"clientPid\":1,\"clientServiceSid\":\"S-1-5-18\",\"expiresAt\":2,\"issuedAt\":1,\"keyId\":\""+hash+"\",\"requestHash\":\""+hash+"\",\"requestId\":\"request\",\"schema\":\"stellar-pipe-request-v0.1\"}";
  const std::string envelope="{\"payload\":\""+B64(payload)+"\",\"protected\":\""+B64(header)+"\",\"schema\":\"stellar-pipe-request-envelope-v0.1\",\"signature\":\""+std::string(86,'A')+"\"}";
  if(!stellar::service::json::ParseCanonicalSignedRequest(envelope).accepted)return 32;
  if(stellar::service::json::ParseCanonicalSignedRequest(envelope+" ").accepted)return 33;
  const std::string contractHeader="{\"alg\":\"ES256\",\"kid\":\""+hash+"\",\"typ\":\"stellar-capability-contract+json\",\"version\":1}";
  const std::string contractPayload="{\"bindings\":{\"audience\":{\"installId\":\"install\",\"machineId\":\"machine\",\"service\":\"aegis-stellar-sandbox\"},\"effects\":{\"capabilities\":[],\"imports\":[],\"manifestHash\":\""+hash+"\",\"runnerImportsHash\":\""+hash+"\"},\"policy\":{\"appContainer\":true,\"childProcesses\":\"deny\",\"filesystem\":\"stdio-only\",\"homeostasis\":\"NOT_EVALUATED\",\"inheritedHandles\":[\"stdin\",\"stdout\",\"stderr\"],\"network\":\"deny\"},\"request\":{\"buildLockHash\":\""+hash+"\",\"imageHash\":\""+hash+"\",\"inputHash\":\""+hash+"\",\"packageHash\":\""+hash+"\",\"requestHash\":\""+hash+"\",\"runnerHash\":\""+hash+"\",\"sourceHash\":\""+hash+"\",\"toolchainHash\":\""+hash+"\"},\"resources\":{\"activeProcesses\":1,\"cpuTimeMs\":2000,\"memoryBytes\":134217728,\"outputBytes\":65536,\"wallTimeMs\":5000},\"target\":{\"abi\":\"stellar-win64-v0.1\",\"entrySymbol\":\"stellar_entry\",\"platform\":\"windows-x86_64-msvc\",\"profile\":\"stellar-native-core-v0\"}},\"contractId\":\"contract\",\"executionNonce\":\""+nonce+"\",\"expiresAt\":\"2026-08-17T00:01:00.000Z\",\"issuedAt\":\"2026-08-17T00:00:00.000Z\",\"issuer\":{\"role\":\"service.stellar.contract.issue\",\"subject\":\"custodian\",\"tenantId\":\"aegis-lab\"},\"notBefore\":\"2026-08-17T00:00:00.000Z\",\"schema\":\"stellar.capability-contract/v0.1\"}";
  const std::string contractEnvelope="{\"payload\":\""+B64(contractPayload)+"\",\"protected\":\""+B64(contractHeader)+"\",\"schema\":\"stellar.capability-contract-envelope/v0.1\",\"signature\":\""+std::string(86,'A')+"\"}";
  if(!stellar::service::json::ParseCanonicalCapabilityContract(contractEnvelope).accepted)return 34;
  const auto wrongRole=contractPayload.find("service.stellar.contract.issue");
  std::string invalidContract=contractPayload;invalidContract.replace(wrongRole,30,"AEGIS_STELLAR_STEWARD");
  const std::string invalidContractEnvelope="{\"payload\":\""+B64(invalidContract)+"\",\"protected\":\""+B64(contractHeader)+"\",\"schema\":\"stellar.capability-contract-envelope/v0.1\",\"signature\":\""+std::string(86,'A')+"\"}";
  if(stellar::service::json::ParseCanonicalCapabilityContract(invalidContractEnvelope).accepted)return 35;
  const std::string receiptHeader="{\"alg\":\"ES256\",\"kid\":\""+hash+"\",\"schema\":\"stellar-broker-receipt-protected-v0.1\"}";
  const std::string receiptPayload="{\"action\":\"fixed-probes\",\"brokerImageHash\":\""+hash+"\",\"brokerService\":\"AegisStellarExecutionBroker\",\"cleanupEvidenceHash\":\""+hash+"\",\"contractHash\":\""+hash+"\",\"contractId\":\"contract\",\"evidenceHash\":\""+hash+"\",\"expiresAt\":2,\"hostId\":\"host\",\"issuedAt\":1,\"nonce\":\""+nonce+"\",\"operationId\":\"operation\",\"releaseHash\":\""+hash+"\",\"requestHash\":\""+hash+"\",\"requestId\":\"request\",\"runnerHash\":\""+hash+"\",\"schema\":\"stellar-broker-receipt-v0.1\",\"status\":\"completed\",\"targetService\":\"aegis-stellar-sandbox\"}";
  const std::string receiptEnvelope="{\"payload\":\""+B64(receiptPayload)+"\",\"protected\":\""+B64(receiptHeader)+"\",\"schema\":\"stellar-broker-receipt-envelope-v0.1\",\"signature\":\""+std::string(86,'A')+"\"}";
  if(!stellar::service::json::ParseCanonicalBrokerReceipt(receiptEnvelope).accepted)return 36;
  return 0;
}
