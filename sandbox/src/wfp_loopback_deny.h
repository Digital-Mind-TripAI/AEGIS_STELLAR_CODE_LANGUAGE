#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <fwpmu.h>
#include <winsock2.h>
#include <sddl.h>
#include <vector>
namespace stellar::sandbox {
class LoopbackDenyLease final {
public:
  LoopbackDenyLease() { session_.flags = FWPM_SESSION_FLAG_DYNAMIC; }
  LoopbackDenyLease(const LoopbackDenyLease&) = delete;
  LoopbackDenyLease& operator=(const LoopbackDenyLease&) = delete;
  ~LoopbackDenyLease() { Remove(); }
  bool Install(PSID sid) {
    Remove(); lastError_ = ERROR_SUCCESS;
    if (!sid || !IsValidSid(sid)) { lastError_ = ERROR_INVALID_SID; return false; }
    // A local engine must use the default RPC authentication negotiation.  Passing
    // RPC_C_AUTHN_WINNT requests an explicit remote-style auth method; use the
    // local engine's default negotiation for a broker-owned dynamic session.
    lastError_ = FwpmEngineOpen0(nullptr, RPC_C_AUTHN_DEFAULT, nullptr, &session_, &engine_);
    if (lastError_ != ERROR_SUCCESS) return false;
    sid_.assign(static_cast<BYTE*>(sid), static_cast<BYTE*>(sid) + GetLengthSid(sid));
    if (CoCreateGuid(&key_) != S_OK) { lastError_ = ERROR_GEN_FAILURE; Remove(); return false; }
    // ALE_PACKAGE_ID is explicitly typed FWP_SID. Passing the SID bytes as a
    // FWP_BYTE_BLOB makes FwpmFilterAdd0 reject the condition with
    // FWP_E_TYPE_MISMATCH (0x80320027).
    FWP_CONDITION_VALUE0 package{}; package.type = FWP_SID; package.sid = reinterpret_cast<SID*>(sid_.data());
    FWP_CONDITION_VALUE0 remote{}; remote.type = FWP_V4_ADDR_MASK; remote.v4AddrMask = &loopback_;
    FWPM_FILTER_CONDITION0 conditions[2]{};
    conditions[0].fieldKey = FWPM_CONDITION_ALE_PACKAGE_ID; conditions[0].matchType = FWP_MATCH_EQUAL; conditions[0].conditionValue = package;
    conditions[1].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS; conditions[1].matchType = FWP_MATCH_EQUAL; conditions[1].conditionValue = remote;
    filter_.filterKey = key_; filter_.displayData.name = const_cast<wchar_t*>(L"AEGIS Stellar ephemeral AppContainer loopback deny");
    filter_.displayData.description = const_cast<wchar_t*>(L"Fixed zero-capability probe lease; package SID bound");
    filter_.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4; filter_.subLayerKey = FWPM_SUBLAYER_UNIVERSAL;
    filter_.weight.type = FWP_UINT64; filter_.weight.uint64 = &weight_; filter_.numFilterConditions = 2; filter_.filterCondition = conditions;
    filter_.action.type = FWP_ACTION_BLOCK; filter_.flags = FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT;
    lastError_ = FwpmFilterAdd0(engine_, &filter_, nullptr, &filterId_);
    if (lastError_ != ERROR_SUCCESS) { Remove(); return false; }
    installed_ = true; return true;
  }
  void Remove() noexcept { if (engine_ && installed_) FwpmFilterDeleteByKey0(engine_, &key_); installed_ = false; filterId_ = 0; if (engine_) FwpmEngineClose0(engine_); engine_ = nullptr; sid_.clear(); filter_ = {}; }
  bool Installed() const noexcept { return installed_; }
  DWORD LastError() const noexcept { return lastError_; }
private:
  FWPM_SESSION0 session_{}; HANDLE engine_ = nullptr; UINT64 filterId_ = 0; GUID key_{}; FWPM_FILTER0 filter_{};
  // FWP_V4_ADDR_AND_MASK uses the canonical 32-bit network values directly;
  // applying htonl to the mask reverses its contiguous bits and yields
  // FWP_E_INVALID_NET_MASK (0x8032001f).
  FWP_V4_ADDR_AND_MASK loopback_{0x7F000000u, 0xFF000000u}; UINT64 weight_ = UINT64_MAX;
  std::vector<BYTE> sid_; bool installed_ = false; DWORD lastError_ = ERROR_SUCCESS;
};
}
