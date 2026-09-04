#include "service_runtime.h"
#include <aclapi.h>
#include <algorithm>
#include <array>
#include <bcrypt.h>
#include <iomanip>
#include <objbase.h>
#include <sddl.h>
#include <softpub.h>
#include <sstream>
#include <strsafe.h>
#include <wincrypt.h>
#include <wintrust.h>
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ole32.lib")

namespace stellar::service {
namespace {
SERVICE_STATUS_HANDLE gStatusHandle{};
SERVICE_STATUS gStatus{};
HANDLE gStop{};
ServiceWorker gWorker{};
const wchar_t *gName{};
DWORD gCheckpoint{};
bool SetState(DWORD state, DWORD error = NO_ERROR, DWORD waitHint = 0) {
  gStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
  gStatus.dwCurrentState = state;
  gStatus.dwControlsAccepted =
      state == SERVICE_RUNNING ? SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN |
                                     SERVICE_ACCEPT_PRESHUTDOWN
                               : 0;
  gStatus.dwWin32ExitCode = error;
  gStatus.dwWaitHint = waitHint;
  gStatus.dwCheckPoint =
      state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING
          ? ++gCheckpoint
          : 0;
  return SetServiceStatus(gStatusHandle, &gStatus) != FALSE;
}
DWORD WINAPI Handler(DWORD control, DWORD, void *, void *) {
  if (control == SERVICE_CONTROL_STOP || control == SERVICE_CONTROL_SHUTDOWN ||
      control == SERVICE_CONTROL_PRESHUTDOWN) {
    DWORD statusError = NO_ERROR;
    if (!SetState(SERVICE_STOP_PENDING, NO_ERROR, kPipeOperationDeadlineMs))
      statusError = GetLastError();
    if (gStop && !SetEvent(gStop) && statusError == NO_ERROR)
      statusError = GetLastError();
    return statusError;
  }
  if (control == SERVICE_CONTROL_INTERROGATE) {
    return SetServiceStatus(gStatusHandle, &gStatus) ? NO_ERROR
                                                     : GetLastError();
  }
  return ERROR_CALL_NOT_IMPLEMENTED;
}
void WINAPI Main(DWORD, wchar_t **) {
  gStatusHandle = RegisterServiceCtrlHandlerExW(gName, Handler, nullptr);
  if (!gStatusHandle)
    return;
  gCheckpoint = 0;
  if (!SetState(SERVICE_START_PENDING, NO_ERROR, 30000))
    return;
  gStop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (!gStop) {
    const DWORD createError = GetLastError();
    if (!SetState(SERVICE_STOPPED, createError))
      OutputDebugStringW(L"Aegis Stellar: SetServiceStatus(STOPPED) failed\n");
    return;
  }
  StartupReadiness readiness;
  const DWORD result =
      gWorker ? gWorker(gStop, readiness) : ERROR_INVALID_FUNCTION;
  const bool stopRequested = ServiceStopRequested(gStop);
  const DWORD terminal =
      result == NO_ERROR && !stopRequested ? ERROR_SERVICE_NOT_ACTIVE : result;
  if (!SetState(SERVICE_STOPPED, terminal))
    OutputDebugStringW(L"Aegis Stellar: SetServiceStatus(STOPPED) failed\n");
  CloseHandle(gStop);
  gStop = nullptr;
}
bool LookupSid(const std::wstring &account, std::vector<BYTE> &sid) {
  DWORD sidBytes = 0, domainBytes = 0;
  SID_NAME_USE use{};
  LookupAccountNameW(nullptr, account.c_str(), nullptr, &sidBytes, nullptr,
                     &domainBytes, &use);
  if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
    return false;
  sid.resize(sidBytes);
  std::vector<wchar_t> domain(domainBytes);
  return LookupAccountNameW(nullptr, account.c_str(), sid.data(), &sidBytes,
                            domain.data(), &domainBytes, &use) != FALSE;
}
std::wstring SidText(PSID sid) {
  LPWSTR text = nullptr;
  if (!ConvertSidToStringSidW(sid, &text))
    return {};
  std::wstring result = text;
  LocalFree(text);
  return result;
}
std::wstring Hex(const BYTE *data, size_t size) {
  std::wostringstream out;
  out << std::hex << std::setfill(L'0');
  for (size_t i = 0; i < size; ++i)
    out << std::setw(2) << static_cast<unsigned>(data[i]);
  return out.str();
}
std::wstring FileIdText(const FILE_ID_128 &id) {
  return Hex(id.Identifier, sizeof(id.Identifier));
}
std::wstring Sha256Handle(HANDLE file) {
  LARGE_INTEGER zero{};
  if (!SetFilePointerEx(file, zero, nullptr, FILE_BEGIN))
    return {};
  BCRYPT_ALG_HANDLE algorithm{};
  BCRYPT_HASH_HANDLE hash{};
  DWORD objectBytes = 0, got = 0;
  if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr,
                                  0) < 0)
    return {};
  if (BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
                        reinterpret_cast<PUCHAR>(&objectBytes),
                        sizeof(objectBytes), &got, 0) < 0) {
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return {};
  }
  std::vector<BYTE> object(objectBytes), digest(32);
  bool ok = BCryptCreateHash(algorithm, &hash, object.data(), objectBytes,
                             nullptr, 0, 0) >= 0;
  BYTE buffer[8192];
  while (ok) {
    DWORD count = 0;
    if (!ReadFile(file, buffer, sizeof(buffer), &count, nullptr)) {
      ok = false;
      break;
    }
    if (!count)
      break;
    ok = BCryptHashData(hash, buffer, count, 0) >= 0;
  }
  if (ok)
    ok = BCryptFinishHash(hash, digest.data(),
                          static_cast<ULONG>(digest.size()), 0) >= 0;
  if (hash)
    BCryptDestroyHash(hash);
  BCryptCloseAlgorithmProvider(algorithm, 0);
  SetFilePointerEx(file, zero, nullptr, FILE_BEGIN);
  return ok ? L"sha256:" + Hex(digest.data(), digest.size()) : std::wstring{};
}
bool AuthenticodeSigner(const std::wstring &path, std::wstring &thumbprint) {
  WINTRUST_FILE_INFO file{sizeof(file)};
  file.pcwszFilePath = path.c_str();
  WINTRUST_DATA trust{sizeof(trust)};
  trust.dwUIChoice = WTD_UI_NONE;
  trust.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
  // D2 is deliberately offline: use only cached revocation evidence and fail
  // closed when the chain cannot be established from that cache.
  trust.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
  trust.dwUnionChoice = WTD_CHOICE_FILE;
  trust.pFile = &file;
  trust.dwStateAction = WTD_STATEACTION_VERIFY;
  GUID policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;
  const LONG verified = WinVerifyTrust(nullptr, &policy, &trust);
  trust.dwStateAction = WTD_STATEACTION_CLOSE;
  WinVerifyTrust(nullptr, &policy, &trust);
  if (verified != ERROR_SUCCESS)
    return false;
  HCERTSTORE store{};
  HCRYPTMSG message{};
  DWORD encoding = 0, content = 0, format = 0;
  if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, path.c_str(),
                        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                        CERT_QUERY_FORMAT_FLAG_BINARY, 0, &encoding, &content,
                        &format, &store, &message, nullptr))
    return false;
  DWORD bytes = 0;
  bool ok = CryptMsgGetParam(message, CMSG_SIGNER_INFO_PARAM, 0, nullptr,
                             &bytes) != FALSE;
  std::vector<BYTE> signer(bytes);
  if (ok)
    ok = CryptMsgGetParam(message, CMSG_SIGNER_INFO_PARAM, 0, signer.data(),
                          &bytes) != FALSE;
  PCCERT_CONTEXT certificate = nullptr;
  if (ok) {
    const auto *info = reinterpret_cast<CMSG_SIGNER_INFO *>(signer.data());
    CERT_INFO find{};
    find.Issuer = info->Issuer;
    find.SerialNumber = info->SerialNumber;
    certificate = CertFindCertificateInStore(
        store, encoding, 0, CERT_FIND_SUBJECT_CERT, &find, nullptr);
    ok = certificate != nullptr;
  }
  BYTE digest[64]{};
  DWORD digestBytes = sizeof(digest);
  if (ok)
    ok =
        CertGetCertificateContextProperty(certificate, CERT_SHA256_HASH_PROP_ID,
                                          digest, &digestBytes) != FALSE;
  if (ok)
    thumbprint = Hex(digest, digestBytes);
  if (certificate)
    CertFreeCertificateContext(certificate);
  if (message)
    CryptMsgClose(message);
  if (store)
    CertCloseStore(store, 0);
  return ok;
}
bool QueryConfig2(SC_HANDLE service, DWORD level, std::vector<BYTE> &data) {
  DWORD bytes = 0;
  QueryServiceConfig2W(service, level, nullptr, 0, &bytes);
  if (!bytes || GetLastError() != ERROR_INSUFFICIENT_BUFFER)
    return false;
  data.resize(bytes);
  return QueryServiceConfig2W(service, level, data.data(), bytes, &bytes) !=
         FALSE;
}
bool RequiredPrivilegesAreExact(const wchar_t *multiSz) {
  if (!multiSz)
    return false;
  std::vector<std::wstring> actual;
  for (const wchar_t *item = multiSz; *item; item += wcslen(item) + 1)
    actual.emplace_back(item);
  std::sort(actual.begin(), actual.end());
  const std::vector<std::wstring> expected = {L"SeChangeNotifyPrivilege",
                                              L"SeImpersonatePrivilege"};
  return actual == expected;
}
bool ExactScmIdentity(const PipePeerPolicy &policy, const PipePeer &peer) {
  SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
  if (!manager)
    return false;
  SC_HANDLE service = OpenServiceW(manager, policy.serviceName.c_str(),
                                   SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);
  if (!service) {
    CloseServiceHandle(manager);
    return false;
  }
  SERVICE_STATUS_PROCESS status{};
  DWORD bytes = 0;
  bool ok = QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
                                 reinterpret_cast<BYTE *>(&status),
                                 sizeof(status), &bytes) != FALSE &&
            status.dwProcessId == peer.pid &&
            status.dwCurrentState == SERVICE_RUNNING;
  QueryServiceConfigW(service, nullptr, 0, &bytes);
  std::vector<BYTE> config(bytes);
  auto *value = reinterpret_cast<QUERY_SERVICE_CONFIGW *>(config.data());
  if (ok)
    ok = bytes && QueryServiceConfigW(service, value, bytes, &bytes) != FALSE;
  if (ok)
    ok = value->dwServiceType == SERVICE_WIN32_OWN_PROCESS &&
         _wcsicmp(value->lpServiceStartName, policy.account.c_str()) == 0;
  if (ok) {
    const std::wstring exactBinary = L"\"" + peer.imagePath + L"\"";
    ok = value->lpBinaryPathName &&
         _wcsicmp(value->lpBinaryPathName, exactBinary.c_str()) == 0;
  }
  std::vector<BYTE> sidInfo, privilegeInfo, failureInfo, failureFlagInfo;
  if (ok)
    ok = QueryConfig2(service, SERVICE_CONFIG_SERVICE_SID_INFO, sidInfo) &&
         reinterpret_cast<SERVICE_SID_INFO *>(sidInfo.data())
                 ->dwServiceSidType == SERVICE_SID_TYPE_UNRESTRICTED;
  if (ok)
    ok = QueryConfig2(service, SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO,
                      privilegeInfo) &&
         RequiredPrivilegesAreExact(
             reinterpret_cast<SERVICE_REQUIRED_PRIVILEGES_INFOW *>(
                 privilegeInfo.data())
                 ->pmszRequiredPrivileges);
  if (ok) {
    ok = QueryConfig2(service, SERVICE_CONFIG_FAILURE_ACTIONS, failureInfo);
    if (ok) {
      const auto *actions =
          reinterpret_cast<SERVICE_FAILURE_ACTIONSW *>(failureInfo.data());
      ok = actions->dwResetPeriod == 86400 && actions->cActions == 3 &&
           actions->lpsaActions &&
           actions->lpsaActions[0].Type == SC_ACTION_RESTART &&
           actions->lpsaActions[0].Delay == 5000 &&
           actions->lpsaActions[1].Type == SC_ACTION_RESTART &&
           actions->lpsaActions[1].Delay == 15000 &&
           actions->lpsaActions[2].Type == SC_ACTION_NONE &&
           actions->lpsaActions[2].Delay == 0;
    }
  }
  if (ok)
    ok =
        QueryConfig2(service, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,
                     failureFlagInfo) &&
        reinterpret_cast<SERVICE_FAILURE_ACTIONS_FLAG *>(failureFlagInfo.data())
                ->fFailureActionsOnNonCrashFailures == TRUE;
  CloseServiceHandle(service);
  CloseServiceHandle(manager);
  return ok;
}
DWORD Remaining(DWORD started, DWORD deadlineMs) {
  const DWORD elapsed = GetTickCount() - started;
  return elapsed >= deadlineMs ? 0 : deadlineMs - elapsed;
}
bool AwaitOverlapped(HANDLE pipe, HANDLE stopEvent, OVERLAPPED &overlapped,
                     DWORD started, DWORD deadlineMs, DWORD &bytes) {
  HANDLE waits[2] = {stopEvent, overlapped.hEvent};
  const DWORD result =
      WaitForMultipleObjects(2, waits, FALSE, Remaining(started, deadlineMs));
  if (result == WAIT_OBJECT_0 + 1)
    return GetOverlappedResult(pipe, &overlapped, &bytes, FALSE) != FALSE;
  CancelPipeIoAndDrain(pipe, overlapped);
  SetLastError(result == WAIT_OBJECT_0 ? ERROR_OPERATION_ABORTED
                                       : ERROR_TIMEOUT);
  return false;
}
bool OverlappedReadOne(HANDLE pipe, HANDLE stopEvent, BYTE *data,
                       DWORD capacity, DWORD &bytes, DWORD deadlineMs) {
  OVERLAPPED overlapped{};
  overlapped.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (!overlapped.hEvent)
    return false;
  const DWORD started = GetTickCount();
  BOOL completed = ReadFile(pipe, data, capacity, &bytes, &overlapped);
  if (!completed && GetLastError() == ERROR_IO_PENDING)
    completed = AwaitOverlapped(pipe, stopEvent, overlapped, started,
                                deadlineMs, bytes);
  const DWORD error = completed ? ERROR_SUCCESS : GetLastError();
  CloseHandle(overlapped.hEvent);
  SetLastError(error);
  return completed != FALSE;
}
bool OverlappedWriteOne(HANDLE pipe, HANDLE stopEvent, const BYTE *data,
                        DWORD size, DWORD &bytes, DWORD deadlineMs) {
  OVERLAPPED overlapped{};
  overlapped.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (!overlapped.hEvent)
    return false;
  const DWORD started = GetTickCount();
  BOOL completed = WriteFile(pipe, data, size, &bytes, &overlapped);
  if (!completed && GetLastError() == ERROR_IO_PENDING)
    completed = AwaitOverlapped(pipe, stopEvent, overlapped, started,
                                deadlineMs, bytes);
  const DWORD error = completed ? ERROR_SUCCESS : GetLastError();
  CloseHandle(overlapped.hEvent);
  SetLastError(error);
  return completed != FALSE;
}
std::string Base64Url(const BYTE *data, DWORD bytes) {
  DWORD chars = 0;
  if (!CryptBinaryToStringA(data, bytes,
                            CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr,
                            &chars))
    return {};
  std::string result(chars, '\0');
  if (!CryptBinaryToStringA(data, bytes,
                            CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
                            result.data(), &chars))
    return {};
  result.resize(chars);
  while (!result.empty() && (result.back() == '=' || result.back() == '\0'))
    result.pop_back();
  for (char &ch : result) {
    if (ch == '+')
      ch = '-';
    else if (ch == '/')
      ch = '_';
  }
  return result;
}
std::string WideUtf8(const std::wstring &value) {
  if (value.empty())
    return {};
  const int bytes = WideCharToMultiByte(
      CP_UTF8, WC_ERR_INVALID_CHARS, value.c_str(),
      static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
  if (bytes <= 0)
    return {};
  std::string result(static_cast<size_t>(bytes), '\0');
  return WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.c_str(),
                             static_cast<int>(value.size()), result.data(),
                             bytes, nullptr, nullptr) == bytes
             ? result
             : std::string{};
}
unsigned long long FileTimeNow() {
  FILETIME value{};
  GetSystemTimePreciseAsFileTime(&value);
  ULARGE_INTEGER result{};
  result.LowPart = value.dwLowDateTime;
  result.HighPart = value.dwHighDateTime;
  return result.QuadPart;
}
std::string JsonEscape(const std::string &value) {
  std::string out;
  for (const char ch : value) {
    if (ch == '\\' || ch == '"')
      out.push_back('\\');
    out.push_back(ch);
  }
  return out;
}
std::string HashBytes(const std::vector<BYTE> &value) {
  BCRYPT_ALG_HANDLE algorithm{};
  BCRYPT_HASH_HANDLE hash{};
  DWORD objectBytes = 0, got = 0;
  std::array<BYTE, 32> digest{};
  if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr,
                                  0) < 0)
    return {};
  if (BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
                        reinterpret_cast<PUCHAR>(&objectBytes),
                        sizeof(objectBytes), &got, 0) < 0) {
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return {};
  }
  std::vector<BYTE> object(objectBytes);
  bool ok = BCryptCreateHash(algorithm, &hash, object.data(), objectBytes,
                             nullptr, 0, 0) >= 0 &&
            BCryptHashData(hash, const_cast<PUCHAR>(value.data()),
                           static_cast<ULONG>(value.size()), 0) >= 0 &&
            BCryptFinishHash(hash, digest.data(),
                             static_cast<ULONG>(digest.size()), 0) >= 0;
  if (hash)
    BCryptDestroyHash(hash);
  BCryptCloseAlgorithmProvider(algorithm, 0);
  if (!ok)
    return {};
  return "sha256:" + WideUtf8(Hex(digest.data(), digest.size()));
}
} // namespace

bool StartupReadiness::Checkpoint(const wchar_t *gateName, bool gatePassed) {
  if (!gatePassed) {
    SetState(SERVICE_STOPPED, ERROR_INVALID_STATE);
    return false;
  }
  if (!gateName || !sequence_.Checkpoint(gateName, true)) {
    SetState(SERVICE_STOPPED, ERROR_INVALID_STATE);
    return false;
  }
  if (ServiceStopRequested(gStop))
    return false;
  return SetState(SERVICE_START_PENDING, NO_ERROR, 30000);
}
bool StartupReadiness::Running() {
  if (!sequence_.Ready() || ServiceStopRequested(gStop))
    return false;
  return SetState(SERVICE_RUNNING);
}
int RunWindowsService(const wchar_t *serviceName, ServiceWorker worker) {
  gName = serviceName;
  gWorker = worker;
  SERVICE_TABLE_ENTRYW table[] = {{const_cast<LPWSTR>(serviceName), Main},
                                  {nullptr, nullptr}};
  return StartServiceCtrlDispatcherW(table) ? 0
                                            : static_cast<int>(GetLastError());
}
bool ServiceStopRequested(HANDLE stopEvent) {
  return stopEvent && WaitForSingleObject(stopEvent, 0) == WAIT_OBJECT_0;
}
PipePeer::~PipePeer() {
  if (imageHandle != INVALID_HANDLE_VALUE)
    CloseHandle(imageHandle);
  if (processHandle != INVALID_HANDLE_VALUE && processHandle)
    CloseHandle(processHandle);
}
HANDLE CreateAuthenticatedPipe(const wchar_t *pipeName,
                               const wchar_t *ownerService,
                               const wchar_t *gatewayService,
                               DWORD messageBytes) {
  if (!pipeName || !ownerService || !gatewayService ||
      messageBytes != kMaximumFrameBytes)
    return INVALID_HANDLE_VALUE;
  std::vector<BYTE> ownerSid, gatewaySid;
  if (!LookupSid(ownerService, ownerSid) ||
      !LookupSid(gatewayService, gatewaySid))
    return INVALID_HANDLE_VALUE;
  const std::wstring ownerText = SidText(ownerSid.data());
  const std::wstring gatewayText = SidText(gatewaySid.data());
  // SYSTEM and the owning service administer the endpoint. Only Gateway has
  // the precise client read/write/synchronize rights used for application IPC.
  std::wstring sddl = L"O:" + ownerText + L"D:P(A;;GA;;;SY)(A;;GA;;;" +
                      ownerText + L")(A;;0x0012008b;;;" + gatewayText + L")";
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
          sddl.c_str(), SDDL_REVISION_1, &descriptor, nullptr))
    return INVALID_HANDLE_VALUE;
  SECURITY_ATTRIBUTES security{sizeof(security), descriptor, FALSE};
  HANDLE pipe = CreateNamedPipeW(
      pipeName,
      PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
      PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT |
          PIPE_REJECT_REMOTE_CLIENTS,
      kMaximumConcurrentConnections, messageBytes + sizeof(DWORD),
      messageBytes + sizeof(DWORD), kPipeOperationDeadlineMs, &security);
  LocalFree(descriptor);
  if (pipe == INVALID_HANDLE_VALUE)
    return pipe;
  PSECURITY_DESCRIPTOR liveDescriptor = nullptr;
  PSID liveOwner = nullptr;
  PACL liveDacl = nullptr;
  const DWORD securityError =
      GetSecurityInfo(pipe, SE_KERNEL_OBJECT,
                      OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                      &liveOwner, nullptr, &liveDacl, nullptr, &liveDescriptor);
  bool exact = securityError == ERROR_SUCCESS && liveOwner && liveDacl &&
               EqualSid(liveOwner, ownerSid.data()) != FALSE &&
               liveDacl->AceCount == 3;
  bool sawSystem = false, sawOwner = false, sawGateway = false;
  BYTE systemSid[SECURITY_MAX_SID_SIZE]{};
  DWORD systemSidBytes = sizeof(systemSid);
  if (exact)
    exact = CreateWellKnownSid(WinLocalSystemSid, nullptr, systemSid,
                               &systemSidBytes) != FALSE;
  for (DWORD index = 0; exact && index < liveDacl->AceCount; ++index) {
    void *rawAce = nullptr;
    exact = GetAce(liveDacl, index, &rawAce) != FALSE;
    if (!exact)
      break;
    const auto *ace = static_cast<ACCESS_ALLOWED_ACE *>(rawAce);
    exact = ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE &&
            ace->Header.AceFlags == 0;
    PSID aceSid = const_cast<DWORD *>(&ace->SidStart);
    if (EqualSid(aceSid, systemSid)) {
      exact = ace->Mask == GENERIC_ALL && !sawSystem;
      sawSystem = true;
    } else if (EqualSid(aceSid, ownerSid.data())) {
      exact = ace->Mask == GENERIC_ALL && !sawOwner;
      sawOwner = true;
    } else if (EqualSid(aceSid, gatewaySid.data())) {
      // Gateway opens with GENERIC_READ | FILE_WRITE_DATA. Deliberately omit
      // FILE_GENERIC_WRITE because its pipe mapping includes the server-only
      // FILE_CREATE_PIPE_INSTANCE bit.
      exact = ace->Mask == kGatewayPipeClientAclMask && !sawGateway;
      sawGateway = true;
    } else {
      exact = false;
    }
  }
  if (liveDescriptor)
    LocalFree(liveDescriptor);
  exact = exact && sawSystem && sawOwner && sawGateway;
  if (!exact) {
    CloseHandle(pipe);
    SetLastError(ERROR_INVALID_SECURITY_DESCR);
    return INVALID_HANDLE_VALUE;
  }
  return pipe;
}
void CancelPipeIoAndDrain(HANDLE pipe, OVERLAPPED &overlapped) {
  CancelIoEx(pipe, &overlapped);
  DWORD ignored = 0;
  GetOverlappedResult(pipe, &overlapped, &ignored, TRUE);
}
bool ConnectAuthenticatedPipe(HANDLE pipe, HANDLE stopEvent, DWORD deadlineMs) {
  OVERLAPPED overlapped{};
  overlapped.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (!overlapped.hEvent)
    return false;
  DWORD ignored = 0;
  const DWORD started = GetTickCount();
  BOOL connected = ConnectNamedPipe(pipe, &overlapped);
  if (!connected) {
    const DWORD error = GetLastError();
    if (error == ERROR_PIPE_CONNECTED) {
      SetEvent(overlapped.hEvent);
      connected = TRUE;
    } else if (error == ERROR_IO_PENDING)
      connected = AwaitOverlapped(pipe, stopEvent, overlapped, started,
                                  deadlineMs, ignored);
  }
  const DWORD error = connected ? ERROR_SUCCESS : GetLastError();
  CloseHandle(overlapped.hEvent);
  SetLastError(error);
  return connected != FALSE;
}
bool AuthenticatePipeClient(HANDLE pipe, const PipePeerPolicy &policy,
                            PipePeer &peer) {
  if (!GetNamedPipeClientProcessId(pipe, &peer.pid) || !peer.pid)
    return false;
  if (!ImpersonateNamedPipeClient(pipe))
    return false;
  HANDLE token = nullptr;
  bool sidMatches = false;
  if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &token)) {
    DWORD bytes = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &bytes);
    std::vector<BYTE> data(bytes);
    if (bytes &&
        GetTokenInformation(token, TokenUser, data.data(), bytes, &bytes)) {
      const auto user = reinterpret_cast<TOKEN_USER *>(data.data());
      peer.sid = SidText(user->User.Sid);
      std::vector<BYTE> expected;
      sidMatches = LookupSid(policy.account, expected) &&
                   EqualSid(user->User.Sid, expected.data()) != FALSE;
    }
    CloseHandle(token);
  }
  const BOOL reverted = RevertToSelf();
  if (!sidMatches || !reverted)
    return false;
  peer.processHandle = OpenProcess(
      PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, peer.pid);
  if (peer.processHandle == INVALID_HANDLE_VALUE || !peer.processHandle)
    return false;
  FILETIME exitTime{}, kernel{}, user{};
  if (!GetProcessTimes(peer.processHandle, &peer.creationTime, &exitTime,
                       &kernel, &user))
    return false;
  DWORD chars = 32768;
  std::vector<wchar_t> path(chars);
  if (!QueryFullProcessImageNameW(peer.processHandle, 0, path.data(), &chars))
    return false;
  peer.imagePath.assign(path.data(), chars);
  if (_wcsicmp(peer.imagePath.c_str(), policy.imagePath.c_str()) != 0)
    return false;
  peer.imageHandle =
      CreateFileW(peer.imagePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                  nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (peer.imageHandle == INVALID_HANDLE_VALUE)
    return false;
  FILE_ID_INFO id{};
  BY_HANDLE_FILE_INFORMATION legacy{};
  if (!GetFileInformationByHandleEx(peer.imageHandle, FileIdInfo, &id,
                                    sizeof(id)) ||
      !GetFileInformationByHandle(peer.imageHandle, &legacy))
    return false;
  peer.imageFileId = id.FileId;
  peer.imageVolumeSerial = legacy.dwVolumeSerialNumber;
  peer.imageSha256 = Sha256Handle(peer.imageHandle);
  if (peer.imageSha256.empty() ||
      _wcsicmp(peer.imageSha256.c_str(), policy.imageSha256.c_str()) != 0 ||
      _wcsicmp(FileIdText(peer.imageFileId).c_str(),
               policy.imageFileId.c_str()) != 0 ||
      peer.imageVolumeSerial != policy.imageVolumeSerial)
    return false;
  if (!AuthenticodeSigner(peer.imagePath, peer.signerThumbprint) ||
      _wcsicmp(peer.signerThumbprint.c_str(),
               policy.signerThumbprint.c_str()) != 0)
    return false;
  // WinTrust was asked to verify the path while this no-write/no-delete-share
  // handle was held. Re-read identity and refuse any trust-target substitution.
  FILE_ID_INFO trustedId{};
  BY_HANDLE_FILE_INFORMATION trustedLegacy{};
  if (!GetFileInformationByHandleEx(peer.imageHandle, FileIdInfo, &trustedId,
                                    sizeof(trustedId)) ||
      !GetFileInformationByHandle(peer.imageHandle, &trustedLegacy) ||
      memcmp(&trustedId.FileId, &peer.imageFileId, sizeof(peer.imageFileId)) !=
          0 ||
      trustedLegacy.dwVolumeSerialNumber != peer.imageVolumeSerial)
    return false;
  peer.scmServiceName = policy.serviceName;
  return ExactScmIdentity(policy, peer);
}
bool AuthenticatePinnedProcess(DWORD pid, const PipePeerPolicy &policy,
                               PipePeer &peer) {
  if (!pid)
    return false;
  peer.pid = pid;
  peer.processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
                                   FALSE, pid);
  if (!peer.processHandle)
    return false;
  HANDLE token{};
  if (!OpenProcessToken(peer.processHandle, TOKEN_QUERY, &token))
    return false;
  DWORD tokenBytes = 0;
  GetTokenInformation(token, TokenUser, nullptr, 0, &tokenBytes);
  std::vector<BYTE> tokenData(tokenBytes), expectedSid;
  bool ok = tokenBytes && GetTokenInformation(token, TokenUser, tokenData.data(),
                                               tokenBytes, &tokenBytes) &&
            LookupSid(policy.account, expectedSid);
  if (ok) {
    const auto *user = reinterpret_cast<TOKEN_USER *>(tokenData.data());
    ok = EqualSid(user->User.Sid, expectedSid.data()) != FALSE;
    if (ok)
      peer.sid = SidText(user->User.Sid);
  }
  CloseHandle(token);
  FILETIME exitTime{}, kernel{}, userTime{};
  if (!ok || !GetProcessTimes(peer.processHandle, &peer.creationTime, &exitTime,
                              &kernel, &userTime))
    return false;
  DWORD chars = 32768;
  std::vector<wchar_t> path(chars);
  if (!QueryFullProcessImageNameW(peer.processHandle, 0, path.data(), &chars))
    return false;
  peer.imagePath.assign(path.data(), chars);
  if (_wcsicmp(peer.imagePath.c_str(), policy.imagePath.c_str()) != 0)
    return false;
  peer.imageHandle = CreateFileW(peer.imagePath.c_str(), GENERIC_READ,
                                 FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                 FILE_ATTRIBUTE_NORMAL, nullptr);
  if (peer.imageHandle == INVALID_HANDLE_VALUE)
    return false;
  FILE_ID_INFO id{};
  BY_HANDLE_FILE_INFORMATION legacy{};
  if (!GetFileInformationByHandleEx(peer.imageHandle, FileIdInfo, &id,
                                    sizeof(id)) ||
      !GetFileInformationByHandle(peer.imageHandle, &legacy))
    return false;
  peer.imageFileId = id.FileId;
  peer.imageVolumeSerial = legacy.dwVolumeSerialNumber;
  peer.imageSha256 = Sha256Handle(peer.imageHandle);
  if (_wcsicmp(peer.imageSha256.c_str(), policy.imageSha256.c_str()) != 0 ||
      _wcsicmp(FileIdText(id.FileId).c_str(), policy.imageFileId.c_str()) != 0 ||
      peer.imageVolumeSerial != policy.imageVolumeSerial ||
      !AuthenticodeSigner(peer.imagePath, peer.signerThumbprint) ||
      _wcsicmp(peer.signerThumbprint.c_str(), policy.signerThumbprint.c_str()) != 0)
    return false;
  FILE_ID_INFO after{};
  BY_HANDLE_FILE_INFORMATION afterLegacy{};
  if (!GetFileInformationByHandleEx(peer.imageHandle, FileIdInfo, &after,
                                    sizeof(after)) ||
      !GetFileInformationByHandle(peer.imageHandle, &afterLegacy) ||
      memcmp(&after.FileId, &peer.imageFileId, sizeof(after.FileId)) != 0 ||
      afterLegacy.dwVolumeSerialNumber != peer.imageVolumeSerial)
    return false;
  peer.scmServiceName = policy.serviceName;
  return ExactScmIdentity(policy, peer);
}
bool ReadBoundedFrame(HANDLE pipe, HANDLE stopEvent, std::vector<BYTE> &body,
                      bool &oneRequestPerConnection, DWORD deadlineMs,
                      DWORD maxBytes) {
  if (oneRequestPerConnection || maxBytes != kMaximumFrameBytes)
    return false;
  std::vector<BYTE> frame(static_cast<size_t>(maxBytes) + sizeof(DWORD) + 1);
  DWORD frameBytes = 0;
  if (!OverlappedReadOne(pipe, stopEvent, frame.data(),
                         static_cast<DWORD>(frame.size()), frameBytes,
                         deadlineMs)) {
    if (GetLastError() == ERROR_MORE_DATA)
      return false;
    return false;
  }
  if (frameBytes <= sizeof(DWORD))
    return false;
  DWORD declaredBytes = 0;
  memcpy(&declaredBytes, frame.data(), sizeof(declaredBytes));
  if (!declaredBytes || declaredBytes > maxBytes ||
      frameBytes != sizeof(DWORD) + declaredBytes)
    return false;
  body.assign(frame.begin() + sizeof(DWORD), frame.begin() + frameBytes);
  oneRequestPerConnection = true;
  return true;
}
bool WriteBoundedFrame(HANDLE pipe, HANDLE stopEvent,
                       const std::vector<BYTE> &body, DWORD deadlineMs,
                       DWORD maxBytes) {
  if (body.empty() || body.size() > maxBytes || maxBytes != kMaximumFrameBytes)
    return false;
  const DWORD declaredBytes = static_cast<DWORD>(body.size());
  std::vector<BYTE> frame(sizeof(DWORD) + body.size());
  memcpy(frame.data(), &declaredBytes, sizeof(declaredBytes));
  memcpy(frame.data() + sizeof(DWORD), body.data(), body.size());
  DWORD written = 0;
  return OverlappedWriteOne(pipe, stopEvent, frame.data(),
                            static_cast<DWORD>(frame.size()), written,
                            deadlineMs) &&
         written == frame.size();
}
bool VerifyEs256WithCng(BCRYPT_KEY_HANDLE publicKey,
                        const std::vector<BYTE> &signedBytes,
                        const std::vector<BYTE> &p1363Signature) {
  if (!publicKey || signedBytes.empty() || p1363Signature.size() != 64)
    return false;
  BCRYPT_ALG_HANDLE algorithm{};
  BCRYPT_HASH_HANDLE hash{};
  DWORD objectBytes = 0, got = 0;
  std::array<BYTE, 32> digest{};
  if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr,
                                  0) < 0)
    return false;
  bool ok = BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
                              reinterpret_cast<PUCHAR>(&objectBytes),
                              sizeof(objectBytes), &got, 0) >= 0;
  std::vector<BYTE> object(objectBytes);
  if (ok)
    ok = BCryptCreateHash(algorithm, &hash, object.data(), objectBytes, nullptr,
                          0, 0) >= 0;
  if (ok)
    ok = BCryptHashData(hash, const_cast<PUCHAR>(signedBytes.data()),
                        static_cast<ULONG>(signedBytes.size()), 0) >= 0;
  if (ok)
    ok = BCryptFinishHash(hash, digest.data(),
                          static_cast<ULONG>(digest.size()), 0) >= 0;
  if (ok)
    ok = BCryptVerifySignature(publicKey, nullptr, digest.data(),
                               static_cast<ULONG>(digest.size()),
                               const_cast<PUCHAR>(p1363Signature.data()),
                               static_cast<ULONG>(p1363Signature.size()),
                               0) >= 0;
  if (hash)
    BCryptDestroyHash(hash);
  BCryptCloseAlgorithmProvider(algorithm, 0);
  return ok;
}
bool PerformAuthenticatedHandshake(HANDLE pipe, HANDLE stopEvent,
                                   const wchar_t *pipeId,
                                   const wchar_t *serverServiceName,
                                   const PipePeerPolicy &clientPolicy,
                                   SignedRequestVerifier &verifier,
                                   const char *expectedAction, PipePeer &peer,
                                   std::vector<BYTE> &canonicalRequest,
                                   HandshakeState &state, DWORD deadlineMs) {
  state = HandshakeState::connected;
  const ULONGLONG handshakeStarted = GetTickCount64();
  const auto remaining = [&]() -> DWORD {
    const ULONGLONG elapsed = GetTickCount64() - handshakeStarted;
    return elapsed >= deadlineMs ? 0 : deadlineMs - static_cast<DWORD>(elapsed);
  };
  const auto refuse = [&]() {
    state = ServiceStopRequested(stopEvent) ? HandshakeState::stopped
                                            : HandshakeState::refused;
    return false;
  };
  if (!pipeId || !serverServiceName || !expectedAction || !*expectedAction)
    return refuse();
  std::array<BYTE, 32> nonce{};
  if (BCryptGenRandom(nullptr, nonce.data(), static_cast<ULONG>(nonce.size()),
                      BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0)
    return refuse();
  std::vector<BYTE> serverSid;
  std::wstring serverAccount =
      L"NT SERVICE\\" + std::wstring(serverServiceName);
  if (!LookupSid(serverAccount, serverSid))
    return refuse();
  HANDLE currentProcess = GetCurrentProcess();
  FILETIME serverCreation{}, exitTime{}, kernelTime{}, userTime{};
  DWORD serverPathChars = 32768;
  std::vector<wchar_t> serverPath(serverPathChars);
  if (!GetProcessTimes(currentProcess, &serverCreation, &exitTime, &kernelTime,
                       &userTime) ||
      !QueryFullProcessImageNameW(currentProcess, 0, serverPath.data(),
                                  &serverPathChars))
    return refuse();
  std::wstring serverImagePath(serverPath.data(), serverPathChars);
  HANDLE serverImage =
      CreateFileW(serverImagePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                  nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (serverImage == INVALID_HANDLE_VALUE)
    return refuse();
  FILE_ID_INFO serverFileId{};
  BY_HANDLE_FILE_INFORMATION serverLegacy{};
  std::wstring serverSigner;
  const std::wstring serverHash = Sha256Handle(serverImage);
  bool serverIdentityOk =
      !serverHash.empty() &&
      GetFileInformationByHandleEx(serverImage, FileIdInfo, &serverFileId,
                                   sizeof(serverFileId)) &&
      GetFileInformationByHandle(serverImage, &serverLegacy) &&
      AuthenticodeSigner(serverImagePath, serverSigner);
  FILE_ID_INFO trustedServerId{};
  BY_HANDLE_FILE_INFORMATION trustedServerLegacy{};
  serverIdentityOk =
      serverIdentityOk &&
      GetFileInformationByHandleEx(serverImage, FileIdInfo, &trustedServerId,
                                   sizeof(trustedServerId)) &&
      GetFileInformationByHandle(serverImage, &trustedServerLegacy) &&
      memcmp(&trustedServerId.FileId, &serverFileId.FileId,
             sizeof(serverFileId.FileId)) == 0 &&
      trustedServerLegacy.dwVolumeSerialNumber ==
          serverLegacy.dwVolumeSerialNumber;
  CloseHandle(serverImage);
  if (!serverIdentityOk)
    return refuse();
  const unsigned long long issuedAt = FileTimeNow(),
                           expiresAt = issuedAt + 5000ULL * 10000ULL;
  ULARGE_INTEGER serverCreationValue{};
  serverCreationValue.LowPart = serverCreation.dwLowDateTime;
  serverCreationValue.HighPart = serverCreation.dwHighDateTime;
  GUID instance{};
  if (CoCreateGuid(&instance) != S_OK)
    return refuse();
  wchar_t instanceText[64]{};
  if (!StringFromGUID2(instance, instanceText, 64))
    return refuse();
  std::ostringstream challenge;
  challenge << "{\"expiresAt\":" << expiresAt << ",\"issuedAt\":" << issuedAt
            << ",\"nonce\":\""
            << Base64Url(nonce.data(), static_cast<DWORD>(nonce.size()))
            << "\",\"pipeId\":\"" << JsonEscape(WideUtf8(pipeId))
            << "\",\"protocolVersion\":\"0.1\",\"schema\":\"stellar-pipe-"
               "challenge-v0.1\",\"serverCreationTime\":"
            << serverCreationValue.QuadPart << ",\"serverImageFileId\":\""
            << JsonEscape(WideUtf8(FileIdText(serverFileId.FileId)))
            << "\",\"serverImageHash\":\"" << JsonEscape(WideUtf8(serverHash))
            << "\",\"serverImageSigner\":\""
            << JsonEscape(WideUtf8(serverSigner))
            << "\",\"serverImageVolumeSerial\":"
            << serverLegacy.dwVolumeSerialNumber << ",\"serverInstanceId\":\""
            << JsonEscape(WideUtf8(instanceText))
            << "\",\"serverPid\":" << GetCurrentProcessId()
            << ",\"serverServiceName\":\""
            << JsonEscape(WideUtf8(serverServiceName))
            << ",\"serverServiceSid\":\""
            << JsonEscape(WideUtf8(SidText(serverSid.data()))) << "\"}";
  const std::string strictCanonicalChallenge = challenge.str();
  const std::vector<BYTE> challengeFrame(strictCanonicalChallenge.begin(),
                                         strictCanonicalChallenge.end());
  DWORD budget = remaining();
  if (!budget || !WriteBoundedFrame(pipe, stopEvent, challengeFrame, budget))
    return refuse();
  state = HandshakeState::challenge_sent;
  bool oneRequestPerConnection = false;
  std::vector<BYTE> reply;
  budget = remaining();
  if (!budget || !ReadBoundedFrame(pipe, stopEvent, reply,
                                   oneRequestPerConnection, budget))
    return refuse();
  state = HandshakeState::reply_received;
  // The reply must be received before impersonation; signature verification
  // and dispatch are forbidden until the OS-derived identity is bound.
  if (!AuthenticatePipeClient(pipe, clientPolicy, peer))
    return refuse();
  state = HandshakeState::identity_bound;
  const std::string strictCanonical(reply.begin(), reply.end());
  const std::string challengeHash = HashBytes(challengeFrame);
  const unsigned long long nowAfterReceipt = FileTimeNow();
  if (challengeHash.empty() || nowAfterReceipt > expiresAt || !remaining() ||
      verifier.VerifyAndConsumeStrictCanonicalEs256(
          strictCanonical, challengeHash, expectedAction, peer, issuedAt,
          expiresAt,
          nowAfterReceipt) != SignedRequestVerifier::Result::accepted)
    return refuse();
  canonicalRequest = std::move(reply);
  state = HandshakeState::accepted;
  return true;
}
} // namespace stellar::service
