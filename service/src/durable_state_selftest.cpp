#include "durable_state.h"
#include <windows.h>
#include <bcrypt.h>
#include <fstream>
#include <iomanip>
#include <sstream>
#pragma comment(lib, "bcrypt.lib")
using namespace stellar::service;
namespace {
const std::string Sig(86, 'A');
const std::string SigB = std::string(85, 'B') + "A";
const std::string Kid =
    "sha256:319e2f5e4c300aa59f4662149d9d554596caa4571781374754ab7894d75c0dc5";
const std::string Spki =
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEwsNSJKtCVprCQ2hKimwoGLTi_b_"
    "sgsWBbi0G2PTLYSDGMoV5y_4vycW5QpwFtwwd62wDhaj3gIPelqwgTIvrqg";
const std::string Hash =
    "sha256:1111111111111111111111111111111111111111111111111111111111111111";
const std::string RequestHash =
    "sha256:2222222222222222222222222222222222222222222222222222222222222222";
const std::string Nonce = "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM";
const std::string BrokerSig = "Je_"
                              "UjJb0gnpRD6mX47JJ4PHqfHXUdwLXlTcXIn8iPb1KEE2EfJg"
                              "bcONJGbYCcRDeAI4LNSOi4Erc6raYcxeyGg";
const std::string Envelope =
    "{\"payload\":"
    "\"eyJhY3Rpb24iOiJmaXhlZC1wcm9iZXMiLCJicm9rZXJJbWFnZUhhc2giOiJzaGEyNTY6MTEx"
    "MTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMT"
    "ExMTExMSIsImJyb2tlclNlcnZpY2UiOiJBZWdpc1N0ZWxsYXJFeGVjdXRpb25Ccm9rZXIiLCJj"
    "bGVhbnVwRXZpZGVuY2VIYXNoIjoic2hhMjU2OjExMTExMTExMTExMTExMTExMTExMTExMTExMT"
    "ExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTEiLCJjb250cmFjdEhhc2giOiJz"
    "aGEyNTY6MTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMT"
    "ExMTExMTExMTExMTExMSIsImNvbnRyYWN0SWQiOiJjb250cmFjdCIsImV2aWRlbmNlSGFzaCI6"
    "InNoYTI1NjoxMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMT"
    "ExMTExMTExMTExMTExMTExIiwiZXhwaXJlc0F0IjoyMDAsImhvc3RJZCI6Imhvc3QiLCJpc3N1"
    "ZWRBdCI6MTAwLCJub25jZSI6IkF3TURBd01EQXdNREF3TURBd01EQXdNREF3TURBd01EQXdNRE"
    "F3TURBd00iLCJvcGVyYXRpb25JZCI6Im9wZXJhdGlvbiIsInJlbGVhc2VIYXNoIjoic2hhMjU2"
    "OjExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMT"
    "ExMTExMTExMTEiLCJyZXF1ZXN0SGFzaCI6InNoYTI1NjoyMjIyMjIyMjIyMjIyMjIyMjIyMjIy"
    "MjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyIiwicmVxdWVzdElkIj"
    "oicmVxdWVzdCIsInJ1bm5lckhhc2giOiJzaGEyNTY6MTExMTExMTExMTExMTExMTExMTExMTEx"
    "MTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMSIsInNjaGVtYSI6InN0ZW"
    "xsYXItYnJva2VyLXJlY2VpcHQtdjAuMSIsInN0YXR1cyI6ImNvbXBsZXRlZCIsInRhcmdldFNl"
    "cnZpY2UiOiJhZWdpcy1zdGVsbGFyLXNhbmRib3gifQ\",\"protected\":"
    "\"eyJhbGciOiJFUzI1NiIsImtpZCI6InNoYTI1NjozMTllMmY1ZTRjMzAwYWE1OWY0NjYyMTQ5"
    "ZDlkNTU0NTk2Y2FhNDU3MTc4MTM3NDc1NGFiNzg5NGQ3NWMwZGM1Iiwic2NoZW1hIjoic3RlbG"
    "xhci1icm9rZXItcmVjZWlwdC1wcm90ZWN0ZWQtdjAuMSJ9\",\"schema\":\"stellar-"
    "broker-receipt-envelope-v0.1\",\"signature\":\"Je_"
    "UjJb0gnpRD6mX47JJ4PHqfHXUdwLXlTcXIn8iPb1KEE2EfJgbcONJGbYCcRDeAI4LNSOi4Erc6"
    "raYcxeyGg\"}";
bool Verify(const std::string &, const std::string &, const std::string &s) {
  return s == Sig;
}
std::string Sign(const std::string &, const std::string &) { return Sig; }
std::wstring Temp(const wchar_t *n) {
  wchar_t b[MAX_PATH]{};
  GetTempPathW(MAX_PATH, b);
  return std::wstring(b) + n;
}
std::string Sha(const std::string &v) {
  BCRYPT_ALG_HANDLE a{};
  BCRYPT_HASH_HANDLE h{};
  DWORD n = 0, g = 0;
  BYTE d[32]{};
  BCryptOpenAlgorithmProvider(&a, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
  BCryptGetProperty(a, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&n),
                    sizeof(n), &g, 0);
  std::vector<BYTE> o(n);
  const bool ok =
      BCryptCreateHash(a, &h, o.data(), n, nullptr, 0, 0) == 0 &&
      BCryptHashData(h, reinterpret_cast<PUCHAR>(const_cast<char *>(v.data())),
                     static_cast<ULONG>(v.size()), 0) == 0 &&
      BCryptFinishHash(h, d, 32, 0) == 0;
  if (h)
    BCryptDestroyHash(h);
  BCryptCloseAlgorithmProvider(a, 0);
  std::ostringstream x;
  x << "sha256:" << std::hex << std::setfill('0');
  if (ok)
    for (BYTE b : d)
      x << std::setw(2) << static_cast<unsigned>(b);
  return x.str();
}
void Clean(const std::wstring &p) {
  DeleteFileW(p.c_str());
  DeleteFileW((p + L".new").c_str());
  DeleteFileW((p + L".lock").c_str());
}
std::string RegistryLine() {
  return "{\"kid\":\"" + Kid +
         "\",\"kind\":\"install\",\"notAfter\":1000,\"notBefore\":1,"
         "\"overlapUntil\":1000,\"previousHash\":\"sha256:" +
         std::string(64, '0') +
         "\",\"revokedAt\":0,\"schema\":\"stellar.key-registry-record/"
         "v0.1\",\"sequence\":1,\"signature\":\"" +
         Sig + "\",\"spki\":\"" + Spki + "\"}";
}
std::string KeyLine(const std::string &kid, const std::string &spki,
                    const std::string &kind, unsigned long long sequence,
                    const std::string &previousHash,
                    unsigned long long notBefore,
                    unsigned long long overlapUntil,
                    unsigned long long revokedAt,
                    const std::string &signature) {
  return "{\"kid\":\"" + kid + "\",\"kind\":\"" + kind +
         "\",\"notAfter\":1000,\"notBefore\":" +
         std::to_string(notBefore) + ",\"overlapUntil\":" +
         std::to_string(overlapUntil) + ",\"previousHash\":\"" +
         previousHash + "\",\"revokedAt\":" + std::to_string(revokedAt) +
         ",\"schema\":\"stellar.key-registry-record/v0.1\",\"sequence\":" +
         std::to_string(sequence) + ",\"signature\":\"" + signature +
         "\",\"spki\":\"" + spki + "\"}";
}
JournalRecord Issued() {
  JournalRecord r{};
  r.state = OperationState::ISSUED;
  r.requestId = "request";
  r.requestHash = RequestHash;
  r.contractId = "contract";
  r.contractHash = Hash;
  r.nonce = Nonce;
  r.operationId = "operation";
  r.releaseHash = Hash;
  r.action = "fixed-probes";
  r.evidenceHash = Hash;
  r.cleanupEvidenceHash = Hash;
  r.hostId = "host";
  r.targetService = "aegis-stellar-sandbox";
  r.brokerService = "AegisStellarExecutionBroker";
  r.brokerImageHash = Hash;
  r.runnerHash = Hash;
  r.journalRecordSignature = Sig;
  return r;
}
} // namespace
int wmain(int argc, wchar_t **argv) {
  if (argc == 4 && wcscmp(argv[1], L"--worker") == 0) {
    DurableReplayJournal j(argv[2]);
    if (!j.Recover(Verify, Kid, Sign))
      return 90;
    const auto result = j.DriveAndDispatch("request", RequestHash, [&] {
      HANDLE marker = CreateFileW(argv[3], GENERIC_WRITE, 0, nullptr,
                                  CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
      if (marker == INVALID_HANDLE_VALUE) return false;
      const char evidence[] = "dispatch-callback-invoked-once";
      DWORD written = 0;
      const bool ok = WriteFile(marker, evidence, sizeof(evidence)-1, &written,
                                nullptr) && written == sizeof(evidence)-1 &&
                      FlushFileBuffers(marker);
      CloseHandle(marker);
      return ok;
    });
    return result == DriveDisposition::DISPATCHED ? 0 : 2;
  }
  const auto rp = Temp(L"aegis-stellar-d3-v02-registry.jsonl"),
             rotation = Temp(L"aegis-stellar-d3-v02-rotation.jsonl"),
             wrongRotation = Temp(L"aegis-stellar-d3-v02-rotation-wrong.jsonl"),
             jp = Temp(L"aegis-stellar-d3-v02-journal.jsonl"),
             dispatchMarker = Temp(L"aegis-stellar-d3-v02-dispatch.marker"),
             bad = Temp(L"aegis-stellar-d3-v02-corrupt.jsonl");
  Clean(rp);
  Clean(rotation);
  Clean(wrongRotation);
  Clean(jp);
  DeleteFileW(dispatchMarker.c_str());
  Clean(bad);
  {
    std::ofstream o(rp, std::ios::binary);
    o << RegistryLine() << '\n';
  }
  SignedKeyRegistryFile registry(rp);
  if (!registry.RecoverAndLoad(Kid, Verify))
    return 10;
  const std::string oldKid = Sha("abc"), newKid = Sha("abcd");
  const std::string install = KeyLine(oldKid, "YWJj", "install", 1,
                                      "sha256:" + std::string(64, '0'), 1,
                                      100, 0, Sig);
  const std::string rotate = KeyLine(newKid, "YWJjZA", "rotate", 2,
                                     Sha(install), 20, 100, 0, Sig);
  const std::string revoke = KeyLine(oldKid, "YWJj", "revoke", 3,
                                     Sha(rotate), 1, 100, 200, SigB);
  const std::string wrongRevoke = KeyLine(oldKid, "YWJj", "revoke", 3,
                                          Sha(rotate), 1, 100, 200, Sig);
  const auto signerAware = [&](const std::string &signer, const std::string &,
                               const std::string &signature) {
    return (signer == oldKid && signature == Sig) ||
           (signer == newKid && signature == SigB);
  };
  {
    std::ofstream out(rotation, std::ios::binary);
    out << install << '\n' << rotate << '\n' << revoke << '\n';
    std::ofstream wrong(wrongRotation, std::ios::binary);
    wrong << install << '\n' << rotate << '\n' << wrongRevoke << '\n';
  }
  SignedKeyRegistryFile rotated(rotation), wrongSigner(wrongRotation);
  if (!rotated.RecoverAndLoad(oldKid, signerAware)) return 11;
  if (rotated.Resolve(oldKid, 200)) return 12;
  if (!rotated.Resolve(newKid, 200)) return 13;
  if (wrongSigner.RecoverAndLoad(oldKid, signerAware)) return 14;
  DurableReplayJournal journal(jp);
  if (!journal.Recover(Verify, Kid, Sign) || !journal.Issue(Issued()))
    return 20;
  wchar_t exe[MAX_PATH]{};
  GetModuleFileNameW(nullptr, exe, MAX_PATH);
  std::vector<PROCESS_INFORMATION> ps;
  for (int i = 0; i < 12; ++i) {
    std::wstring cmd =
        L"\"" + std::wstring(exe) + L"\" --worker \"" + jp +
        L"\" \"" + dispatchMarker + L"\"";
    STARTUPINFOW si{sizeof(si)};
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, FALSE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
      return 21;
    CloseHandle(pi.hThread);
    ps.push_back(pi);
  }
  int winners = 0;
  for (auto &p : ps) {
    WaitForSingleObject(p.hProcess, 10000);
    DWORD code = 99;
    GetExitCodeProcess(p.hProcess, &code);
    CloseHandle(p.hProcess);
    if (code == 0)
      ++winners;
  }
  if (winners != 1)
    return 22;
  WIN32_FILE_ATTRIBUTE_DATA markerData{};
  if (!GetFileAttributesExW(dispatchMarker.c_str(), GetFileExInfoStandard,
                            &markerData) || markerData.nFileSizeHigh != 0 ||
      markerData.nFileSizeLow != 30)
    return 41;
  DurableReplayJournal recovered(jp);
  if (!recovered.Recover(Verify, Kid, Sign) ||
      (recovered.State("request") != OperationState::DISPATCHED &&
       recovered.State("request") != OperationState::RECONCILING))
    return 23;
  int restartDispatches = 0;
  const auto resumed = recovered.DriveAndDispatch("request", RequestHash, [&] {
    ++restartDispatches;
    return true;
  });
  if ((resumed != DriveDisposition::RECONCILE_REQUIRED) || restartDispatches)
    return 24;
  DurableReceipt receipt{"request",
                         RequestHash,
                         "contract",
                         Hash,
                         Nonce,
                         "operation",
                         Hash,
                         "fixed-probes",
                         Hash,
                         Hash,
                         "host",
                         "aegis-stellar-sandbox",
                         "AegisStellarExecutionBroker",
                         Hash,
                         Hash,
                         Envelope,
                         BrokerSig};
  if (!recovered.Consume(receipt, registry, 150))
    return 25;
  bool conflict = false;
  auto prior = recovered.PriorReceipt("request", RequestHash, conflict);
  if (!prior || conflict || prior->brokerCanonicalReceipt != Envelope ||
      prior->brokerSignature != BrokerSig)
    return 26;
  DurableReplayJournal restart(jp);
  if (!restart.Recover(Verify, Kid, Sign))
    return 27;
  auto again = restart.PriorReceipt("request", RequestHash, conflict);
  if (!again || again->brokerCanonicalReceipt != Envelope ||
      again->brokerSignature != BrokerSig ||
      restart.Drive("request", RequestHash) !=
          DriveDisposition::PRIOR_RECEIPT)
    return 28;
  if (!CopyFileW(jp.c_str(), bad.c_str(), FALSE))
    return 30;
  {
    std::ofstream o(bad, std::ios::binary | std::ios::app);
    o << "{\"truncated\":";
  }
  DurableReplayJournal truncated(bad);
  if (truncated.Recover(Verify, Kid, Sign))
    return 31;
  Clean(bad);
  if (!CopyFileW(jp.c_str(), bad.c_str(), FALSE))
    return 32;
  {
    std::fstream f(bad, std::ios::binary | std::ios::in | std::ios::out);
    std::string s((std::istreambuf_iterator<char>(f)), {});
    const auto at = s.find(Sig);
    if (at == std::string::npos)
      return 33;
    s[at] = 'B';
    f.seekp(0);
    f.write(s.data(), static_cast<std::streamsize>(s.size()));
  }
  DurableReplayJournal corrupt(bad);
  if (corrupt.Recover(Verify, Kid, Sign))
    return 34;
  if (!CopyFileW(jp.c_str(), (jp + L".new").c_str(), FALSE))
    return 35;
  {
    std::ofstream o(jp + L".new", std::ios::binary | std::ios::app);
    o << "crash";
  }
  DurableReplayJournal stale(jp);
  if (!stale.Recover(Verify, Kid, Sign) ||
      GetFileAttributesW((jp + L".new").c_str()) != INVALID_FILE_ATTRIBUTES)
    return 36;
  auto refused = Issued();
  refused.requestId = "request-refused";
  refused.requestHash = Sha("request-refused");
  DeleteFileW(bad.c_str());
  if (!CopyFileW(jp.c_str(), bad.c_str(), FALSE) || !stale.Issue(refused) ||
      !CopyFileW(jp.c_str(), (jp + L".new").c_str(), FALSE) ||
      !CopyFileW(bad.c_str(), jp.c_str(), FALSE))
    return 37;
  DurableReplayJournal crashRecovered(jp);
  if (!crashRecovered.Recover(Verify, Kid, Sign) ||
      crashRecovered.State(refused.requestId) != OperationState::ISSUED)
    return 38;
  if (!crashRecovered.Reserve(refused.requestId, refused.requestHash) ||
      !crashRecovered.Refuse(refused.requestId, Sha("quarantine")))
    return 39;
  DurableReplayJournal refusedRestart(jp);
  if (!refusedRestart.Recover(Verify, Kid, Sign) ||
      refusedRestart.Drive(refused.requestId, refused.requestHash) !=
          DriveDisposition::PERMANENTLY_REFUSED)
    return 40;
  Clean(rp);
  Clean(rotation);
  Clean(wrongRotation);
  Clean(jp);
  DeleteFileW(dispatchMarker.c_str());
  Clean(bad);
  return 0;
}
