#include "durable_state.h"
#include "gateway_pipe_client.h"
#include <algorithm>
#include <windows.h>
#include <bcrypt.h>
#include <iomanip>
#include <map>
#include <sstream>
#pragma comment(lib,"bcrypt.lib")
namespace stellar::service { namespace {
const std::string Zero="sha256:"+std::string(64,'0');
std::string Sha(const std::string&v){BCRYPT_ALG_HANDLE a{};BCRYPT_HASH_HANDLE h{};DWORD n=0,g=0;BYTE d[32]{};if(BCryptOpenAlgorithmProvider(&a,BCRYPT_SHA256_ALGORITHM,nullptr,0)!=0)return{};bool ok=BCryptGetProperty(a,BCRYPT_OBJECT_LENGTH,reinterpret_cast<PUCHAR>(&n),sizeof(n),&g,0)==0;std::vector<BYTE>o(n);ok=ok&&BCryptCreateHash(a,&h,o.data(),n,nullptr,0,0)==0&&BCryptHashData(h,reinterpret_cast<PUCHAR>(const_cast<char*>(v.data())),static_cast<ULONG>(v.size()),0)==0&&BCryptFinishHash(h,d,32,0)==0;if(h)BCryptDestroyHash(h);BCryptCloseAlgorithmProvider(a,0);std::ostringstream x;x<<"sha256:"<<std::hex<<std::setfill('0');if(ok)for(BYTE b:d)x<<std::setw(2)<<static_cast<unsigned>(b);return ok?x.str():std::string{};}
std::string B64(const std::string&in){static constexpr char t[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";std::string out;unsigned a=0,b=0;for(unsigned char c:in){a=(a<<8)|c;b+=8;while(b>=6){b-=6;out+=t[(a>>b)&63];}}if(b)out+=t[(a<<(6-b))&63];return out;}
bool UnB64(const std::string&in,std::string&out){if(in.empty()){out.clear();return true;}std::vector<unsigned char>b;if(!json::DecodeCanonicalBase64Url(in,b))return false;out.assign(b.begin(),b.end());return true;}
bool ReadLines(const std::wstring&p,std::vector<std::string>&lines){HANDLE f=CreateFileW(p.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);if(f==INVALID_HANDLE_VALUE)return false;LARGE_INTEGER n{};bool ok=GetFileSizeEx(f,&n)&&n.QuadPart>=0&&n.QuadPart<=16*1024*1024;std::string bytes(ok?static_cast<size_t>(n.QuadPart):0,'\0');DWORD got=0;if(ok&&!bytes.empty())ok=ReadFile(f,bytes.data(),static_cast<DWORD>(bytes.size()),&got,nullptr)&&got==bytes.size();CloseHandle(f);if(!ok||(!bytes.empty()&&bytes.back()!='\n'))return false;for(size_t s=0;s<bytes.size();){const auto e=bytes.find('\n',s);if(e==std::string::npos||e==s||e-s>32768)return false;lines.push_back(bytes.substr(s,e-s));s=e+1;}return true;}
bool Atomic(const std::wstring&p,const std::string&bytes){const auto t=p+L".new";DeleteFileW(t.c_str());HANDLE f=CreateFileW(t.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL|FILE_FLAG_WRITE_THROUGH,nullptr);if(f==INVALID_HANDLE_VALUE)return false;DWORD wrote=0;bool ok=bytes.size()<=MAXDWORD&&WriteFile(f,bytes.data(),static_cast<DWORD>(bytes.size()),&wrote,nullptr)&&wrote==bytes.size()&&FlushFileBuffers(f);CloseHandle(f);if(ok)ok=MoveFileExW(t.c_str(),p.c_str(),MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH)!=FALSE;if(!ok)DeleteFileW(t.c_str());return ok;}
struct Lock{HANDLE h{INVALID_HANDLE_VALUE};OVERLAPPED o{};explicit Lock(const std::wstring&p){h=CreateFileW((p+L".lock").c_str(),GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ,nullptr,OPEN_ALWAYS,FILE_ATTRIBUTE_HIDDEN|FILE_FLAG_WRITE_THROUGH,nullptr);if(h!=INVALID_HANDLE_VALUE&&!LockFileEx(h,LOCKFILE_EXCLUSIVE_LOCK,0,MAXDWORD,MAXDWORD,&o)){CloseHandle(h);h=INVALID_HANDLE_VALUE;}}~Lock(){if(h!=INVALID_HANDLE_VALUE){UnlockFileEx(h,0,MAXDWORD,MAXDWORD,&o);CloseHandle(h);}}explicit operator bool()const{return h!=INVALID_HANDLE_VALUE;}};
bool KidSpki(const json::KeyRegistryRecord&r){std::vector<unsigned char>b;return json::DecodeCanonicalBase64Url(r.spki,b)&&Sha(std::string(b.begin(),b.end()))==r.kid;}
const char*Txt(OperationState s){switch(s){case OperationState::ISSUED:return"ISSUED";case OperationState::RESERVED:return"RESERVED";case OperationState::DISPATCHED:return"DISPATCHED";case OperationState::RECONCILING:return"RECONCILING";case OperationState::CONSUMED:return"CONSUMED";case OperationState::REFUSED:return"REFUSED";}return"";}
OperationState StateOf(const std::string&s){return s=="ISSUED"?OperationState::ISSUED:s=="RESERVED"?OperationState::RESERVED:s=="DISPATCHED"?OperationState::DISPATCHED:s=="RECONCILING"?OperationState::RECONCILING:s=="CONSUMED"?OperationState::CONSUMED:OperationState::REFUSED;}
bool Allowed(OperationState a,OperationState b){return(a==OperationState::ISSUED&&b==OperationState::RESERVED)||(a==OperationState::RESERVED&&(b==OperationState::DISPATCHED||b==OperationState::REFUSED))||(a==OperationState::DISPATCHED&&(b==OperationState::RECONCILING||b==OperationState::CONSUMED||b==OperationState::REFUSED))||(a==OperationState::RECONCILING&&(b==OperationState::CONSUMED||b==OperationState::REFUSED));}
bool Same(const JournalRecord&a,const JournalRecord&b){return a.requestId==b.requestId&&a.requestHash==b.requestHash&&a.contractId==b.contractId&&a.contractHash==b.contractHash&&a.nonce==b.nonce&&a.operationId==b.operationId&&a.releaseHash==b.releaseHash&&a.action==b.action&&a.evidenceHash==b.evidenceHash&&a.cleanupEvidenceHash==b.cleanupEvidenceHash&&a.hostId==b.hostId&&a.targetService==b.targetService&&a.brokerService==b.brokerService&&a.brokerImageHash==b.brokerImageHash&&a.runnerHash==b.runnerHash;}
std::string Core(const JournalRecord&r){return"{\"action\":\""+r.action+"\",\"brokerCanonicalReceipt\":\""+B64(r.brokerCanonicalReceipt)+"\",\"brokerImageHash\":\""+r.brokerImageHash+"\",\"brokerReceiptHash\":\""+r.brokerReceiptHash+"\",\"brokerService\":\""+r.brokerService+"\",\"brokerSignature\":\""+r.brokerSignature+"\",\"cleanupEvidenceHash\":\""+r.cleanupEvidenceHash+"\",\"contractHash\":\""+r.contractHash+"\",\"contractId\":\""+r.contractId+"\",\"evidenceHash\":\""+r.evidenceHash+"\",\"hostId\":\""+r.hostId+"\",\"nonce\":\""+r.nonce+"\",\"operationId\":\""+r.operationId+"\",\"previousHash\":\""+r.previousHash+"\",\"releaseHash\":\""+r.releaseHash+"\",\"requestHash\":\""+r.requestHash+"\",\"requestId\":\""+r.requestId+"\",\"runnerHash\":\""+r.runnerHash+"\",\"schema\":\"stellar.replay-journal-record/v0.2\",\"sequence\":"+std::to_string(r.sequence)+",\"state\":\""+Txt(r.state)+"\",\"targetService\":\""+r.targetService+"\"}";}
std::string Full(const JournalRecord&r){return"{\"action\":\""+r.action+"\",\"brokerCanonicalReceipt\":\""+B64(r.brokerCanonicalReceipt)+"\",\"brokerImageHash\":\""+r.brokerImageHash+"\",\"brokerReceiptHash\":\""+r.brokerReceiptHash+"\",\"brokerService\":\""+r.brokerService+"\",\"brokerSignature\":\""+r.brokerSignature+"\",\"cleanupEvidenceHash\":\""+r.cleanupEvidenceHash+"\",\"contractHash\":\""+r.contractHash+"\",\"contractId\":\""+r.contractId+"\",\"evidenceHash\":\""+r.evidenceHash+"\",\"hostId\":\""+r.hostId+"\",\"journalRecordSignature\":\""+r.journalRecordSignature+"\",\"nonce\":\""+r.nonce+"\",\"operationId\":\""+r.operationId+"\",\"previousHash\":\""+r.previousHash+"\",\"recordHash\":\""+r.recordHash+"\",\"releaseHash\":\""+r.releaseHash+"\",\"requestHash\":\""+r.requestHash+"\",\"requestId\":\""+r.requestId+"\",\"runnerHash\":\""+r.runnerHash+"\",\"schema\":\"stellar.replay-journal-record/v0.2\",\"sequence\":"+std::to_string(r.sequence)+",\"state\":\""+Txt(r.state)+"\",\"targetService\":\""+r.targetService+"\"}";}
const JournalRecord*Last(const std::vector<JournalRecord>&v,const std::string&id){for(auto i=v.rbegin();i!=v.rend();++i)if(i->requestId==id)return&*i;return nullptr;}
bool Issued(const JournalRecord&r){return r.state==OperationState::ISSUED&&!r.requestId.empty()&&!r.requestHash.empty()&&!r.contractId.empty()&&!r.contractHash.empty()&&!r.nonce.empty()&&!r.operationId.empty()&&!r.releaseHash.empty()&&!r.action.empty()&&!r.evidenceHash.empty()&&!r.cleanupEvidenceHash.empty()&&!r.hostId.empty()&&!r.targetService.empty()&&!r.brokerService.empty()&&!r.brokerImageHash.empty()&&!r.runnerHash.empty()&&r.brokerCanonicalReceipt.empty()&&r.brokerSignature.empty();}
}

bool SignedKeyRegistryFile::LoadCandidate(
    const std::wstring &p, const std::string &root,
    const RecordSignatureVerifier &verify,
    std::vector<json::KeyRegistryRecord> &out) const {
  std::vector<std::string> lines;
  if (!ReadLines(p, lines) || lines.empty())
    return false;
  std::string previous = Zero;
  std::map<std::string, json::KeyRegistryRecord> latest;
  for (size_t i = 0; i < lines.size(); ++i) {
    json::KeyRegistryRecord r;
    if (!json::ParseCanonicalKeyRegistryRecord(lines[i], r).accepted ||
        r.sequence != i + 1 || r.previousHash != previous || !KidSpki(r))
      return false;
    std::string signer = root;
    if (i) {
      const auto eventTime = r.kind == "revoke" ? r.revokedAt : r.notBefore;
      const auto active =
          std::find_if(out.rbegin(), out.rend(), [&](const auto &x) {
            return !x.revokedAt && x.notBefore <= eventTime &&
                   eventTime < x.notAfter;
          });
      if (active == out.rend())
        return false;
      signer = active->kid;
    }
    if (!verify(signer, r.canonicalUnsigned, r.signature) ||
        (i == 0 && r.kind != "install") || (i && r.kind == "install"))
      return false;
    if (r.kind == "rotate" &&
        (latest.contains(r.kid) || r.overlapUntil < r.notBefore ||
         r.overlapUntil - r.notBefore > 86400))
      return false;
    if (r.kind == "revoke" &&
        (!latest.contains(r.kid) || latest[r.kid].revokedAt ||
         r.revokedAt < r.notBefore))
      return false;
    latest[r.kid] = r;
    out.push_back(r);
    previous = Sha(lines[i]);
  }
  return true;
}
bool SignedKeyRegistryFile::RecoverAndLoad(const std::string&root,const RecordSignatureVerifier&verify){Lock lock(path_);if(!lock)return false;std::vector<json::KeyRegistryRecord>a,b;const bool ao=LoadCandidate(path_,root,verify,a),bo=LoadCandidate(path_+L".new",root,verify,b);if(!ao&&!bo)return false;if(bo&&(!ao||b.size()>a.size())){if(!MoveFileExW((path_+L".new").c_str(),path_.c_str(),MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH))return false;a=std::move(b);}else DeleteFileW((path_+L".new").c_str());records_=std::move(a);rootKid_=root;return true;}
bool SignedKeyRegistryFile::PersistAndReopen(const std::vector<json::KeyRegistryRecord>&r,const std::string&root,const RecordSignatureVerifier&v){std::string bytes;for(const auto&x:r)bytes+=x.canonicalSigned+'\n';if(!Atomic(path_,bytes))return false;std::vector<json::KeyRegistryRecord>back;if(!LoadCandidate(path_,root,v,back)||back.size()!=r.size())return false;records_=std::move(back);return true;}
bool SignedKeyRegistryFile::Apply(const std::string&line,const RecordSignatureVerifier&v){Lock lock(path_);if(!lock)return false;json::KeyRegistryRecord r;if(!json::ParseCanonicalKeyRegistryRecord(line,r).accepted||r.sequence!=records_.size()+1||r.previousHash!=(records_.empty()?Zero:Sha(records_.back().canonicalSigned))||!KidSpki(r))return false;std::string signer=rootKid_;if(!records_.empty()){auto active=ActiveIssuer(r.kind=="revoke"?r.revokedAt:r.notBefore);if(!active)return false;signer=active->kid;}if(!v(signer,r.canonicalUnsigned,r.signature))return false;const bool known=std::any_of(records_.begin(),records_.end(),[&](const auto&x){return x.kid==r.kid;});if((records_.empty()&&r.kind!="install")||(!records_.empty()&&r.kind=="install")||(r.kind=="rotate"&&(known||r.overlapUntil<r.notBefore||r.overlapUntil-r.notBefore>86400))||(r.kind=="revoke"&&!Resolve(r.kid,r.revokedAt)))return false;auto next=records_;next.push_back(r);return PersistAndReopen(next,rootKid_,v);}
std::optional<json::KeyRegistryRecord>SignedKeyRegistryFile::Resolve(const std::string&kid,unsigned long long now)const{for(auto i=records_.rbegin();i!=records_.rend();++i)if(i->kid==kid){if((i->revokedAt&&i->revokedAt<=now)||now<i->notBefore||now>=i->notAfter)return{};auto active=ActiveIssuer(now);if(active&&active->kid!=kid&&now>active->overlapUntil)return{};return*i;}return{};}
std::optional<json::KeyRegistryRecord>SignedKeyRegistryFile::ActiveIssuer(unsigned long long now)const{for(auto i=records_.rbegin();i!=records_.rend();++i)if(i->kind=="install"||i->kind=="rotate"){bool revoked=false;for(auto e=records_.rbegin();e!=records_.rend();++e)if(e->kind=="revoke"&&e->kid==i->kid&&e->revokedAt<=now){revoked=true;break;}if(!revoked&&i->notBefore<=now&&now<i->notAfter)return*i;}return{};}

bool DurableReplayJournal::LoadCandidate(
    const std::wstring &p, std::vector<JournalRecord> &out) const {
  std::vector<std::string> lines;
  if (!ReadLines(p, lines))
    return false;
  std::map<std::string, JournalRecord> latest;
  std::string previous = Zero;
  for (size_t i = 0; i < lines.size(); ++i) {
    json::ReplayRecord x;
    if (!json::ParseCanonicalReplayRecord(lines[i], x).accepted ||
        x.sequence != i + 1 || x.previousHash != previous ||
        x.recordHash != Sha(x.canonicalUnsigned) ||
        !verify_(signingKid_, x.canonicalUnsigned, x.journalRecordSignature))
      return false;
    JournalRecord r{x.sequence,
                    StateOf(x.state),
                    x.requestId,
                    x.requestHash,
                    x.contractId,
                    x.contractHash,
                    x.nonce,
                    x.operationId,
                    x.releaseHash,
                    x.action,
                    x.evidenceHash,
                    x.cleanupEvidenceHash,
                    x.hostId,
                    x.targetService,
                    x.brokerService,
                    x.brokerImageHash,
                    x.runnerHash,
                    x.previousHash,
                    x.recordHash,
                    "",
                    x.brokerReceiptHash,
                    x.brokerSignature,
                    x.journalRecordSignature};
    if (!UnB64(x.brokerCanonicalReceipt, r.brokerCanonicalReceipt))
      return false;
    auto prior = latest.find(r.requestId);
    if ((prior == latest.end() && !Issued(r)) ||
        (prior != latest.end() &&
         (!Allowed(prior->second.state, r.state) || !Same(prior->second, r))))
      return false;
    if (r.state == OperationState::CONSUMED &&
        (r.brokerCanonicalReceipt.empty() ||
         Sha(r.brokerCanonicalReceipt) != r.brokerReceiptHash))
      return false;
    latest[r.requestId] = r;
    out.push_back(r);
    previous = Sha(lines[i]);
  }
  return true;
}
bool DurableReplayJournal::LoadBestLocked(std::vector<JournalRecord>&out,bool repair){const DWORD ma=GetFileAttributesW(path_.c_str()),ta=GetFileAttributesW((path_+L".new").c_str());const bool mm=ma==INVALID_FILE_ATTRIBUTES,tm=ta==INVALID_FILE_ATTRIBUTES;std::vector<JournalRecord>a,b;const bool ao=!mm&&!(ma&FILE_ATTRIBUTE_DIRECTORY)&&LoadCandidate(path_,a),bo=!tm&&!(ta&FILE_ATTRIBUTE_DIRECTORY)&&LoadCandidate(path_+L".new",b);if(mm&&tm){out.clear();return true;}if(!ao&&!bo)return false;if(bo&&(!ao||b.size()>a.size())){if(repair&&!MoveFileExW((path_+L".new").c_str(),path_.c_str(),MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH))return false;out=std::move(b);}else{if(repair&&!tm)DeleteFileW((path_+L".new").c_str());out=std::move(a);}return true;}
bool DurableReplayJournal::Recover(const RecordSignatureVerifier&v,const std::string&kid,const RecordSignatureSigner&s){Lock lock(path_);if(!lock||!v||!s||kid.empty())return false;verify_=v;signer_=s;signingKid_=kid;std::vector<JournalRecord>x;if(!LoadBestLocked(x,true)){verify_={};signer_={};return false;}records_=std::move(x);return true;}
bool DurableReplayJournal::PersistAndRevalidate(const std::vector<JournalRecord>&next,std::vector<JournalRecord>&back){std::string bytes;for(const auto&r:next)bytes+=Full(r)+'\n';return Atomic(path_,bytes)&&LoadCandidate(path_,back)&&back.size()==next.size()&&back.back().recordHash==next.back().recordHash;}
bool DurableReplayJournal::Transition(const std::function<bool(const std::vector<JournalRecord>&,JournalRecord&)>&prep){Lock lock(path_);if(!lock||!verify_||!signer_)return false;std::vector<JournalRecord>current;if(!LoadBestLocked(current,true))return false;JournalRecord r;if(!prep(current,r))return false;r.sequence=current.size()+1;r.previousHash=current.empty()?Zero:Sha(Full(current.back()));r.journalRecordSignature.clear();const std::string core=Core(r);r.journalRecordSignature=signer_(signingKid_,core);r.recordHash=Sha(core);if(r.journalRecordSignature.empty()||!verify_(signingKid_,core,r.journalRecordSignature))return false;current.push_back(r);std::vector<JournalRecord>back;if(!PersistAndRevalidate(current,back))return false;records_=std::move(back);return true;}
bool DurableReplayJournal::Issue(const JournalRecord&r){return Transition([&](const auto&v,JournalRecord&n){if(!Issued(r)||Last(v,r.requestId))return false;n=r;n.brokerReceiptHash=Zero;return true;});}
bool DurableReplayJournal::Reserve(const std::string&id,const std::string&hash){return Transition([&](const auto&v,JournalRecord&n){auto p=Last(v,id);if(!p||p->requestHash!=hash||p->state!=OperationState::ISSUED)return false;n=*p;n.state=OperationState::RESERVED;return true;});}
bool DurableReplayJournal::MarkDispatched(const std::string&id){return Transition([&](const auto&v,JournalRecord&n){auto p=Last(v,id);if(!p||p->state!=OperationState::RESERVED)return false;n=*p;n.state=OperationState::DISPATCHED;return true;});}
bool DurableReplayJournal::BeginReconciliation(const std::string&id){return Transition([&](const auto&v,JournalRecord&n){auto p=Last(v,id);if(!p||p->state!=OperationState::DISPATCHED)return false;n=*p;n.state=OperationState::RECONCILING;return true;});}
bool DurableReplayJournal::Consume(const DurableReceipt &r,
                                   const SignedKeyRegistryFile &registry,
                                   unsigned long long now) {
  return Transition([&](const auto &v, JournalRecord &n) {
    auto p = Last(v, r.requestId);
    if (!p ||
        (p->state != OperationState::DISPATCHED &&
         p->state != OperationState::RECONCILING) ||
        r.requestHash != p->requestHash || r.contractId != p->contractId ||
        r.contractHash != p->contractHash || r.nonce != p->nonce ||
        r.operationId != p->operationId || r.releaseHash != p->releaseHash ||
        r.action != p->action || r.evidenceHash != p->evidenceHash ||
        r.cleanupEvidenceHash != p->cleanupEvidenceHash ||
        r.hostId != p->hostId ||
        r.targetService != p->targetService ||
        r.brokerService != p->brokerService ||
        r.brokerImageHash != p->brokerImageHash ||
        r.runnerHash != p->runnerHash)
      return false;
    std::vector<BYTE> bytes(r.brokerCanonicalReceipt.begin(),
                            r.brokerCanonicalReceipt.end());
    json::BrokerReceiptEnvelope e;
    if (!VerifyRegistryBrokerReceipt(bytes, registry, now, &e))
      return false;
    BrokerReceiptBinding expected{
        p->requestId, p->requestHash,   p->contractId,    p->contractHash,
        p->nonce,     p->operationId,   p->releaseHash,   p->action,
        p->evidenceHash, p->cleanupEvidenceHash, p->hostId, p->targetService,
        p->brokerService, p->brokerImageHash, p->runnerHash};
    if (!BrokerReceiptMatches(e.receipt, expected, now) ||
        e.receipt.status != "completed" ||
        r.brokerSignature !=
            B64(std::string(e.signature.begin(), e.signature.end())))
      return false;
    n = *p;
    n.state = OperationState::CONSUMED;
    n.brokerCanonicalReceipt = r.brokerCanonicalReceipt;
    n.brokerReceiptHash = Sha(r.brokerCanonicalReceipt);
    n.brokerSignature = r.brokerSignature;
    return true;
  });
}
bool DurableReplayJournal::Refuse(const std::string&id,const std::string&reason){return Transition([&](const auto&v,JournalRecord&n){auto p=Last(v,id);if(!p||p->state==OperationState::CONSUMED||p->state==OperationState::REFUSED||reason.size()!=71)return false;n=*p;n.state=OperationState::REFUSED;n.brokerCanonicalReceipt.clear();n.brokerSignature.clear();n.brokerReceiptHash=reason;return true;});}
DriveDisposition DurableReplayJournal::Drive(const std::string&id,const std::string&hash){bool conflict=false;if(PriorReceipt(id,hash,conflict))return DriveDisposition::PRIOR_RECEIPT;if(conflict)return DriveDisposition::FAILED;switch(State(id)){case OperationState::ISSUED:return Reserve(id,hash)&&MarkDispatched(id)?DriveDisposition::DISPATCHED:DriveDisposition::FAILED;case OperationState::RESERVED:return MarkDispatched(id)?DriveDisposition::DISPATCHED:DriveDisposition::FAILED;case OperationState::DISPATCHED:return BeginReconciliation(id)?DriveDisposition::RECONCILE_REQUIRED:DriveDisposition::FAILED;case OperationState::RECONCILING:return DriveDisposition::RECONCILE_REQUIRED;case OperationState::REFUSED:return DriveDisposition::PERMANENTLY_REFUSED;default:return DriveDisposition::FAILED;}}
DriveDisposition DurableReplayJournal::DriveAndDispatch(const std::string&id,const std::string&hash,const std::function<bool()>&dispatch){if(!dispatch)return DriveDisposition::FAILED;const auto disposition=Drive(id,hash);if(disposition!=DriveDisposition::DISPATCHED)return disposition;if(dispatch())return DriveDisposition::DISPATCHED;return BeginReconciliation(id)?DriveDisposition::RECONCILE_REQUIRED:DriveDisposition::FAILED;}
std::optional<DurableReceipt> DurableReplayJournal::PriorReceipt(
    const std::string &id, const std::string &hash, bool &conflict) const {
  conflict = false;
  for (auto i = records_.rbegin(); i != records_.rend(); ++i)
    if (i->requestId == id) {
      conflict = i->requestHash != hash;
      if (conflict || i->state != OperationState::CONSUMED)
        return {};
      return DurableReceipt{i->requestId,      i->requestHash,
                            i->contractId,     i->contractHash,
                            i->nonce,          i->operationId,
                            i->releaseHash,    i->action,
                            i->evidenceHash,   i->cleanupEvidenceHash,
                            i->hostId,         i->targetService,
                            i->brokerService,  i->brokerImageHash,
                            i->runnerHash,     i->brokerCanonicalReceipt,
                            i->brokerSignature};
    }
  return {};
}
OperationState DurableReplayJournal::State(const std::string&id)const{auto p=Last(records_,id);return p?p->state:OperationState::REFUSED;}
}
