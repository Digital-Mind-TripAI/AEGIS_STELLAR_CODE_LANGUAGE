#include "canonical_json.h"
#include <algorithm>
#include <array>
#include <windows.h>
#include <bcrypt.h>
#include <charconv>
#include <cstdint>
#include <iomanip>
#include <limits>
#include <set>
#include <sstream>
#include <utility>
#include <wincrypt.h>
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")
namespace stellar::service::json { namespace {
enum class Kind{nullValue,boolean,integer,string,array,object};
struct Value{Kind kind{};bool boolean{};std::int64_t integer{};std::string string;std::vector<Value> array;std::vector<std::pair<std::string,Value>> object;};
class Parser{public:Parser(std::string_view s,std::size_t d):s_(s),maxDepth_(d){}Result Run(Value*out=nullptr){Value v;if(!Read(v,0))return{false,error_};if(pos_!=s_.size())return{false,Error::trailing_data};if(out)*out=std::move(v);return{true,Error::none};}
private:bool Read(Value&v,std::size_t depth){if(depth>maxDepth_)return Fail(Error::maximumDepth);if(pos_>=s_.size())return Fail(Error::syntax);const unsigned char c=static_cast<unsigned char>(s_[pos_]);if(c>=0x80)return Fail(Error::non_ascii);if(c=='{')return Object(v,depth+1);if(c=='[')return Array(v,depth+1);if(c=='"'){v.kind=Kind::string;return String(v.string);}if(c=='t'){v.kind=Kind::boolean;v.boolean=true;return Literal("true");}if(c=='f'){v.kind=Kind::boolean;return Literal("false");}if(c=='n'){v.kind=Kind::nullValue;return Literal("null");}v.kind=Kind::integer;return Number(v.integer);}
bool Object(Value&v,std::size_t depth){v.kind=Kind::object;++pos_;if(Take('}'))return true;std::set<std::string>seen;std::string prior;for(;;){if(v.object.size()>=256)return Fail(Error::maximumMembers);std::string key;if(!String(key)||!Take(':'))return Fail(Error::syntax);if(!seen.insert(key).second)return Fail(Error::duplicate_key);if(!prior.empty()&&key<=prior)return Fail(Error::noncanonical_key_order);prior=key;Value item;if(!Read(item,depth))return false;v.object.push_back({std::move(key),std::move(item)});if(Take('}'))return true;if(!Take(','))return Fail(Error::syntax);}}
bool Array(Value&v,std::size_t depth){v.kind=Kind::array;++pos_;if(Take(']'))return true;for(;;){if(v.array.size()>=256)return Fail(Error::maximumMembers);Value item;if(!Read(item,depth))return false;v.array.push_back(std::move(item));if(Take(']'))return true;if(!Take(','))return Fail(Error::syntax);}}
bool String(std::string&out){if(!Take('"'))return false;while(pos_<s_.size()){const unsigned char c=static_cast<unsigned char>(s_[pos_++]);if(c=='"')return true;if(c<0x20||c>=0x80)return Fail(c>=0x80?Error::non_ascii:Error::syntax);if(c=='\\'){if(pos_>=s_.size())return Fail(Error::syntax);const char e=s_[pos_++];if(e!='"'&&e!='\\')return Fail(Error::noncanonical_escape);out.push_back(e);}else out.push_back(static_cast<char>(c));if(out.size()>4096)return Fail(Error::field_value);}return Fail(Error::syntax);}
bool Number(std::int64_t&out){const std::size_t start=pos_;const bool neg=Take('-');if(pos_>=s_.size())return Fail(Error::syntax);if(s_[pos_]=='0'){++pos_;if(neg)return Fail(Error::negative_zero);if(pos_<s_.size()&&s_[pos_]>='0'&&s_[pos_]<='9')return Fail(Error::unsupported_number);}else{if(s_[pos_]<'1'||s_[pos_]>'9')return Fail(Error::unsupported_number);while(pos_<s_.size()&&s_[pos_]>='0'&&s_[pos_]<='9')++pos_;}if(pos_<s_.size()&&(s_[pos_]=='.'||s_[pos_]=='e'||s_[pos_]=='E'||s_[pos_]=='+'))return Fail(Error::unsupported_number);const auto p=std::from_chars(s_.data()+start,s_.data()+pos_,out);return p.ec==std::errc{}&&p.ptr==s_.data()+pos_?true:Fail(Error::unsupported_number);}
bool Literal(std::string_view x){if(s_.substr(pos_,x.size())!=x)return Fail(Error::syntax);pos_+=x.size();return true;}bool Take(char x){if(pos_<s_.size()&&s_[pos_]==x){++pos_;return true;}return false;}bool Fail(Error e){error_=e;return false;}std::string_view s_;std::size_t pos_{};std::size_t maxDepth_;Error error_{Error::syntax};};
const Value*F(const Value&v,std::string_view key){if(v.kind!=Kind::object)return nullptr;auto i=std::lower_bound(v.object.begin(),v.object.end(),key,[](const auto&a,std::string_view b){return a.first<b;});return i!=v.object.end()&&i->first==key?&i->second:nullptr;}
bool Exact(const Value&v,std::initializer_list<std::string_view>keys){if(v.kind!=Kind::object||v.object.size()!=keys.size())return false;std::vector<std::string_view>w(keys);std::sort(w.begin(),w.end());for(std::size_t i=0;i<w.size();++i)if(v.object[i].first!=w[i])return false;return true;}
bool Exact(const Value&v,std::initializer_list<const char*>keys){std::vector<std::string_view>w;w.reserve(keys.size());for(const char*key:keys)w.emplace_back(key);if(v.kind!=Kind::object||v.object.size()!=w.size())return false;std::sort(w.begin(),w.end());for(std::size_t i=0;i<w.size();++i)if(v.object[i].first!=w[i])return false;return true;}
bool Text(const Value&v,std::size_t min=1,std::size_t max=4096){return v.kind==Kind::string&&v.string.size()>=min&&v.string.size()<=max;}bool Int(const Value&v,std::int64_t min,std::int64_t max){return v.kind==Kind::integer&&v.integer>=min&&v.integer<=max;}bool C(const Value&v,std::string_view s){return v.kind==Kind::string&&v.string==s;}
bool Hash(const Value&v){return Text(v,71,71)&&v.string.starts_with("sha256:")&&std::all_of(v.string.begin()+7,v.string.end(),[](char c){return(c>='0'&&c<='9')||(c>='a'&&c<='f');});}bool Hex(const Value&v,std::size_t n){return Text(v,n*2,n*2)&&std::all_of(v.string.begin(),v.string.end(),[](char c){return(c>='0'&&c<='9')||(c>='a'&&c<='f')||(c>='A'&&c<='F');});}
bool Id(const Value&v){return Text(v,1,128)&&std::all_of(v.string.begin(),v.string.end(),[](char c){return(c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='.'||c=='_'||c==':'||c=='-';});}
bool B64(const Value&v,std::size_t n=0){if(v.kind!=Kind::string)return false;std::vector<unsigned char>b;return DecodeCanonicalBase64Url(v.string,b)&&(!n||b.size()==n);}
bool P256Kid(const Value&spki,std::string&kid){
  if(!B64(spki))return false;std::vector<unsigned char>der;if(!DecodeCanonicalBase64Url(spki.string,der)||der.empty())return false;
  CERT_PUBLIC_KEY_INFO* info=nullptr;DWORD infoBytes=0;
  if(!CryptDecodeObjectEx(X509_ASN_ENCODING,X509_PUBLIC_KEY_INFO,der.data(),static_cast<DWORD>(der.size()),CRYPT_DECODE_ALLOC_FLAG,nullptr,&info,&infoBytes)||!info)return false;
  BCRYPT_KEY_HANDLE key{};const bool imported=CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING,info,0,nullptr,&key)==TRUE;LocalFree(info);if(!imported)return false;
  wchar_t algorithm[64]{};DWORD bytes=0;const bool p256=BCryptGetProperty(key,BCRYPT_ALGORITHM_NAME,reinterpret_cast<PUCHAR>(algorithm),sizeof(algorithm),&bytes,0)>=0&&std::wstring_view(algorithm)==BCRYPT_ECDSA_P256_ALGORITHM;BCryptDestroyKey(key);if(!p256)return false;
  BCRYPT_ALG_HANDLE hashAlgorithm{};BCRYPT_HASH_HANDLE hash{};DWORD objectBytes=0,got=0;std::array<BYTE,32>digest{};
  bool ok=BCryptOpenAlgorithmProvider(&hashAlgorithm,BCRYPT_SHA256_ALGORITHM,nullptr,0)>=0&&BCryptGetProperty(hashAlgorithm,BCRYPT_OBJECT_LENGTH,reinterpret_cast<PUCHAR>(&objectBytes),sizeof(objectBytes),&got,0)>=0;std::vector<BYTE>object(objectBytes);
  if(ok)ok=BCryptCreateHash(hashAlgorithm,&hash,object.data(),objectBytes,nullptr,0,0)>=0;
  if(ok)ok=BCryptHashData(hash,const_cast<PUCHAR>(der.data()),static_cast<ULONG>(der.size()),0)>=0;
  if(ok)ok=BCryptFinishHash(hash,digest.data(),static_cast<ULONG>(digest.size()),0)>=0;
  if(hash)BCryptDestroyHash(hash);if(hashAlgorithm)BCryptCloseAlgorithmProvider(hashAlgorithm,0);if(!ok)return false;
  std::ostringstream out;out<<"sha256:"<<std::hex<<std::setfill('0');for(BYTE byte:digest)out<<std::setw(2)<<static_cast<unsigned>(byte);kid=out.str();return true;
}
bool Iso(const Value&v,std::int64_t&millis){if(!Text(v,24,24))return false;const auto&s=v.string;for(int i:{0,1,2,3,5,6,8,9,11,12,14,15,17,18,20,21,22})if(s[static_cast<std::size_t>(i)]<'0'||s[static_cast<std::size_t>(i)]>'9')return false;if(s[4]!='-'||s[7]!='-'||s[10]!='T'||s[13]!=':'||s[16]!=':'||s[19]!='.'||s[23]!='Z')return false;auto n=[&](int p,int count){int x=0;while(count--)x=x*10+s[static_cast<std::size_t>(p++)]-'0';return x;};int y=n(0,4),m=n(5,2),d=n(8,2),hh=n(11,2),mm=n(14,2),ss=n(17,2),ms=n(20,3);if(y<1970||m<1||m>12||d<1||hh>23||mm>59||ss>59)return false;static constexpr int md[]={31,28,31,30,31,30,31,31,30,31,30,31};const int days=md[m-1]+(m==2&&((y%4==0&&y%100!=0)||y%400==0)?1:0);if(d>days)return false;const int adjusted=y-(m<=2);const int era=(adjusted>=0?adjusted:adjusted-399)/400;const unsigned yoe=static_cast<unsigned>(adjusted-era*400),mp=static_cast<unsigned>(m+(m>2?-3:9));const unsigned doy=(153*mp+2)/5+static_cast<unsigned>(d)-1,doe=yoe*365+yoe/4-yoe/100+doy;const std::int64_t civil=static_cast<std::int64_t>(era)*146097+doe-719468;millis=((civil*24+hh)*60+mm)*60000+ss*1000+ms;return true;}
bool List(const Value&v,std::size_t max,bool stdio=false){if(v.kind!=Kind::array||v.array.size()>max)return false;if(stdio)return v.array.size()==3&&C(v.array[0],"stdin")&&C(v.array[1],"stdout")&&C(v.array[2],"stderr");std::string prior;for(const auto&i:v.array){if(!Id(i)||(!prior.empty()&&i.string<=prior))return false;prior=i.string;}return true;}
Result Dom(std::string_view s,Value&r){if(s.empty())return{false,Error::syntax};if(s.size()>32768)return{false,Error::maximumBytes};return Parser(s,16).Run(&r);}Result Bad(Error e=Error::schema){return{false,e};}
bool Challenge(const Value&r){const auto*issued=F(r,"issuedAt"),*expires=F(r,"expiresAt");return Exact(r,{"expiresAt","issuedAt","nonce","pipeId","protocolVersion","schema","serverCreationTime","serverImageFileId","serverImageHash","serverImageSigner","serverImageVolumeSerial","serverInstanceId","serverPid","serverServiceName","serverServiceSid"})&&C(*F(r,"schema"),"stellar-pipe-challenge-v0.1")&&C(*F(r,"protocolVersion"),"0.1")&&Text(*F(r,"pipeId"),1,256)&&Id(*F(r,"serverServiceName"))&&Text(*F(r,"serverServiceSid"),8,184)&&Int(*F(r,"serverPid"),1,0xffffffffLL)&&Int(*F(r,"serverCreationTime"),1,INT64_MAX)&&Hash(*F(r,"serverImageHash"))&&Hex(*F(r,"serverImageFileId"),16)&&Int(*F(r,"serverImageVolumeSerial"),0,0xffffffffLL)&&Hex(*F(r,"serverImageSigner"),32)&&Id(*F(r,"serverInstanceId"))&&Text(*F(r,"nonce"),43,43)&&B64(*F(r,"nonce"),32)&&issued&&expires&&Int(*issued,0,INT64_MAX)&&Int(*expires,0,INT64_MAX)&&expires->integer>issued->integer&&expires->integer-issued->integer<=50000000;}
bool PipeHeader(const Value&r,std::string&kid){if(!Exact(r,{"alg","keyId","schema"})||!C(*F(r,"alg"),"ES256")||!C(*F(r,"schema"),"stellar-pipe-request-protected-v0.1")||!Hash(*F(r,"keyId")))return false;kid=F(r,"keyId")->string;return true;}
bool PipeBody(const Value&r,const std::string&kid,PipeRequest*out){const auto*i=F(r,"issuedAt"),*e=F(r,"expiresAt");const bool valid=Exact(r,{"action","challengeHash","clientCreationTime","clientImageFileId","clientImageHash","clientImageSigner","clientImageVolumeSerial","clientPid","clientServiceSid","expiresAt","issuedAt","keyId","requestHash","requestId","schema"})&&C(*F(r,"schema"),"stellar-pipe-request-v0.1")&&Id(*F(r,"action"))&&Hash(*F(r,"challengeHash"))&&Id(*F(r,"requestId"))&&Hash(*F(r,"requestHash"))&&Text(*F(r,"clientServiceSid"),8,184)&&Int(*F(r,"clientPid"),1,0xffffffffLL)&&Text(*F(r,"clientCreationTime"),1,32)&&Hash(*F(r,"clientImageHash"))&&Hex(*F(r,"clientImageFileId"),16)&&Int(*F(r,"clientImageVolumeSerial"),0,0xffffffffLL)&&Hex(*F(r,"clientImageSigner"),32)&&C(*F(r,"keyId"),kid)&&i&&e&&Int(*i,0,INT64_MAX)&&Int(*e,0,INT64_MAX)&&e->integer>i->integer&&e->integer-i->integer<=50000000;if(valid&&out)*out={F(r,"action")->string,F(r,"challengeHash")->string,F(r,"requestId")->string,F(r,"requestHash")->string,F(r,"clientServiceSid")->string,F(r,"clientCreationTime")->string,F(r,"clientImageHash")->string,F(r,"clientImageFileId")->string,F(r,"clientImageSigner")->string,F(r,"keyId")->string,static_cast<std::uint32_t>(F(r,"clientPid")->integer),static_cast<std::uint32_t>(F(r,"clientImageVolumeSerial")->integer),static_cast<std::uint64_t>(i->integer),static_cast<std::uint64_t>(e->integer)};return valid;}
bool ContractHeader(const Value&r,std::string&kid){if(!Exact(r,{"alg","kid","typ","version"})||!C(*F(r,"alg"),"ES256")||!C(*F(r,"typ"),"stellar-capability-contract+json")||!Int(*F(r,"version"),1,1)||!Hash(*F(r,"kid")))return false;kid=F(r,"kid")->string;return true;}
bool ReceiptHeader(const Value&r,std::string&kid){if(!Exact(r,{"alg","kid","schema"})||!C(*F(r,"alg"),"ES256")||!C(*F(r,"schema"),"stellar-broker-receipt-protected-v0.1")||!Hash(*F(r,"kid")))return false;kid=F(r,"kid")->string;return true;}
bool ReceiptBody(const Value&r,BrokerReceipt*out){const auto*i=F(r,"issuedAt"),*e=F(r,"expiresAt");const bool valid=Exact(r,{"action","brokerImageHash","brokerService","cleanupEvidenceHash","contractHash","contractId","evidenceHash","expiresAt","hostId","issuedAt","nonce","operationId","releaseHash","requestHash","requestId","runnerHash","schema","status","targetService"})&&C(*F(r,"schema"),"stellar-broker-receipt-v0.1")&&Id(*F(r,"action"))&&Hash(*F(r,"brokerImageHash"))&&Id(*F(r,"brokerService"))&&Hash(*F(r,"cleanupEvidenceHash"))&&Hash(*F(r,"contractHash"))&&Id(*F(r,"contractId"))&&Hash(*F(r,"evidenceHash"))&&Id(*F(r,"hostId"))&&B64(*F(r,"nonce"),32)&&Id(*F(r,"operationId"))&&Hash(*F(r,"releaseHash"))&&Hash(*F(r,"requestHash"))&&Id(*F(r,"requestId"))&&Hash(*F(r,"runnerHash"))&&Id(*F(r,"targetService"))&&i&&e&&Int(*i,0,INT64_MAX)&&Int(*e,0,INT64_MAX)&&e->integer>=i->integer&&e->integer-i->integer<=50000000&&(C(*F(r,"status"),"completed")||C(*F(r,"status"),"refused"));if(valid&&out)*out={F(r,"action")->string,F(r,"brokerImageHash")->string,F(r,"brokerService")->string,F(r,"cleanupEvidenceHash")->string,F(r,"contractHash")->string,F(r,"contractId")->string,F(r,"evidenceHash")->string,F(r,"hostId")->string,F(r,"nonce")->string,F(r,"operationId")->string,F(r,"releaseHash")->string,F(r,"requestHash")->string,F(r,"requestId")->string,F(r,"runnerHash")->string,F(r,"status")->string,F(r,"targetService")->string,static_cast<std::uint64_t>(i->integer),static_cast<std::uint64_t>(e->integer)};return valid;}
bool Audience(const Value&r){return Exact(r,{"installId","machineId","service"})&&Id(*F(r,"installId"))&&Id(*F(r,"machineId"))&&C(*F(r,"service"),"aegis-stellar-sandbox");}
bool Requests(const Value&r){if(!Exact(r,{"buildLockHash","imageHash","inputHash","packageHash","requestHash","runnerHash","sourceHash","toolchainHash"}))return false;for(const auto&i:r.object)if(!Hash(i.second))return false;return true;}
bool Target(const Value&r){const auto*p=F(r,"profile");return Exact(r,{"abi","entrySymbol","platform","profile"})&&C(*F(r,"abi"),"stellar-win64-v0.1")&&Id(*F(r,"entrySymbol"))&&C(*F(r,"platform"),"windows-x86_64-msvc")&&p&&p->kind==Kind::string&&(p->string=="stellar-lab-v0"||p->string=="stellar-native-core-v0");}
bool Effects(const Value&r){if(!Exact(r,{"capabilities","imports","manifestHash","runnerImportsHash"})||!List(*F(r,"capabilities"),16)||!Hash(*F(r,"manifestHash"))||!Hash(*F(r,"runnerImportsHash")))return false;const auto*i=F(r,"imports");if(!i||i->kind!=Kind::array||i->array.size()>16)return false;std::string prior;for(const auto&e:i->array){if(!Exact(e,{"dll","symbols"})||!Text(*F(e,"dll"),5,128)||!List(*F(e,"symbols"),64))return false;const auto&dll=F(e,"dll")->string;if(!std::all_of(dll.begin(),dll.end(),[](char c){return(c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='_'||c=='.'||c=='-';})||dll.size()<4)return false;std::string suffix=dll.substr(dll.size()-4);std::transform(suffix.begin(),suffix.end(),suffix.begin(),[](char c){return static_cast<char>(c>='A'&&c<='Z'?c-'A'+'a':c);});if(suffix!=".dll"||(!prior.empty()&&dll<=prior))return false;prior=dll;}return true;}
bool Policy(const Value&r){const auto*a=F(r,"appContainer");return Exact(r,{"appContainer","childProcesses","filesystem","homeostasis","inheritedHandles","network"})&&a&&a->kind==Kind::boolean&&a->boolean&&C(*F(r,"childProcesses"),"deny")&&C(*F(r,"filesystem"),"stdio-only")&&C(*F(r,"homeostasis"),"NOT_EVALUATED")&&List(*F(r,"inheritedHandles"),3,true)&&C(*F(r,"network"),"deny");}
bool Resources(const Value&r){return Exact(r,{"activeProcesses","cpuTimeMs","memoryBytes","outputBytes","wallTimeMs"})&&Int(*F(r,"activeProcesses"),1,1)&&Int(*F(r,"cpuTimeMs"),1,2000)&&Int(*F(r,"memoryBytes"),1048576,134217728)&&Int(*F(r,"outputBytes"),1,65536)&&Int(*F(r,"wallTimeMs"),1,5000);}
bool ContractBody(const Value&r){std::int64_t issued=0,notBefore=0,expires=0;if(!Exact(r,{"bindings","contractId","executionNonce","expiresAt","issuedAt","issuer","notBefore","schema"})||!C(*F(r,"schema"),"stellar.capability-contract/v0.1")||!Id(*F(r,"contractId"))||!B64(*F(r,"executionNonce"),32)||!Iso(*F(r,"issuedAt"),issued)||!Iso(*F(r,"notBefore"),notBefore)||!Iso(*F(r,"expiresAt"),expires)||notBefore!=issued||expires<=issued||expires-issued>60000)return false;const auto&issuer=*F(r,"issuer");if(!Exact(issuer,{"role","subject","tenantId"})||!C(*F(issuer,"role"),"service.stellar.contract.issue")||!Id(*F(issuer,"subject"))||!Id(*F(issuer,"tenantId")))return false;const auto&b=*F(r,"bindings");return Exact(b,{"audience","effects","policy","request","resources","target"})&&Audience(*F(b,"audience"))&&Effects(*F(b,"effects"))&&Policy(*F(b,"policy"))&&Requests(*F(b,"request"))&&Resources(*F(b,"resources"))&&Target(*F(b,"target"));}
bool Service(const Value&v){return Text(v,12,140)&&v.string.starts_with("NT SERVICE\\")&&std::all_of(v.string.begin()+11,v.string.end(),[](char c){return(c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='.'||c=='_'||c=='-'||c==' ';});}
bool Pipe(const Value&v){return Text(v,10,140)&&v.string.starts_with("\\\\.\\pipe\\")&&std::all_of(v.string.begin()+9,v.string.end(),[](char c){return(c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='.'||c=='_'||c=='-';});}
bool Cng(const Value&v){const auto slash=v.kind==Kind::string?v.string.find('\\'):std::string::npos;return Text(v,3,257)&&slash!=std::string::npos&&slash>0&&slash+1<v.string.size()&&std::all_of(v.string.begin(),v.string.end(),[](char c){return(c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9')||c==' '||c=='.'||c=='_'||c=='-'||c=='\\';});}
bool Path(const Value&v){return Text(v,4,260)&&v.string.size()>3&&((v.string[0]>='A'&&v.string[0]<='Z')||(v.string[0]>='a'&&v.string[0]<='z'))&&v.string[1]==':'&&v.string[2]=='\\'&&std::none_of(v.string.begin()+3,v.string.end(),[](char c){return c=='/'||c==':'||c=='*'||c=='?'||c=='\"'||c=='<'||c=='>'||c=='|';})&&v.string.find("\\\\") == std::string::npos&&v.string.find("\\..\\") == std::string::npos;}
bool Thumbprint(const Value&v){return Text(v,40,64)&&std::all_of(v.string.begin(),v.string.end(),[](char c){return(c>='0'&&c<='9')||(c>='A'&&c<='F');});}
bool PolicyHeader(const Value&r,std::string&kid){if(!Exact(r,{"alg","kid","typ","version"})||!C(*F(r,"alg"),"ES256")||!C(*F(r,"typ"),"stellar-custodian-gateway-policy+json")||!Int(*F(r,"version"),1,1)||!Hash(*F(r,"kid")))return false;kid=F(r,"kid")->string;return true;}
bool Gateway(const Value&r,CustodianGatewayPin&out){if(!Exact(r,{"account","imageFileId","imagePath","imageSha256","imageVolumeSerial","serviceName","signerThumbprint"})||!Service(*F(r,"account"))||!Hex(*F(r,"imageFileId"),16)||!Path(*F(r,"imagePath"))||!Hash(*F(r,"imageSha256"))||!Int(*F(r,"imageVolumeSerial"),0,0xffffffffLL)||!Id(*F(r,"serviceName"))||!Thumbprint(*F(r,"signerThumbprint")))return false;out={F(r,"account")->string,F(r,"imageFileId")->string,F(r,"imagePath")->string,F(r,"imageSha256")->string,F(r,"serviceName")->string,F(r,"signerThumbprint")->string,static_cast<std::uint32_t>(F(r,"imageVolumeSerial")->integer)};return true;}
bool CustodianPolicyBody(const Value&r,CustodianGatewayPolicy&out){std::int64_t issued=0,expires=0;if(!Exact(r,{"audience","custodian","expiresAt","gateway","issuedAt","policyId","requestSigner","schema"})||!C(*F(r,"schema"),"stellar.custodian-gateway-policy/v0.1")||!Id(*F(r,"policyId"))||!Iso(*F(r,"issuedAt"),issued)||!Iso(*F(r,"expiresAt"),expires))return false;const auto&a=*F(r,"audience"),&c=*F(r,"custodian"),&q=*F(r,"requestSigner");CustodianGatewayPin gateway;if(!Exact(a,{"installId","machineId"})||!Id(*F(a,"installId"))||!Id(*F(a,"machineId"))||!Exact(c,{"account","cngKeyReference","pipe"})||!Service(*F(c,"account"))||!Cng(*F(c,"cngKeyReference"))||!Pipe(*F(c,"pipe"))||!Exact(q,{"kid","publicKeySpki"})||!Hash(*F(q,"kid"))||!B64(*F(q,"publicKeySpki"))||!Gateway(*F(r,"gateway"),gateway))return false;out={F(a,"installId")->string,F(a,"machineId")->string,F(c,"account")->string,F(c,"cngKeyReference")->string,F(c,"pipe")->string,F(r,"policyId")->string,F(q,"kid")->string,F(q,"publicKeySpki")->string,static_cast<std::uint64_t>(issued),static_cast<std::uint64_t>(expires),std::move(gateway)};return true;}
Result Envelope(std::string_view input,std::string_view schema,bool contract,SignedEnvelope*decoded){Value root;auto result=Dom(input,root);if(!result.accepted)return result;if(!Exact(root,{"payload","protected","schema","signature"})||!C(*F(root,"schema"),schema)||!Text(*F(root,"protected"),2,32768)||!Text(*F(root,"payload"),2,32768)||!Text(*F(root,"signature"),86,86))return Bad();std::vector<unsigned char>hb,pb,sig;if(!DecodeCanonicalBase64Url(F(root,"protected")->string,hb)||!DecodeCanonicalBase64Url(F(root,"payload")->string,pb)||!DecodeCanonicalBase64Url(F(root,"signature")->string,sig,64)||sig.size()!=64)return Bad(Error::base64url);std::string h(hb.begin(),hb.end()),p(pb.begin(),pb.end()),kid;Value hv,pv;result=Dom(h,hv);if(!result.accepted)return result;result=Dom(p,pv);if(!result.accepted)return result;PipeRequest request;if(!(contract?ContractHeader(hv,kid):PipeHeader(hv,kid))||!(contract?ContractBody(pv):PipeBody(pv,kid,&request)))return Bad();if(decoded)*decoded={h,p,F(root,"protected")->string,F(root,"payload")->string,kid,std::move(sig),std::move(request)};return{true,Error::none};}
bool CustodianIssuanceRequestBody(const Value&r,CustodianIssuanceRequest&out){
  if(!Exact(r,{"action","requestId","schema","signingInput","signingInputHash"})||!C(*F(r,"schema"),"stellar.custodian-issuance-request/v0.1")||!C(*F(r,"action"),"issue-capability-contract")||!Id(*F(r,"requestId"))||!B64(*F(r,"signingInput"))||!Hash(*F(r,"signingInputHash")))return false;
  std::vector<unsigned char> decoded;if(!DecodeCanonicalBase64Url(F(r,"signingInput")->string,decoded,32768)||decoded.empty())return false;
  out={F(r,"requestId")->string,F(r,"signingInput")->string,F(r,"signingInputHash")->string};return true;
}
bool CustodianIssuanceResultBody(const Value&r,CustodianIssuanceResult&out){
  if(!Exact(r,{"keyId","refusalCode","requestId","schema","signature","signingInputHash","status"})||!C(*F(r,"schema"),"stellar.custodian-issuance-result/v0.1")||!Id(*F(r,"requestId"))||!Hash(*F(r,"signingInputHash"))||!Hash(*F(r,"keyId"))||!(C(*F(r,"status"),"issued")||C(*F(r,"status"),"refused"))||!Text(*F(r,"refusalCode"),0,128)||!Text(*F(r,"signature"),0,86))return false;
  const bool issued=C(*F(r,"status"),"issued");if(issued?(!F(r,"refusalCode")->string.empty()||!B64(*F(r,"signature"),64)):(!F(r,"signature")->string.empty()||!Id(*F(r,"refusalCode"))))return false;
  std::vector<unsigned char> signature;if(issued&&!DecodeCanonicalBase64Url(F(r,"signature")->string,signature,64))return false;
  out={F(r,"requestId")->string,F(r,"signingInputHash")->string,F(r,"keyId")->string,F(r,"status")->string,F(r,"refusalCode")->string,std::move(signature)};return true;
}
bool LabGatewayIdentity(const Value&r,LabGatewayBridgeIdentity&out){
  if(!Exact(r,{"account","executablePath","pipe","serviceName"})||!Service(*F(r,"account"))||!Path(*F(r,"executablePath"))||!Pipe(*F(r,"pipe"))||!Id(*F(r,"serviceName")))return false;
  out={F(r,"account")->string,F(r,"executablePath")->string,F(r,"pipe")->string,F(r,"serviceName")->string};return true;
}
bool LabGatewayBridgeRequestBody(const Value&r,LabGatewayBridgeRequest&out){
  if(!Exact(r,{"action","bridge","cngKeyReference","installId","machineId","requestId","schema","signingInput","signingInputHash"})||!C(*F(r,"schema"),"stellar.lab-gateway-bridge-request/v0.1")||!C(*F(r,"action"),"sign-capability-contract")||!Cng(*F(r,"cngKeyReference"))||!Id(*F(r,"installId"))||!Id(*F(r,"machineId"))||!Id(*F(r,"requestId"))||!B64(*F(r,"signingInput"))||!Hash(*F(r,"signingInputHash")))return false;
  std::vector<unsigned char> bytes;if(!DecodeCanonicalBase64Url(F(r,"signingInput")->string,bytes,32768)||bytes.empty())return false;
  LabGatewayBridgeIdentity bridge;if(!LabGatewayIdentity(*F(r,"bridge"),bridge))return false;
  out={std::move(bridge),F(r,"cngKeyReference")->string,F(r,"installId")->string,F(r,"machineId")->string,F(r,"requestId")->string,F(r,"signingInput")->string,F(r,"signingInputHash")->string};return true;
}
bool LabGatewayBridgeResultBody(const Value&r,LabGatewayBridgeResult&out){
  if(!Exact(r,{"keyId","refusalCode","requestId","schema","signature","signingInputHash","status"})||!C(*F(r,"schema"),"stellar.lab-gateway-bridge-result/v0.1")||!Hash(*F(r,"keyId"))||!Id(*F(r,"requestId"))||!Text(*F(r,"refusalCode"),0,128)||!Text(*F(r,"signature"),0,86)||!Hash(*F(r,"signingInputHash"))||!(C(*F(r,"status"),"issued")||C(*F(r,"status"),"refused")))return false;
  const bool issued=C(*F(r,"status"),"issued");if(issued?(!F(r,"refusalCode")->string.empty()||!B64(*F(r,"signature"),64)):(!F(r,"signature")->string.empty()||!Id(*F(r,"refusalCode"))))return false;
  std::vector<unsigned char> signature;if(issued&&!DecodeCanonicalBase64Url(F(r,"signature")->string,signature,64))return false;
  out={F(r,"keyId")->string,F(r,"refusalCode")->string,F(r,"requestId")->string,F(r,"signingInputHash")->string,F(r,"status")->string,std::move(signature)};return true;
}
bool RequestSignerRegistryBody(const Value&r,RequestSignerRegistry&out){
  if(!Exact(r,{"registryId","schema","signers"})||!C(*F(r,"schema"),"stellar.request-signer-registry/v0.1")||!Id(*F(r,"registryId")))return false;
  const auto*items=F(r,"signers");if(!items||items->kind!=Kind::array||items->array.empty()||items->array.size()>32)return false;
  std::string prior;std::vector<RequestSignerRegistryEntry> signers;signers.reserve(items->array.size());
  for(const auto&item:items->array){std::string calculated;if(!Exact(item,{"kid","publicKeySpki"})||!Hash(*F(item,"kid"))||!P256Kid(*F(item,"publicKeySpki"),calculated)||calculated!=F(item,"kid")->string||(!prior.empty()&&F(item,"kid")->string<=prior))return false;prior=F(item,"kid")->string;signers.push_back({F(item,"kid")->string,F(item,"publicKeySpki")->string});}
  out={F(r,"registryId")->string,std::move(signers)};return true;
}
}
bool DecodeCanonicalBase64Url(std::string_view input,std::vector<unsigned char>&out,std::size_t maximumBytes){if(input.empty()||input.find('=')!=std::string_view::npos||input.size()%4==1)return false;for(char c:input)if(!((c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='-'||c=='_'))return false;out.clear();std::uint32_t acc=0;unsigned bits=0;for(char c:input){const unsigned v=c>='A'&&c<='Z'?static_cast<unsigned>(c-'A'):c>='a'&&c<='z'?static_cast<unsigned>(c-'a'+26):c>='0'&&c<='9'?static_cast<unsigned>(c-'0'+52):c=='-'?62u:63u;acc=(acc<<6)|v;bits+=6;if(bits>=8){bits-=8;out.push_back(static_cast<unsigned char>((acc>>bits)&0xff));if(out.size()>maximumBytes)return false;}}if(bits&&(acc&((1u<<bits)-1u)))return false;return (out.size()*8+5)/6==input.size();}
Result ParseCanonical(std::string_view input,std::size_t maximumBytes,std::size_t maximumDepth){if(input.empty())return{false,Error::syntax};if(input.size()>maximumBytes)return{false,Error::maximumBytes};return Parser(input,maximumDepth).Run();}
Result ParseCanonicalChallenge(std::string_view input,PipeChallenge*out){Value root;auto r=Dom(input,root);if(!r.accepted||!Challenge(root))return r.accepted?Bad():r;if(out)*out={F(root,"pipeId")->string,F(root,"serverServiceName")->string,F(root,"serverServiceSid")->string,F(root,"serverImageHash")->string,F(root,"serverImageFileId")->string,F(root,"serverImageSigner")->string,F(root,"serverInstanceId")->string,F(root,"nonce")->string,static_cast<std::uint32_t>(F(root,"serverPid")->integer),static_cast<std::uint32_t>(F(root,"serverImageVolumeSerial")->integer),static_cast<std::uint64_t>(F(root,"serverCreationTime")->integer),static_cast<std::uint64_t>(F(root,"issuedAt")->integer),static_cast<std::uint64_t>(F(root,"expiresAt")->integer)};return r;}
Result ParseCanonicalSignedRequest(std::string_view input,SignedEnvelope*decoded){return Envelope(input,"stellar-pipe-request-envelope-v0.1",false,decoded);}
Result ParseCanonicalCapabilityContract(std::string_view input,SignedEnvelope*decoded){return Envelope(input,"stellar.capability-contract-envelope/v0.1",true,decoded);}
Result ParseCanonicalCustodianGatewayPolicy(std::string_view input,CustodianGatewayPolicyEnvelope*out){Value root;auto result=Dom(input,root);if(!result.accepted)return result;if(!Exact(root,{"payload","protected","schema","signature"})||!C(*F(root,"schema"),"stellar.custodian-gateway-policy-envelope/v0.1")||!Text(*F(root,"protected"),2,32768)||!Text(*F(root,"payload"),2,32768)||!Text(*F(root,"signature"),86,86))return Bad();std::vector<unsigned char>header,payload,signature;if(!DecodeCanonicalBase64Url(F(root,"protected")->string,header)||!DecodeCanonicalBase64Url(F(root,"payload")->string,payload)||!DecodeCanonicalBase64Url(F(root,"signature")->string,signature,64)||signature.size()!=64)return Bad(Error::base64url);Value h,p;result=Dom(std::string_view(reinterpret_cast<const char*>(header.data()),header.size()),h);if(!result.accepted)return result;result=Dom(std::string_view(reinterpret_cast<const char*>(payload.data()),payload.size()),p);if(!result.accepted)return result;std::string kid;CustodianGatewayPolicy policy;if(!PolicyHeader(h,kid)||!CustodianPolicyBody(p,policy))return Bad();if(out)*out={F(root,"protected")->string,F(root,"payload")->string,kid,std::move(signature),std::move(policy)};return{true,Error::none};}
Result ParseCanonicalCustodianIssuanceRequest(std::string_view input,CustodianIssuanceRequest*out){Value root;auto result=Dom(input,root);if(!result.accepted)return result;CustodianIssuanceRequest request;if(!CustodianIssuanceRequestBody(root,request))return Bad();if(out)*out=std::move(request);return result;}
Result ParseCanonicalCustodianIssuanceResult(std::string_view input,CustodianIssuanceResult*out){Value root;auto result=Dom(input,root);if(!result.accepted)return result;CustodianIssuanceResult response;if(!CustodianIssuanceResultBody(root,response))return Bad();if(out)*out=std::move(response);return result;}
Result ParseCanonicalLabGatewayBridgeRequest(std::string_view input,LabGatewayBridgeRequest*out){Value root;auto result=Dom(input,root);if(!result.accepted)return result;LabGatewayBridgeRequest request;if(!LabGatewayBridgeRequestBody(root,request))return Bad();if(out)*out=std::move(request);return result;}
Result ParseCanonicalLabGatewayBridgeResult(std::string_view input,LabGatewayBridgeResult*out){Value root;auto result=Dom(input,root);if(!result.accepted)return result;LabGatewayBridgeResult response;if(!LabGatewayBridgeResultBody(root,response))return Bad();if(out)*out=std::move(response);return result;}
Result ParseCanonicalRequestSignerRegistry(std::string_view input,RequestSignerRegistry*out){Value root;auto result=Dom(input,root);if(!result.accepted)return result;RequestSignerRegistry registry;if(!RequestSignerRegistryBody(root,registry))return Bad();if(out)*out=std::move(registry);return result;}
Result ParseCanonicalBrokerReceipt(std::string_view input,BrokerReceiptEnvelope*out){Value root;auto result=Dom(input,root);if(!result.accepted)return result;if(!Exact(root,{"payload","protected","schema","signature"})||!C(*F(root,"schema"),"stellar-broker-receipt-envelope-v0.1")||!Text(*F(root,"protected"),2,32768)||!Text(*F(root,"payload"),2,32768)||!Text(*F(root,"signature"),86,86))return Bad();std::vector<unsigned char>hb,pb,sig;if(!DecodeCanonicalBase64Url(F(root,"protected")->string,hb)||!DecodeCanonicalBase64Url(F(root,"payload")->string,pb)||!DecodeCanonicalBase64Url(F(root,"signature")->string,sig,64)||sig.size()!=64)return Bad(Error::base64url);std::string header(hb.begin(),hb.end()),payload(pb.begin(),pb.end()),kid;Value hv,pv;result=Dom(header,hv);if(!result.accepted)return result;result=Dom(payload,pv);if(!result.accepted)return result;BrokerReceipt receipt;if(!ReceiptHeader(hv,kid)||!ReceiptBody(pv,&receipt))return Bad();if(out)*out={header,payload,F(root,"protected")->string,F(root,"payload")->string,kid,std::move(sig),std::move(receipt)};return{true,Error::none};}
Result ParseCanonicalKeyRegistryRecord(std::string_view input,
                                       KeyRegistryRecord &out) {
  Value r;
  auto result = Dom(input, r);
  if (!result.accepted)
    return result;
  if (!Exact(r, {"kid", "kind", "notAfter", "notBefore", "overlapUntil",
                 "previousHash", "revokedAt", "schema", "sequence", "signature",
                 "spki"}) ||
      !C(*F(r, "schema"), "stellar.key-registry-record/v0.1") ||
      !Id(*F(r, "kind")) || !Int(*F(r, "sequence"), 1, INT64_MAX) ||
      !Hash(*F(r, "previousHash")) || !Hash(*F(r, "kid")) ||
      !B64(*F(r, "spki")) || !Int(*F(r, "notBefore"), 0, INT64_MAX) ||
      !Int(*F(r, "notAfter"), 1, INT64_MAX) ||
      !Int(*F(r, "overlapUntil"), 0, INT64_MAX) ||
      !Int(*F(r, "revokedAt"), 0, INT64_MAX) || !B64(*F(r, "signature"), 64) ||
      F(r, "notAfter")->integer <= F(r, "notBefore")->integer)
    return Bad();
  const auto &kind = F(r, "kind")->string;
  if (kind != "install" && kind != "rotate" && kind != "revoke")
    return Bad();
  out = {};
  out.canonicalSigned = std::string(input);
  out.kind = kind;
  out.previousHash = F(r, "previousHash")->string;
  out.kid = F(r, "kid")->string;
  out.spki = F(r, "spki")->string;
  out.signature = F(r, "signature")->string;
  out.sequence = static_cast<std::uint64_t>(F(r, "sequence")->integer);
  out.notBefore = static_cast<std::uint64_t>(F(r, "notBefore")->integer);
  out.notAfter = static_cast<std::uint64_t>(F(r, "notAfter")->integer);
  out.overlapUntil = static_cast<std::uint64_t>(F(r, "overlapUntil")->integer);
  out.revokedAt = static_cast<std::uint64_t>(F(r, "revokedAt")->integer);
  out.canonicalUnsigned =
      "{\"kid\":\"" + out.kid + "\",\"kind\":\"" + out.kind +
      "\",\"notAfter\":" + std::to_string(out.notAfter) +
      ",\"notBefore\":" + std::to_string(out.notBefore) +
      ",\"overlapUntil\":" + std::to_string(out.overlapUntil) +
      ",\"previousHash\":\"" + out.previousHash +
      "\",\"revokedAt\":" + std::to_string(out.revokedAt) +
      ",\"schema\":\"stellar.key-registry-record/v0.1\",\"sequence\":" +
      std::to_string(out.sequence) + ",\"spki\":\"" + out.spki + "\"}";
  return result;
}
Result ParseCanonicalReplayRecord(std::string_view input, ReplayRecord &out) {
  Value r;
  auto result = Dom(input, r);
  if (!result.accepted)
    return result;
  const auto keys = {"action",          "brokerCanonicalReceipt",
                     "brokerImageHash", "brokerReceiptHash",
                     "brokerService",   "brokerSignature",
                     "cleanupEvidenceHash", "contractHash", "contractId",
                     "evidenceHash",
                     "hostId",          "journalRecordSignature",
                     "nonce",           "operationId",
                     "previousHash",    "recordHash",
                     "releaseHash",     "requestHash",
                     "requestId",       "runnerHash",
                     "schema",          "sequence",
                     "state",           "targetService"};
  if (!Exact(r, keys) ||
      !C(*F(r, "schema"), "stellar.replay-journal-record/v0.2") ||
      !Id(*F(r, "action")) ||
      !Text(*F(r, "brokerCanonicalReceipt"), 0, 32768) ||
      !Hash(*F(r, "brokerImageHash")) || !Hash(*F(r, "brokerReceiptHash")) ||
      !Id(*F(r, "brokerService")) || !Text(*F(r, "brokerSignature"), 0, 86) ||
      !Hash(*F(r, "cleanupEvidenceHash")) || !Hash(*F(r, "contractHash")) ||
      !Id(*F(r, "contractId")) || !Hash(*F(r, "evidenceHash")) ||
      !Id(*F(r, "hostId")) || !B64(*F(r, "journalRecordSignature"), 64) ||
      !B64(*F(r, "nonce"), 32) || !Id(*F(r, "operationId")) ||
      !Hash(*F(r, "previousHash")) || !Hash(*F(r, "recordHash")) ||
      !Hash(*F(r, "releaseHash")) || !Hash(*F(r, "requestHash")) ||
      !Id(*F(r, "requestId")) || !Hash(*F(r, "runnerHash")) ||
      !Int(*F(r, "sequence"), 1, INT64_MAX) || !Id(*F(r, "state")) ||
      !Id(*F(r, "targetService")))
    return Bad();
  const std::string state = F(r, "state")->string;
  if (state != "ISSUED" && state != "RESERVED" && state != "DISPATCHED" &&
      state != "RECONCILING" && state != "CONSUMED" && state != "REFUSED")
    return Bad();
  const bool consumed = state == "CONSUMED";
  if (consumed ? (!B64(*F(r, "brokerCanonicalReceipt")) ||
                  !B64(*F(r, "brokerSignature"), 64))
               : (!F(r, "brokerCanonicalReceipt")->string.empty() ||
                  !F(r, "brokerSignature")->string.empty()))
    return Bad();
  out = {};
  out.canonicalSigned = std::string(input);
  out.state = state;
  out.requestId = F(r, "requestId")->string;
  out.requestHash = F(r, "requestHash")->string;
  out.contractId = F(r, "contractId")->string;
  out.contractHash = F(r, "contractHash")->string;
  out.nonce = F(r, "nonce")->string;
  out.operationId = F(r, "operationId")->string;
  out.releaseHash = F(r, "releaseHash")->string;
  out.action = F(r, "action")->string;
  out.evidenceHash = F(r, "evidenceHash")->string;
  out.cleanupEvidenceHash = F(r, "cleanupEvidenceHash")->string;
  out.hostId = F(r, "hostId")->string;
  out.targetService = F(r, "targetService")->string;
  out.brokerService = F(r, "brokerService")->string;
  out.brokerImageHash = F(r, "brokerImageHash")->string;
  out.runnerHash = F(r, "runnerHash")->string;
  out.previousHash = F(r, "previousHash")->string;
  out.recordHash = F(r, "recordHash")->string;
  out.brokerCanonicalReceipt = F(r, "brokerCanonicalReceipt")->string;
  out.brokerReceiptHash = F(r, "brokerReceiptHash")->string;
  out.brokerSignature = F(r, "brokerSignature")->string;
  out.journalRecordSignature = F(r, "journalRecordSignature")->string;
  out.sequence = static_cast<std::uint64_t>(F(r, "sequence")->integer);
  out.canonicalUnsigned =
      "{\"action\":\"" + out.action + "\",\"brokerCanonicalReceipt\":\"" +
      out.brokerCanonicalReceipt + "\",\"brokerImageHash\":\"" +
      out.brokerImageHash + "\",\"brokerReceiptHash\":\"" +
      out.brokerReceiptHash + "\",\"brokerService\":\"" + out.brokerService +
      "\",\"brokerSignature\":\"" + out.brokerSignature +
      "\",\"cleanupEvidenceHash\":\"" + out.cleanupEvidenceHash +
      "\",\"contractHash\":\"" + out.contractHash + "\",\"contractId\":\"" +
      out.contractId + "\",\"evidenceHash\":\"" + out.evidenceHash +
      "\",\"hostId\":\"" + out.hostId + "\",\"nonce\":\"" +
      out.nonce + "\",\"operationId\":\"" + out.operationId +
      "\",\"previousHash\":\"" + out.previousHash + "\",\"releaseHash\":\"" +
      out.releaseHash + "\",\"requestHash\":\"" + out.requestHash +
      "\",\"requestId\":\"" + out.requestId + "\",\"runnerHash\":\"" +
      out.runnerHash +
      "\",\"schema\":\"stellar.replay-journal-record/v0.2\",\"sequence\":" +
      std::to_string(out.sequence) + ",\"state\":\"" + out.state +
      "\",\"targetService\":\"" + out.targetService + "\"}";
  return result;
}
}
