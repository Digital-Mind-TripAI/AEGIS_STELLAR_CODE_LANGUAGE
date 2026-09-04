#include "scm_readiness.h"
#include <windows.h>
#include <winsvc.h>
using namespace stellar::service;
namespace {
struct Mock final : ScmConfigurationOs {
  int fault{};
  bool Read(const wchar_t *name, ScmDecodedConfiguration &v) override {
    const bool broker = wcscmp(name,L"AegisStellarExecutionBroker")==0;
    v.serviceType=SERVICE_WIN32_OWN_PROCESS;v.startType=SERVICE_AUTO_START;
    v.errorControl=SERVICE_ERROR_NORMAL;
    v.account=broker?L"NT SERVICE\\AegisStellarExecutionBroker":L"NT SERVICE\\AegisStellarCustodian";
    v.binaryPath=broker?L"\"C:\\Program Files\\AEGIS\\Stellar\\v0.1\\bin\\AegisStellarExecutionBroker.exe\"":L"\"C:\\Program Files\\AEGIS\\Stellar\\v0.1\\bin\\AegisStellarCustodian.exe\"";
    v.serviceSidType=SERVICE_SID_TYPE_UNRESTRICTED;v.delayedAutoStart=true;
    v.failureOnNonCrash=true;v.runtimeStateValid=true;v.exactDacl=true;
    v.requiredPrivileges={L"SeImpersonatePrivilege",L"SeChangeNotifyPrivilege"};
    v.failureResetSeconds=86400;
    v.failureActions={{SC_ACTION_RESTART,5000},{SC_ACTION_RESTART,15000},{SC_ACTION_NONE,0}};
    if(!broker)switch(fault){case 1:v.serviceType=SERVICE_WIN32_SHARE_PROCESS;break;case 2:v.startType=SERVICE_DEMAND_START;break;case 3:v.errorControl=SERVICE_ERROR_IGNORE;break;case 4:v.account=L"wrong";break;case 5:v.binaryPath=L"wrong";break;case 6:v.dependencies={L"dep"};break;case 7:v.serviceSidType=SERVICE_SID_TYPE_NONE;break;case 8:v.delayedAutoStart=false;break;case 9:v.failureOnNonCrash=false;break;case 10:v.runtimeStateValid=false;break;case 11:v.requiredPrivileges.pop_back();break;case 12:v.failureResetSeconds=1;break;case 13:v.failureActions[0].delayMs=1;break;case 14:v.exactDacl=false;break;case 15:return false;}
    return true;
  }
};
}
int main(){Mock valid;if(!VerifyBothServiceScmConfigurationWithOs(valid))return 1;for(int fault=1;fault<=15;++fault){Mock bad;bad.fault=fault;if(VerifyBothServiceScmConfigurationWithOs(bad))return 2;}return 0;}
