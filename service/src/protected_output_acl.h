#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>
namespace stellar::discovery {
bool ProtectedOutputAclAllowed(PSECURITY_DESCRIPTOR descriptor,PSID explicitlyApprovedSid,std::string&error);
bool ProtectedOutputHandleAllowed(HANDLE directory,PSID explicitlyApprovedSid,std::string&error);
}
