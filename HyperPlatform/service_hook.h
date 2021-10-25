#pragma once
#include"include/vector.hpp"
#include"FakePage.h"

struct ServiceHook : ICFakePage
{
	virtual void Construct() override;
	virtual void Destruct() override;
	PVOID DetourFunc;
	PVOID *TrampolineFunc;
	bool isEverythignSuc = false;
};

__kernel_entry NTSYSCALLAPI NTSTATUS NtOpenProcess(
	PHANDLE            ProcessHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PCLIENT_ID         ClientId
);

using NtOpenProcessType = decltype(&NtOpenProcess);

void AddServiceHook(PVOID HookFuncStart, PVOID Detour, PVOID *TramPoline);

void RemoveServiceHook();


//Example


// 
//hook NtOpenProcess
// 
inline NtOpenProcessType OriNtOpenProcess;
NTSTATUS DetourNtOpenProcess(
	PHANDLE            ProcessHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PCLIENT_ID         ClientId
);