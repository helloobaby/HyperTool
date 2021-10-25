#include"service_hook.h"
#include"include/stdafx.h"
#include"include/vector.hpp"
extern "C"
{
#include"kernel-hook/khook/khook/hk.h"
}

using std::vector; 
vector<ServiceHook> vServcieHook;

void ServiceHook::Construct()
{
	if (!this->DetourFunc || !this->TrampolineFunc || !this->fp.GuestVA)
	{
		Log("DetourFunc or TrampolineFunc or fp.GuestVA is null!\n");
		Log("DetourFunc %p\nTrampolineFunc %p\nfp.GuestVA %p\n",
			this->DetourFunc, this->TrampolineFunc, this->fp.GuestVA);
		return;
	}
	NTSTATUS Status = HkDetourFunction((this->fp).GuestVA, this->DetourFunc, this->TrampolineFunc);

	if (!NT_SUCCESS(Status)) {
		Log("HkDetourFunction Failed %x\n", Status);
		return;
	}

	//获得这个页的开始地址
	auto tmp = (PVOID)(((ULONG_PTR)(this->fp).GuestVA >> 12) << 12);
	this->fp.GuestPA = MmGetPhysicalAddress(tmp);
	this->fp.PageContent = ExAllocatePoolWithQuota(NonPagedPool, PAGE_SIZE);
	memcpy(this->fp.PageContent, this->fp.GuestVA, PAGE_SIZE);
	this->fp.PageContentPA = MmGetPhysicalAddress(this->fp.PageContent);
	if (!fp.GuestPA.QuadPart || !fp.PageContentPA.QuadPart)
	{
		HkRestoreFunction((this->fp).GuestVA, this->TrampolineFunc);
		Log("MmGetPhysicalAddress error %s %d\n",__func__,__LINE__);
		return;
	}

	this->isEverythignSuc = true;

}

void ServiceHook::Destruct()
{
	if (!this->isEverythignSuc)
		return;

	NTSTATUS Status = HkRestoreFunction((this->fp).GuestVA, this->TrampolineFunc);
	if (!NT_SUCCESS(Status)) {
		Log("HkRestoreFunction Failed %x\n", Status);
		return;
	}
}

void AddServiceHook(PVOID HookFuncStart, PVOID Detour, PVOID *TramPoline)
{
	ServiceHook tmp;
	tmp.DetourFunc = Detour;
	tmp.fp.GuestVA = HookFuncStart;
	tmp.TrampolineFunc = TramPoline;
	tmp.Construct();
	vServcieHook.push_back(tmp);
}

void RemoveServiceHook()
{
	for (auto& hook : vServcieHook)
	{
		hook.Destruct();
	}
}


//example

NTSTATUS DetourNtOpenProcess(
	PHANDLE            ProcessHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PCLIENT_ID         ClientId
)
{
	static int once =0;
	if(!(once++))
	Log("hello world\n");


	return OriNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}