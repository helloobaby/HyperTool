#include"service_hook.h"
#include"include/stdafx.h"
#include"include/vector.hpp"
#include"include/exclusivity.h"
#include"include/write_protect.h"
#include"kernel-hook/khook/hde/hde.h"
extern "C"
{
#include"kernel-hook/khook/khook/hk.h"
}

using std::vector; 
vector<ServiceHook> vServcieHook;
hde64s gIns;

void ServiceHook::Construct()
{
	if (!this->DetourFunc || !this->TrampolineFunc || !this->fp.GuestVA)
	{
		Log("DetourFunc or TrampolineFunc or fp.GuestVA is null!\n");
		Log("DetourFunc %p\nTrampolineFunc %p\nfp.GuestVA %p\n",
			this->DetourFunc, this->TrampolineFunc, this->fp.GuestVA);
		return;
	}

#if 0
	NTSTATUS Status = HkDetourFunction((this->fp).GuestVA, this->DetourFunc, this->TrampolineFunc);

	if (!NT_SUCCESS(Status)) {
		Log("HkDetourFunction Failed %x\n", Status);
		return;
	}
#endif

	//获得指定函数所在页的开始处
	auto tmp = (PVOID)(((ULONG_PTR)(this->fp).GuestVA >> 12) << 12);
	//GuestPA为GuestVA这个页面起始的物理地址
	//GuestVA必须初始化后不能改变
	this->fp.GuestPA = MmGetPhysicalAddress(tmp);
	this->fp.PageContent = ExAllocatePoolWithQuota(NonPagedPool, PAGE_SIZE);
	memcpy(this->fp.PageContent, tmp, PAGE_SIZE);
	this->fp.PageContentPA = MmGetPhysicalAddress(this->fp.PageContent);
	if (!fp.GuestPA.QuadPart || !fp.PageContentPA.QuadPart)
	{
		HkRestoreFunction((this->fp).GuestVA, this->TrampolineFunc);
		Log("MmGetPhysicalAddress error %s %d\n",__func__,__LINE__);
		return;
	}

	auto exclusivity = ExclGainExclusivity();
	//
	//
	//mov rax,xx
	//jmp rax
	//
	//
	static char hook[] = { 0x48,0xB8,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0xFF,0xE0 };
	size_t CodeLength = 0;
	while (CodeLength < 12)
	{
		HdeDisassemble((void*)((ULONG_PTR)(this->DetourFunc) + CodeLength), &gIns);
		CodeLength += gIns.len;
	}
	this->HookCodeLen = CodeLength;
	/*
	* 1.分配一个动态内存(Orixxxxx)保存函数开头至少12个字节,还得加上一个jmpxxx的字节，因为Ori还得jmp回去
	* 2.然后修改函数开头为move rax,xx jump rax,xx
	* 3.
	*/

	*(this->TrampolineFunc) = ExAllocatePoolWithTag(NonPagedPool, CodeLength + 14, 'a');
	if (!*(this->TrampolineFunc))
	{
		Log("ExAllocatePoolWithTag failed ,no memory!\n");
		return;
	}
	memcpy(*(this->TrampolineFunc), this->fp.GuestVA, CodeLength);
	static char hook2[] = { 0xff,0x25,0,0,0,0,1,1,1,1,1,1,1,1 };
	ULONG_PTR jmp_return = (ULONG_PTR)this->fp.GuestVA + CodeLength - 1;
	memcpy(hook2 + 6, &jmp_return, 8);
	memcpy((void*)((ULONG_PTR)(*(this->TrampolineFunc)) + CodeLength), hook2, 14);
	auto irql = WPOFFx64();

	PVOID* Ptr = &this->DetourFunc;
	memcpy(hook + 2, Ptr, 8);
	memcpy((PVOID)this->fp.GuestVA, hook, sizeof(hook));

	WPONx64(irql);


	ExclReleaseExclusivity(exclusivity);


	this->isEverythignSuc = true;

}

void ServiceHook::Destruct()
{
	if (!this->isEverythignSuc)
		return;

#if 0
	NTSTATUS Status = HkRestoreFunction((this->fp).GuestVA, this->TrampolineFunc);
	if (!NT_SUCCESS(Status)) {
		Log("HkRestoreFunction Failed %x\n", Status);
		return;
	}
#endif
	auto irql = WPOFFx64();
	memcpy(this->fp.GuestVA, *(this->TrampolineFunc), this->HookCodeLen);
	WPONx64(irql);
	ExFreePool(*(this->TrampolineFunc));

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