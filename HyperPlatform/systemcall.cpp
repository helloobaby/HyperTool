#include"systemcall.h"
#include"util.h"
#include"ia32_type.h"
#include"log.h"
#include"include/exclusivity.h"
#include"ept.h"

extern "C"
{
#include"kernel-hook/khook/khook/hk.h"
extern "C" void DetourKiSystemServiceStart();
NTSYSAPI const char* PsGetProcessImageFileName(PEPROCESS Process);

}

FakePage SystemFakePage;


const char* GetSyscallProcess()
{
	return PsGetProcessImageFileName(IoGetCurrentProcess());
}

NTSTATUS InitSystemVar()
{
	//
	//初始化内核基址
	//
	KernelBase = GetKernelBase();
	
	PtrKiSystemServiceStart = (ULONG_PTR)&DetourKiSystemServiceStart;

	//KiSystemServiceCopyStart = OffsetKiSystemServiceCopyStart + KernelBase;
	KiSystemServiceStart = OffsetKiSystemServiceStart + KernelBase;

	aSYSTEM_SERVICE_DESCRIPTOR_TABLE = 
	(SYSTEM_SERVICE_DESCRIPTOR_TABLE*)(OffsetKeServiceDescriptorTable + KernelBase);


	SystemFakePage.GuestVA = (PVOID)((KiSystemServiceStart >>12) << 12);
	SystemFakePage.PageContent = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, 'a');
	if (!SystemFakePage.PageContent)
		return STATUS_UNSUCCESSFUL;
	memcpy(SystemFakePage.PageContent, SystemFakePage.GuestVA,PAGE_SIZE);
	//PA都没有页对齐
	SystemFakePage.GuestPA = MmGetPhysicalAddress(SystemFakePage.GuestVA);
	SystemFakePage.PageContentPA = MmGetPhysicalAddress(SystemFakePage.PageContent);

	return STATUS_SUCCESS;
}

void DoSystemCallHook()
{

	auto exclusivity = ExclGainExclusivity();
	HkDetourFunction((PVOID)
		KiSystemServiceStart,
		(PVOID)PtrKiSystemServiceStart,
		&OriKiSystemServiceStart);
	ExclReleaseExclusivity(exclusivity);
}

//只用于SSDT，不适用于ShadowSSDT
PVOID GetSSDTEntry(IN ULONG index)
{
	PSYSTEM_SERVICE_DESCRIPTOR_TABLE pSSDT = aSYSTEM_SERVICE_DESCRIPTOR_TABLE;
	PVOID pBase = (PVOID)KernelBase;

	if (pSSDT && pBase)
	{
		// Index range check 在shadowssdt里的话返回0
		if (index > pSSDT->NumberOfServices)
			return NULL;

		return (PUCHAR)pSSDT->ServiceTableBase + (((PLONG)pSSDT->ServiceTableBase)[index] >> 4);
	}

	return NULL;
}

void InitUserSystemCallHandler(decltype(&SystemCallHandler) UserHandler)
{
	UserSystemCallHandler = UserHandler;
}

void SystemCallHandler(KTRAP_FRAME * TrapFrame,ULONG SSDT_INDEX)
{

#if 1
	//用来记录拦截了多少次系统调用，方便debug，只有第一次的时候会输出
	static ULONG64 SysCallCount = 0;
	if (!SysCallCount) {
		Log("[SysCallCount]at %p\n", &SysCallCount);
		Log("[SYSCALL]%s\nIndex %x\nTarget %llx\n", GetSyscallProcess(), SSDT_INDEX, GetSSDTEntry(SSDT_INDEX));
	}
	SysCallCount++;
#endif

	//然后应该调用用户给的处理函数，如果没有提供，则使用默认的

	if (UserSystemCallHandler)
	{
		UserSystemCallHandler(TrapFrame, SSDT_INDEX);
	}
}
