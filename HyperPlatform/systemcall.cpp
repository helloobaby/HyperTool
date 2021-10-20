#include"systemcall.h"
#include"util.h"
#include"ia32_type.h"
#include"log.h"
#include"include/exclusivity.h"
#include"ept.h"

extern "C"
{
#include"kernel-hook/khook/khook/hk.h"
extern "C" void DetourKiSystemCall64Shadow();
extern "C" void DetourKiSystemServiceCopyEnd();
extern "C" void DetourOtherKiSystemServiceCopyEnd();
extern "C" void DetourKiSystemServiceCopyStart();
extern "C" void DetourKiSystemServiceStart();
NTSYSAPI const char* PsGetProcessImageFileName(PEPROCESS Process);

}

FakePage SystemFakePage;

ULONG_PTR
fulsh_insn_cache(
	_In_ ULONG_PTR Argument
)
{
#if 1
	Log("flush insn cache!\n");
#endif
	//aZwFlushInstructionCache();
	return true;
}

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
	
	KiSystemCall64Shadow = UtilReadMsr64(Msr::kIa32Lstar);
	PtrDetourKiSystemCall64Shadow = (ULONG_PTR)&DetourKiSystemCall64Shadow;
	//PtrKiSystemServiceCopyEnd = (ULONG_PTR)&DetourKiSystemServiceCopyEnd;
	//PtrKiSystemServiceCopyStart = (ULONG_PTR)&DetourKiSystemServiceCopyStart;
	OtherPtrKiSystemServiceCopyEnd = (ULONG_PTR)&DetourOtherKiSystemServiceCopyEnd;
	PtrKiSystemServiceStart = (ULONG_PTR)&DetourKiSystemServiceStart;

	//KiSystemServiceCopyEnd = OffsetKiSystemServiceCopyEnd + KernelBase;
	OtherKiSystemServiceCopyEnd = OffsetKiSystemServiceCopyEnd + KernelBase + 0x20;
	//KiSystemServiceCopyStart = OffsetKiSystemServiceCopyStart + KernelBase;
	KiSystemServiceStart = OffsetKiSystemServiceStart + KernelBase;

	aSYSTEM_SERVICE_DESCRIPTOR_TABLE = 
	(SYSTEM_SERVICE_DESCRIPTOR_TABLE*)(OffsetKeServiceDescriptorTable + KernelBase);

#ifdef DBG
	Log("KiSystemCall64Shadow at %llx\n", KiSystemCall64Shadow);
#endif // DEBUG

	if (!KiSystemCall64Shadow)
		return STATUS_UNSUCCESSFUL;

	KiSystemCall64ShadowCommon = KiSystemCall64Shadow + 0x2D;

	SystemFakePage.GuestVA = (PVOID)((KiSystemServiceStart >>12) << 12);
	SystemFakePage.PageContent = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, 'a');
	if (!SystemFakePage.PageContent)
		return STATUS_UNSUCCESSFUL;
	memcpy(SystemFakePage.PageContent, SystemFakePage.GuestVA,PAGE_SIZE);
	SystemFakePage.GuestPA = MmGetPhysicalAddress(SystemFakePage.GuestVA);
	SystemFakePage.PageContentPA = MmGetPhysicalAddress(SystemFakePage.PageContent);

	return STATUS_SUCCESS;
}

void DoSystemCallHook()
{

#if 0 //开启了KPTI之后这个不行了，因为用户进程并不会有你的代码的映射，更加执行不了
	UtilWriteMsr64(Msr::kIa32Lstar, (ULONG64)DetourKiSystemCall64Shadow);
	DbgBreakPoint();
#endif

	//
	//所以采用直接hook KiSystemCall64 然后用ept隐藏内存
	//
	//一样的道理，hook开头不可取，只能采取hook后面
#if 0
	auto exclusivity = ExclGainExclusivity();
	HkDetourFunction((PVOID)KiSystemCall64Shadow, (PVOID)PtrDetourKiSystemCall64Shadow, NULL);
	ExclReleaseExclusivity(exclusivity);
#endif

	//涉及到全局变量的重定位，比较麻烦
#if 0
	auto exclusivity = ExclGainExclusivity();
	HkDetourFunction((PVOID)KiSystemServiceCopyEnd, (PVOID)PtrKiSystemServiceCopyEnd, &OriKiSystemServiceCopyEnd);
	ExclReleaseExclusivity(exclusivity);
#endif

	//这里也有点傻逼
#if 0
	auto exclusivity = ExclGainExclusivity();
	HkDetourFunction((PVOID)
		KiSystemServiceCopyStart, 
		(PVOID)PtrKiSystemServiceCopyStart, 
		&OriKiSystemServiceCopyStart);
	ExclReleaseExclusivity(exclusivity);
#endif

	//这个地方也不行，有call的地方，如果线程切换把返回地址放在堆栈，但是返回地址附近已经被hook打乱了
	//再回来执行就崩了，特别是高频函数的地方
#if 0
	auto exclusivity = ExclGainExclusivity();
	HkDetourFunction(
		(PVOID)OtherKiSystemServiceCopyEnd, 
		(PVOID)OtherPtrKiSystemServiceCopyEnd,
		&OriOtherKiSystemServiceCopyEnd);
	KeIpiGenericCall(fulsh_insn_cache, NULL);
	ExclReleaseExclusivity(exclusivity);
#endif

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
	ULONG size = 0;
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
