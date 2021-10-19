#include"systemcall.h"
#include"util.h"
#include"ia32_type.h"
#include"log.h"
#include"include/exclusivity.h"

extern "C"
{
#include"kernel-hook/khook/khook/hk.h"
extern "C" void DetourKiSystemCall64Shadow();
extern "C" void DetourKiSystemServiceCopyEnd();
extern "C" void DetourOtherKiSystemServiceCopyEnd();
extern "C" void DetourKiSystemServiceCopyStart();
extern "C" void DetourKiSystemServiceStart();
}

void ZwFlushInstructionCache();

using ZwFlushInstructionCacheType = decltype(&ZwFlushInstructionCache);
ZwFlushInstructionCacheType aZwFlushInstructionCache = NULL;


ULONG_PTR
fulsh_insn_cache(
	_In_ ULONG_PTR Argument
)
{
#if 1
	Log("flush insn cache!\n");
#endif
	aZwFlushInstructionCache();
	return true;
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

#ifdef DBG
	Log("KiSystemCall64Shadow at %llx\n", KiSystemCall64Shadow);
#endif // DEBUG

	if (!KiSystemCall64Shadow)
		return STATUS_UNSUCCESSFUL;

	KiSystemCall64ShadowCommon = KiSystemCall64Shadow + 0x2D;

	return STATUS_SUCCESS;
}

void DoSystemCallHook()
{

	aZwFlushInstructionCache = (ZwFlushInstructionCacheType)(KernelBase + OffsetZwFlushInstructionCache);

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

void SystemCallHandler(ULONG64 ssdt_func_index)
{
	Log("hello world\n");
}
