#include"include/exclusivity.h"
#include"ia32_type.h"
#include"systemcall.h"
#include"include/write_protect.h"
#include "settings.h"

extern "C"
{
#include"kernel-hook/khook/khook/hk.h"
extern "C" void DetourKiSystemServiceStart();
NTSYSAPI const char* PsGetProcessImageFileName(PEPROCESS Process);

}


fpSystemCall SystemCallFake;
char SystemCallRecoverCode[15] = {};
NTSTATUS HookStatus = STATUS_UNSUCCESSFUL;


const char* GetSyscallProcess()
{
	return PsGetProcessImageFileName(IoGetCurrentProcess());
}


NTSTATUS InitSystemVar()
{
	/*
	* 这个函数用来在vmlaunch之前初始化一些全局变量
	* 
	* 1.获得内核基址
	* 
	* 2.获得KiSystemServiceStart的地址
	* 
	* 3.获得SSDT Table的地址
	* 
	* 4.初始化一个伪造的guest页面
	*/


	KernelBase = GetKernelBase();
	PtrKiSystemServiceStart = (ULONG_PTR)&DetourKiSystemServiceStart;

	//KiSystemServiceCopyStart = OffsetKiSystemServiceCopyStart + KernelBase;
	KiSystemServiceStart = OffsetKiSystemServiceStart + KernelBase;

	aSYSTEM_SERVICE_DESCRIPTOR_TABLE = 
	(SYSTEM_SERVICE_DESCRIPTOR_TABLE*)(OffsetKeServiceDescriptorTable + KernelBase);

	SystemCallFake.Construct();

	return STATUS_SUCCESS;
}

void DoSystemCallHook()
{
	OriKiSystemServiceStart = (PVOID)((ULONG_PTR)KiSystemServiceStart + 0x14);
	auto exclusivity = ExclGainExclusivity();
	//
	//push r15
	//mov r15,xx
	//jmp r15
	// 
	//r15:pop r15
	//
	char hook[] = { 0x41,0x57,0x49,0xBF,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x41,0xFF,0xE7 };
	memcpy(SystemCallRecoverCode, (PVOID)KiSystemServiceStart, sizeof(SystemCallRecoverCode));
	memcpy(hook + 4, &PtrKiSystemServiceStart, sizeof(PtrKiSystemServiceStart));
	auto irql = WPOFFx64();
	memcpy((PVOID)KiSystemServiceStart, hook, sizeof(hook));
	WPONx64(irql);

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

#ifdef DBG
	//用来记录拦截了多少次系统调用，方便debug，只有第一次的时候会输出
	static LONG64 SysCallCount = 0;
	if (!SysCallCount) {
		Log("[SysCallCount]at %p\n", &SysCallCount);
		Log("[SYSCALL]%s\nIndex %x\nTarget %llx\n", GetSyscallProcess(), SSDT_INDEX, GetSSDTEntry(SSDT_INDEX));
#if 0
		DbgBreakPoint();
#endif
	}
	InterlockedAdd64(&SysCallCount, 1);
#endif

	//然后应该调用用户给的处理函数，如果没有提供，则使用默认的

	if (UserSystemCallHandler)
	{
		UserSystemCallHandler(TrapFrame, SSDT_INDEX);
	}
}

void SystemCallLog(KTRAP_FRAME* TrapFrame, ULONG SSDT_INDEX)
{
	const char* syscall_name = GetSyscallProcess();
#if 0
	Log("%s\n", syscall_name);
#endif
	//
	//不需要输出shadow ssdt的
	//

	//
	//ConsoleApplication3.vmp.exe
	//因为EPROCESS.ImageFileName[16]，所以需要截断至16个字节(带末尾空字符)
	//这个测试exe在项目目录下
	//
	if (!strcmp(syscall_name, "ConsoleApplica")) {
		if (SSDT_INDEX < 0x1000)
			Log("[%s]Syscall rip %p SSDT Index %p\n", syscall_name,TrapFrame->Rip - 2, SSDT_INDEX);
	}
}