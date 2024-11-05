#include <ntdef.h>
#include <ntimage.h>

#include "log.h"
#include "FakePage.h"
#include "error_bugcheck.h"

typedef struct _SYSTEM_SERVICE_DESCRIPTOR_TABLE
{
	PULONG_PTR ServiceTableBase;
	PULONG ServiceCounterTableBase;
	ULONG_PTR NumberOfServices;
	PUCHAR ParamTableBase;
} SYSTEM_SERVICE_DESCRIPTOR_TABLE, * PSYSTEM_SERVICE_DESCRIPTOR_TABLE;


typedef struct _KLDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	PVOID ExceptionTable;
	ULONG ExceptionTableSize;
	// ULONG padding on IA64
	PVOID GpValue;
	PNON_PAGED_DEBUG_INFO NonPagedDebugInfo;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT __Unused5;
	PVOID SectionPointer;
	ULONG CheckSum;
	// ULONG padding on IA64
	PVOID LoadedImports;
	PVOID PatchInformation;
} KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;


// 需要给asm文件使用
extern "C"
{
	// ntoskrnl.exe基地址
	inline ULONG_PTR KernelBase = NULL;
	//win32kfull.sys基地址
	inline ULONG_PTR Win32kfullBase = NULL;
	//win32kbase.sys基地址
	inline ULONG_PTR Win32kbaseBase = NULL;
	inline ULONG Win32kfullSize = NULL;

	// 内核模块链表头
	inline PLIST_ENTRY PsLoadedModuleList;

	inline UNICODE_STRING Win32kfullBaseString = RTL_CONSTANT_STRING(L"win32kfull.sys");
	inline UNICODE_STRING Win32kbaseBaseString = RTL_CONSTANT_STRING(L"win32kbase.sys");


	// syscall -> nt!KiSystemCall64 -> nt!KiSystemServiceStart -> nt!KiSystemServiceRepeat -> call r10
	inline ULONG_PTR KiSystemServiceStart = NULL;
	// 存储我们的Syscall Handler(汇编) 的地址的指针
	inline ULONG_PTR PtrDetourKiSystemServiceStart = NULL;
	// 上面的汇编 Handler会调用这个C Handler
	void SystemCallHandler(KTRAP_FRAME* TrapFrame, ULONG SSDT_INDEX);

	// Hook中的调用原始函数的函数指针
	inline PVOID OriKiSystemServiceStart = NULL;

	void InitUserSystemCallHandler(decltype(&SystemCallHandler) UserHandler);
	// 上面这个函数初始化这个函数指针
	inline decltype(&SystemCallHandler) UserSystemCallHandler = NULL;
	
	// 汇编写的获得内核基地址
	ULONG_PTR GetKernelBase();

	const char* GetSyscallProcess();
}


//
//在vm初始化之前初始化需要的变量
//

NTSTATUS InitSystemVar();

void DoSystemCallHook();

PVOID GetSSDTEntry(IN ULONG index);

struct fpSystemCall : public ICFakePage
{
	virtual void Construct() override
	{
		fp.GuestVA = (PVOID)((KiSystemServiceStart >> 12) << 12);
		fp.PageContent = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE,'zxc');
		if (!fp.PageContent)
		{
			KeBugCheck(ExAllocatePoolERROR);
		}
		
		// 填充页面内容
		memcpy(fp.PageContent, fp.GuestVA, PAGE_SIZE);

		fp.GuestPA = MmGetPhysicalAddress(fp.GuestVA);
		fp.PageContentPA = MmGetPhysicalAddress(fp.PageContent);
		if (!fp.GuestPA.QuadPart || !fp.PageContentPA.QuadPart)
			KeBugCheck(MmGetPhysicalAddressError);
	}
	virtual void Destruct() override
	{

	}

};

void SystemCallLog(KTRAP_FRAME* TrapFrame, ULONG SSDT_INDEX);