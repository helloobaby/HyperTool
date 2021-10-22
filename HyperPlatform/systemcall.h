#include"log.h"
#include"include/PDBSDK.h"
#include"FakePage.h"

#define NO_MEMORY_BUGCHECK_CODE 0x444444

typedef struct _SYSTEM_SERVICE_DESCRIPTOR_TABLE
{
	PULONG_PTR ServiceTableBase;
	PULONG ServiceCounterTableBase;
	ULONG_PTR NumberOfServices;
	PUCHAR ParamTableBase;
} SYSTEM_SERVICE_DESCRIPTOR_TABLE, * PSYSTEM_SERVICE_DESCRIPTOR_TABLE;


//需要给asm文件使用
extern "C"
{
	inline const ULONG KernelSize = 0xa6e000; //hard signature
	inline ULONG_PTR KernelBase = NULL;


	inline ULONG_PTR KiSystemServiceStart = NULL;
	inline ULONG_PTR PtrKiSystemServiceStart = NULL;
	inline PVOID OriKiSystemServiceStart = NULL;
	inline PSYSTEM_SERVICE_DESCRIPTOR_TABLE aSYSTEM_SERVICE_DESCRIPTOR_TABLE = NULL;

	void SystemCallHandler(KTRAP_FRAME* TrapFrame, ULONG SSDT_INDEX);
	ULONG_PTR GetKernelBase();
	const char* GetSyscallProcess();

	inline decltype(&SystemCallHandler) UserSystemCallHandler = NULL;

	void InitUserSystemCallHandler(decltype(&SystemCallHandler) UserHandler);
}


//
//在vm初始化之前初始化需要的变量
//

NTSTATUS InitSystemVar();

void DoSystemCallHook();

PVOID GetSSDTEntry(IN ULONG index);

struct fpSystemCall :public ICFakePage
{
	virtual void Construct() override
	{
		fp.GuestVA = (PVOID)((KiSystemServiceStart >> 12) << 12);
		fp.PageContent = ExAllocatePoolWithQuota(NonPagedPool, PAGE_SIZE);
		memcpy(fp.PageContent, fp.GuestVA, PAGE_SIZE);

		//
		//PA没有页对齐！
		//
		fp.GuestPA = MmGetPhysicalAddress(fp.GuestVA);
		fp.PageContentPA = MmGetPhysicalAddress(fp.PageContent);
		if (!fp.GuestPA.QuadPart || !fp.PageContentPA.QuadPart)
			KeBugCheck(NO_MEMORY_BUGCHECK_CODE);
	}
	virtual void Destruct() override
	{

	}

};
