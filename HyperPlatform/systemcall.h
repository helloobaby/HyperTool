#include"log.h"
#include"FakePage.h"
#include<ntdef.h>
#include"include/PDBSDK.h"


#define NO_MEMORY_BUGCHECK_CODE 0x444444

typedef struct _SYSTEM_SERVICE_DESCRIPTOR_TABLE
{
	PULONG_PTR ServiceTableBase;
	PULONG ServiceCounterTableBase;
	ULONG_PTR NumberOfServices;
	PUCHAR ParamTableBase;
} SYSTEM_SERVICE_DESCRIPTOR_TABLE, * PSYSTEM_SERVICE_DESCRIPTOR_TABLE;

typedef struct _NON_PAGED_DEBUG_INFO // 9 elements, 0x20 bytes (sizeof) 
{
	/*0x000*/     UINT16       Signature;
	/*0x002*/     UINT16       Flags;
	/*0x004*/     ULONG32      Size;
	/*0x008*/     UINT16       Machine;
	/*0x00A*/     UINT16       Characteristics;
	/*0x00C*/     ULONG32      TimeDateStamp;
	/*0x010*/     ULONG32      CheckSum;
	/*0x014*/     ULONG32      SizeOfImage;
	/*0x018*/     UINT64       ImageBase;
}NON_PAGED_DEBUG_INFO, * PNON_PAGED_DEBUG_INFO;

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


//需要给asm文件使用
extern "C"
{
	inline const ULONG KernelSize = 0xa6e000; //hard signature
	inline ULONG_PTR KernelBase = NULL;
	inline ULONG_PTR Win32kfullBase = NULL;
	inline ULONG_PTR Win32kbaseBase = NULL;
	inline ULONG Win32kfullSize = NULL;
	inline ULONG_PTR PspCidTable;
	inline PLIST_ENTRY PsLoadedModuleList;
	inline UNICODE_STRING Win32kfullBaseString = RTL_CONSTANT_STRING(L"win32kfull.sys");
	inline UNICODE_STRING Win32kbaseBaseString = RTL_CONSTANT_STRING(L"win32kbase.sys");

	inline ULONG_PTR KiSystemServiceStart = NULL;
	inline ULONG_PTR PtrKiSystemServiceStart = NULL;
	inline PVOID OriKiSystemServiceStart = NULL;
	inline PSYSTEM_SERVICE_DESCRIPTOR_TABLE aSYSTEM_SERVICE_DESCRIPTOR_TABLE = NULL;

	//inline LdrpKrnGetDataTableEntryType LdrpKrnGetDataTableEntry = NULL;

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

void SystemCallLog(KTRAP_FRAME* TrapFrame, ULONG SSDT_INDEX);