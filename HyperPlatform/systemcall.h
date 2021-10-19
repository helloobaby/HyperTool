#include"include/stdafx.h"
#include"include/PDBSDK.h"

#if 0
__int64 __fastcall MmCreateShadowMapping(__int64 VirtualAddress, __int64 size);

using MmCreateShadowMappingType = decltype(&MmCreateShadowMapping);

MmCreateShadowMappingType aMmCreateShadowMapping;
#endif

//需要给asm文件使用
extern "C"
{
	inline const ULONG KernelSize = 0xa6e000; //hard signature
	inline ULONG_PTR KernelBase = NULL;
	inline ULONG_PTR KiSystemCall64Shadow = NULL;
	inline ULONG_PTR PtrDetourKiSystemCall64Shadow = NULL;
	inline ULONG_PTR KiSystemCall64ShadowCommon = NULL;
#if 0
	inline ULONG_PTR KiSystemServiceCopyEnd = NULL;
	inline ULONG_PTR PtrKiSystemServiceCopyEnd = (ULONG_PTR)&KiSystemServiceCopyEnd;
	inline PVOID OriKiSystemServiceCopyEnd = NULL;
#endif
	inline ULONG_PTR KiSystemServiceCopyStart = NULL;
	inline ULONG_PTR PtrKiSystemServiceCopyStart = (ULONG_PTR)&KiSystemServiceCopyStart;
	inline PVOID OriKiSystemServiceCopyStart = NULL;

	inline ULONG_PTR OtherKiSystemServiceCopyEnd = NULL;
	inline ULONG_PTR OtherPtrKiSystemServiceCopyEnd = (ULONG_PTR)&OtherKiSystemServiceCopyEnd;
	inline PVOID OriOtherKiSystemServiceCopyEnd = NULL;

	inline ULONG_PTR KiSystemServiceStart = NULL;
	inline ULONG_PTR PtrKiSystemServiceStart = NULL;
	inline PVOID OriKiSystemServiceStart = NULL;

	void SystemCallHandler(ULONG64 ssdt_func_index);
	ULONG_PTR GetKernelBase();
}


//
//在vm初始化之前初始化需要的变量
//

NTSTATUS InitSystemVar();

void DoSystemCallHook();

