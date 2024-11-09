#include "include/exclusivity.h"
#include "ia32_type.h"
#include "systemcall.h"
#include "include/write_protect.h"

extern "C"
{
#include"kernel-hook/khook/khook/hk.h"
	// 我们的Syscall Handler
	extern "C" void DetourKiSystemServiceStart();

	NTSYSAPI PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(_In_ PVOID Base);
}


fpSystemCall SystemCallFake;

char SystemCallRecoverCode[15] = {};
NTSTATUS HookStatus = STATUS_UNSUCCESSFUL;


//copy from blackbone
PKLDR_DATA_TABLE_ENTRY GetSystemModule(IN PUNICODE_STRING pName, IN PVOID pAddress)
{
	if ((pName == NULL && pAddress == NULL) || PsLoadedModuleList == NULL)
		return NULL;

	// No images
	if (IsListEmpty(PsLoadedModuleList))
		return NULL;

	// Search in PsLoadedModuleList
	for (PLIST_ENTRY pListEntry = PsLoadedModuleList->Flink; pListEntry != PsLoadedModuleList; pListEntry = pListEntry->Flink)
	{
		PKLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

		// Check by name or by address
		if ((pName && RtlCompareUnicodeString(&pEntry->BaseDllName, pName, TRUE) == 0) ||
			(pAddress && pAddress >= pEntry->DllBase && (PUCHAR)pAddress < (PUCHAR)pEntry->DllBase + pEntry->SizeOfImage))
		{
			return pEntry;
		}
	}

	return NULL;
}


NTSTATUS InitSystemVar()
{
	// 初始化内核基址 (KernelBase.asm)
	KernelBase = GetKernelBase();
	if (!KernelBase) {
		HYPERPLATFORM_LOG_ERROR("Cant get kernel base");
		return STATUS_UNSUCCESSFUL;
	}
	HYPERPLATFORM_LOG_INFO("[KernelBase]%p", KernelBase);

	UNICODE_STRING UnicodeBuf;
	RtlInitUnicodeString(&UnicodeBuf, L"PsLoadedModuleList");
	PsLoadedModuleList = (PLIST_ENTRY)MmGetSystemRoutineAddress(&UnicodeBuf);

	auto tmpa = GetSystemModule(&Win32kfullBaseString, 0);
	if (tmpa)
	{
		Win32kfullBase = (ULONG_PTR)tmpa->DllBase;
		Win32kfullSize = (ULONG_PTR)tmpa->SizeOfImage;
		HYPERPLATFORM_LOG_INFO("[WIN32kfullBase]%llx", Win32kfullBase);
	}
	else
	{
		HYPERPLATFORM_LOG_ERROR("Cant get Win32kfull Base");
		return STATUS_UNSUCCESSFUL;
	}

	tmpa = GetSystemModule(&Win32kbaseBaseString, 0);
	if (tmpa)
	{
		Win32kbaseBase = (ULONG_PTR)tmpa->DllBase;
		HYPERPLATFORM_LOG_INFO("[WIN32kbaseBase]%llx", Win32kbaseBase);
	}
	else
	{
		HYPERPLATFORM_LOG_ERROR("Cant get Win32kbase Base");
		return STATUS_UNSUCCESSFUL;
	}

	PtrDetourKiSystemServiceStart = (ULONG_PTR)&DetourKiSystemServiceStart;

	// Find .text section
	PIMAGE_NT_HEADERS ntHeaders = RtlImageNtHeader((PVOID)KernelBase);
	PIMAGE_SECTION_HEADER textSection = nullptr;
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
	for (ULONG i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i)
	{
		char sectionName[IMAGE_SIZEOF_SHORT_NAME + 1];
		RtlCopyMemory(sectionName, section->Name, IMAGE_SIZEOF_SHORT_NAME);
		sectionName[IMAGE_SIZEOF_SHORT_NAME] = '\0';
		if (strncmp(sectionName, ".text", sizeof(".text") - sizeof(char)) == 0)
		{
			textSection = section;
			break;
		}
		section++;
	}
	if (textSection == nullptr)
		return STATUS_UNSUCCESSFUL;

	// Find KiSystemServiceStart in .text
	const unsigned char KiSystemServiceStartPattern[] = { 0x8B, 0xF8, 0xC1, 0xEF, 0x07, 0x83, 0xE7, 0x20, 0x25, 0xFF, 0x0F, 0x00, 0x00 };
	const ULONG signatureSize = sizeof(KiSystemServiceStartPattern);
	bool found = false;
	ULONG KiSSSOffset;
	for (KiSSSOffset = 0; KiSSSOffset < textSection->Misc.VirtualSize - signatureSize; KiSSSOffset++)
	{
		if (RtlCompareMemory(((unsigned char*)KernelBase + textSection->VirtualAddress + KiSSSOffset), KiSystemServiceStartPattern, signatureSize) == signatureSize)
		{
			found = true;
			break;
		}
	}
	if (!found) {
		HYPERPLATFORM_LOG_ERROR("Cant find KiSystemServiceStart");
		return STATUS_SUCCESS;
	}
	/*
nt!KiSystemServiceStart:
fffff805`5cbc50f0 4889a390000000  mov     qword ptr [rbx+90h],rsp
fffff805`5cbc50f7 8bf8            mov     edi,eax                  <--- KiSystemServiceStartPattern
fffff805`5cbc50f9 c1ef07          shr     edi,7
fffff805`5cbc50fc 83e720          and     edi,20h
fffff805`5cbc50ff 25ff0f0000      and     eax,0FFFh
	*/
	KiSystemServiceStart = (ULONG_PTR)((unsigned char*)KernelBase + textSection->VirtualAddress + KiSSSOffset - 7);
	HYPERPLATFORM_LOG_INFO("KiSystemServiceStart %llx", KiSystemServiceStart);

	SystemCallFake.Construct();

	return STATUS_SUCCESS;
}

void DoSystemCallHook()
{
	/*
nt!KiSystemServiceStart:
fffff805`5cbc50f0 4157            push    r15
fffff805`5cbc50f2 49bfe0133d5c05f8ffff mov r15,offset HyperTool!DetourKiSystemServiceStart (fffff805`5c3d13e0)
fffff805`5cbc50fc 41ffe7          jmp     r15
fffff805`5cbc50ff 25ff0f0000      and     eax,0FFFh
nt!KiSystemServiceRepeat:
fffff805`5cbc5104 4c8d1575a73100  lea     r10,[nt!KeServiceDescriptorTable (fffff805`5cedf880)]         <------ OriKiSystemServiceStart
fffff805`5cbc510b 4c8d1d6e383000  lea     r11,[nt!KeServiceDescriptorTableShadow (fffff805`5cec8980)]
fffff805`5cbc5112 f7437880000000  test    dword ptr [rbx+78h],80h
fffff805`5cbc5119 7413            je      nt!KiSystemServiceRepeat+0x2a (fffff805`5cbc512e)
	*/
	HYPERPLATFORM_LOG_INFO("DoSystemCallHook Start");
	OriKiSystemServiceStart = (PVOID)((ULONG_PTR)KiSystemServiceStart + 0x14);   // 0x14是KiSystemServiceRepeat和KiSystemServiceStart之间的地址差距
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
	memcpy(hook + 4, &PtrDetourKiSystemServiceStart, sizeof(PtrDetourKiSystemServiceStart));
	auto irql = WPOFFx64();
	memcpy((PVOID)KiSystemServiceStart, hook, sizeof(hook));   // 完成hook
	WPONx64(irql);

	ExclReleaseExclusivity(exclusivity);
	HYPERPLATFORM_LOG_INFO("DoSystemCallHook End");
}

//只用于SSDT，不适用于ShadowSSDT
PVOID GetSSDTEntry(IN ULONG index)
{
	//PSYSTEM_SERVICE_DESCRIPTOR_TABLE pSSDT = aSYSTEM_SERVICE_DESCRIPTOR_TABLE;
	//PVOID pBase = (PVOID)KernelBase;

	//if (pSSDT && pBase)
	//{
	//	// Index range check 在shadowssdt里的话返回0
	//	if (index > pSSDT->NumberOfServices)
	//		return NULL;

	//	return (PUCHAR)pSSDT->ServiceTableBase + (((PLONG)pSSDT->ServiceTableBase)[index] >> 4);
	//}

	return NULL;
}

void SystemCallHandler(KTRAP_FRAME* TrapFrame, ULONG SSDT_INDEX)
{
	UNREFERENCED_PARAMETER(TrapFrame);
	UNREFERENCED_PARAMETER(SSDT_INDEX);
}
