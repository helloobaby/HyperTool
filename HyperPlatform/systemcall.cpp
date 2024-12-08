#include "include/exclusivity.h"
#include "ia32_type.h"
#include "systemcall.h"
#include "include/write_protect.h"
#include "sssdt.h"
#include "ssdt.h"
#include "util.h"
#include "include/vector.hpp"
#include "include/string.hpp"
#include "config.h"
#include "regex/pcre_regex.h"
#include "asm.h"
#include <stdio.h>

extern "C"
{
#include"kernel-hook/khook/khook/hk.h"
	// 我们的Syscall Handler
	extern "C" void DetourKiSystemServiceStart();

	NTSYSAPI PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(_In_ PVOID Base);

	UCHAR* PsGetProcessImageFileName(PEPROCESS Process);
}


fpSystemCall SystemCallFake;

char SystemCallRecoverCode[15] = {};

LONG SyscallRefCount = 0;

extern tagGlobalConfig GlobalConfig;

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
	HYPERPLATFORM_LOG_INFO("KernelBase %p", KernelBase);

	UNICODE_STRING UnicodeBuf;
	RtlInitUnicodeString(&UnicodeBuf, L"PsLoadedModuleList");
	PsLoadedModuleList = (PLIST_ENTRY)MmGetSystemRoutineAddress(&UnicodeBuf);

	auto tmpa = GetSystemModule(&Win32kfullBaseString, 0);
	if (tmpa)
	{
		Win32kfullBase = (ULONG_PTR)tmpa->DllBase;
		Win32kfullSize = (ULONG_PTR)tmpa->SizeOfImage;
		HYPERPLATFORM_LOG_INFO("WIN32kfullBase %llx", Win32kfullBase);
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
		HYPERPLATFORM_LOG_INFO("WIN32kbaseBase %llx", Win32kbaseBase);
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
	constexpr const ULONG signatureSize = sizeof(KiSystemServiceStartPattern);
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
		return STATUS_UNSUCCESSFUL;
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

	// 定位MmAccessFault
	const std::vector<std::string> MmAccessFaultPattern = { 
		// Windows10 17763 
		"\x40\x55\x53\x56\x57\x41\x54\x41\x56\x48\x8D\x6C\x24\xcc\x48\x81\xEC\xcc\xcc\xcc\xcc\x48\x8B\x05\xcc\xcc\xcc\xcc\x48\x33\xC4\x48\x89\x45\xcc\x45\x33\xE4\x41\x0F\xBE\xF0",
		// Windows11 22621
		"\x40\x55\x53\x56\x57\x41\x56\x48\x8D\x6C\x24\xcc\x48\x81\xEC\xcc\xcc\xcc\xcc\x48\x8B\x05\xcc\xcc\xcc\xcc\x48\x33\xC4\x48\x89\x45\xcc\x0F\xB6\xC1" };

	for (auto Pattern : MmAccessFaultPattern) {
		BBScanSection((char*)".text", (unsigned char*)(Pattern.c_str()), '\xcc', Pattern.size(), (PVOID*)&MmAccessFault);
	}
	if (MmAccessFault) {
		HYPERPLATFORM_LOG_INFO("MmAccessFault %llx", MmAccessFault);
	}
	else {
		HYPERPLATFORM_LOG_ERROR("Cant Find MmAccessFault");
		return STATUS_UNSUCCESSFUL;
	}


	const std::vector<std::string> MmAttachSessionPattern = {
		"\x4C\x8B\xDC\x49\x89\x5B\xcc\x49\x89\x6B\xcc\x49\x89\x73\xcc\x57\x41\x56\x41\x57\x48\x83\xEC\xcc\x65\x48\x8B\x04\x25\xcc\xcc\xcc\xcc\x4C\x8B\xFA",
		"\x4C\x8B\xDC\x49\x89\x5B\xcc\x49\x89\x6B\xcc\x49\x89\x73\xcc\x57\x41\x56\x41\x57\x48\x83\xEC\xcc\x48\x8B\xB9"

	};

	for (auto Pattern : MmAttachSessionPattern) {
		BBScanSection((char*)".text", (unsigned char*)(Pattern.c_str()), '\xcc', Pattern.size(), (PVOID*)&MmAttachSession);
	}
	if (MmAttachSession) {
		HYPERPLATFORM_LOG_INFO("MmAttachSession %llx", MmAttachSession);
	}
	else {
		HYPERPLATFORM_LOG_ERROR("Cant Find MmAttachSession");
		return STATUS_UNSUCCESSFUL;
	}

	const std::vector<std::string> MmDetachSessionPattern = {
		"\x48\x89\x5C\x24\xcc\x48\x89\x74\x24\xcc\x57\x48\x83\xEC\xcc\x48\x8B\x99\xcc\xcc\xcc\xcc\x48\x8B\xF2\x48\x8D\x54\x24",
		"\x4C\x8B\xDC\x49\x89\x5B\xcc\x49\x89\x73\xcc\x57\x48\x83\xEC\xcc\x48\x8B\x99\xcc\xcc\xcc\xcc\x0F\x57\xC0"
	};
	
	for (auto Pattern : MmDetachSessionPattern) {
		BBScanSection((char*)".text", (unsigned char*)(Pattern.c_str()), '\xcc', Pattern.size(), (PVOID*)&MmDetachSession);
	}

	if (MmDetachSession) {
		HYPERPLATFORM_LOG_INFO("MmDetachSession %llx", MmDetachSession);
	}
	else {
		HYPERPLATFORM_LOG_ERROR("Cant Find MmDetachSession");
		return STATUS_UNSUCCESSFUL;
	}


	SystemCallFake.Construct();

	if (!sssdt::GetKeServiceDescriptorTableShadow(&SSSDTAddress)) {
		HYPERPLATFORM_LOG_ERROR("Cant Find SSSDT Address");
		return STATUS_UNSUCCESSFUL;
	}
	else {
		HYPERPLATFORM_LOG_INFO("SSSDT Address %llx", SSSDTAddress);
	}

	if (!ssdt::GetKeServiceDescriptorTable(&SSDTAddress)) {
		HYPERPLATFORM_LOG_ERROR("Cant Find SSDT Address");
		return STATUS_UNSUCCESSFUL;
	}
	else {
		HYPERPLATFORM_LOG_INFO("SSDT Address %llx", SSDTAddress);
	}

	g_CsrssPid = GetCrsPid();
	if (g_CsrssPid) {
		HYPERPLATFORM_LOG_INFO("g_CsrssPid %d", g_CsrssPid);
	}
	else {
		HYPERPLATFORM_LOG_ERROR("Cant Find csrss.exe");
		return STATUS_UNSUCCESSFUL;
	}

	ssdt::InitGetSymbolTable();


	return STATUS_SUCCESS;
}

void EnableSystemCallHook()
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


extern LARGE_INTEGER Mm30Milliseconds;
void RemoveSyscallHook() {
	HYPERPLATFORM_LOG_INFO_SAFE("RemoveSyscallHook enter");
	while (SyscallRefCount > 0)
	{
		HYPERPLATFORM_LOG_INFO_SAFE("%s reference count is %d , delay 30ms", SyscallRefCount);
		KeDelayExecutionThread(KernelMode, false, &Mm30Milliseconds);
	}
	
	auto irql = WPOFFx64();
	memcpy((PVOID)KiSystemServiceStart, SystemCallRecoverCode, sizeof(SystemCallRecoverCode));
	WPONx64(irql);
	if (SystemCallFake.fp.PageContent)
		ExFreePool(SystemCallFake.fp.PageContent);

}

// https://j00ru.vexillium.org/syscalls/nt/64/
void SystemCallHandler(KTRAP_FRAME* TrapFrame)
{
	// 内核模式的Zw*函数会设置KernelMode,然后走KiSystemServiceStart
	// 这里监控syscall不需要内核的事件
	if (ExGetPreviousMode() != UserMode)
		return;

	ULONG_PTR Rcx = TrapFrame->Rcx;
	ULONG_PTR Rdx = TrapFrame->Rdx;

	// syscall它其实不一定会保存r8\r9寄存器在TrapFrame里,取决于KTHREAD.DISPATCHER_HEADER.DebugActive
	ULONG_PTR R8 = AsmReadR8();
	ULONG_PTR R9 = AsmReadR9();

	ULONG_PTR arg5 = *(ULONG_PTR*)(TrapFrame->Rsp + 0x28);
	ULONG_PTR arg6 = *(ULONG_PTR*)(TrapFrame->Rsp + 0x30);
	ULONG_PTR arg7 = *(ULONG_PTR*)(TrapFrame->Rsp + 0x38);
	ULONG_PTR arg8 = *(ULONG_PTR*)(TrapFrame->Rsp + 0x40);
	ULONG_PTR arg9 = *(ULONG_PTR*)(TrapFrame->Rsp + 0x48);
	ULONG_PTR arg10 = *(ULONG_PTR*)(TrapFrame->Rsp + 0x50);
	ULONG_PTR arg11 = *(ULONG_PTR*)(TrapFrame->Rsp + 0x58);


	InterlockedAdd(&SyscallRefCount, -1);
	auto _ = make_scope_exit([&]() {
		InterlockedAdd(&SyscallRefCount, 1);
		});

	if (GlobalConfig.syscall.size()) {
		if (_ismatch((char*)PsGetProcessImageFileName(IoGetCurrentProcess()), (char*)GlobalConfig.syscall.c_str()) > 0) {
			PETHREAD Thread = PsGetCurrentThread();
			PULONG PSystemCallNumber = (PULONG)((char*)Thread + SystemCallNumberOffset);

			// SSDT
			if (*PSystemCallNumber < 0x1000) {
				PVOID TargetFunction = ssdt::GetSSDTEntry(*PSystemCallNumber);
				UNREFERENCED_PARAMETER(TargetFunction);

				std::string TargetFunctionName = ssdt::GetSymbolFromAddress(*PSystemCallNumber);

				HYPERPLATFORM_LOG_INFO_SAFE("%s : ", TargetFunctionName.size() ? TargetFunctionName.c_str() : "-");

				// 打印参数,一般来说NT函数最多的参数数量是11个
				LogSysArgs(Rcx, 1);
				LogSysArgs(Rdx, 2);
				LogSysArgs(R8, 3);
				LogSysArgs(R9, 4);
				LogSysArgs(arg5, 5);
				LogSysArgs(arg6, 6);
				LogSysArgs(arg7, 7);
			}



			// SSSDT
			else {

			}

		}
	}
}

void LogSysArgs(ULONG_PTR Arg, ULONG Count) {
	Type type = GuessAddressType(Arg);
	if (type == TypeUnknow) {
		HYPERPLATFORM_LOG_INFO_SAFE("arg%d -> %llx", Count, Arg);
	}
	else if (type == TypeUnknowPtr) {
		char* print = (char*)ExAllocatePoolWithTag(NonPagedPool, GlobalConfig.hexbytes + 1, 'sys');
#define MAX_PRINT 2048
		int len = 0;
		char print_hex[PAGE_SIZE] = {};
		if (GlobalConfig.hexbytes > MAX_PRINT)
		{
			return;
		}
		if (!print) {
			return;
		}
		for (int i = 0; i < GlobalConfig.hexbytes; i++) {
			unsigned c = *((unsigned char*)Arg + i);
			if (IS_PRINTABLE(c)) {
				print[i] = c;
			}
			else {
				print[i] = '.';
			}
			len += sprintf_s(print_hex + len, MAX_PRINT - len, "%02X ", c);
		}

		HYPERPLATFORM_LOG_INFO_SAFE("arg%d -> Ptr %p -> %s -> %s", Count, Arg, print, print_hex);

		ExFreePoolWithTag(print, 'sys');
	}
	else if (type == TypePUNICODE_STRING) {
		HYPERPLATFORM_LOG_INFO_SAFE("arg%d -> %wZ", Count, Arg);
	}
	else if (type == TypePOBJECT_ATTRIBUTES) {
		HYPERPLATFORM_LOG_INFO_SAFE("arg%d -> %wZ", Count, ((POBJECT_ATTRIBUTES)Arg)->ObjectName);
	}
}