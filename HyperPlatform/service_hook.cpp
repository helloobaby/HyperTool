#include"service_hook.h"
#include"include/stdafx.h"
#include"include/vector.hpp"
#include"include/exclusivity.h"
#include"include/write_protect.h"
#include"kernel-hook/khook/hde/hde.h"
#include"include/handle.h"
#include"include/PDBSDK.h"
#include"common.h"

extern "C"
{
#include"kernel-hook/khook/khook/hk.h"
extern ULONG_PTR KernelBase;
extern ULONG_PTR PspCidTable;
}

#define PAGE_FAULT_READ 0


const char* test_process = "Dbgview.exe";

const char* target_process = "csgo.exe";

//还有个快捷方式，如果需要测试的话
//
//#define target_process test_process
//



using std::vector; 
vector<ServiceHook> vServcieHook;
hde64s gIns;




#pragma optimize( "", off )
void ServiceHook::Construct()
{
	if (!this->DetourFunc || !this->TrampolineFunc || !this->fp.GuestVA)
	{
		Log("DetourFunc or TrampolineFunc or fp.GuestVA is null!\n");
		Log("DetourFunc %p\nTrampolineFunc %p\nfp.GuestVA %p\n",
			this->DetourFunc, this->TrampolineFunc, this->fp.GuestVA);
		return;
	}


#if 1
	/**
	* Q:MmGetPhysicalAddress(NtCreateThread)返回的物理地址为0
	*   MmGetPhysicalAddress(NtCreateThreadEx)返回的物理地址不为0
	* 
	* A:
	* 1: kd> u ntcreatethread
	nt!NtCreateThread:
	fffff807`1a6948f0 ??              ???


0: kd> !pte fffff807`1a6948f0
										   VA fffff8071a6948f0
PXE at FFFFFCFE7F3F9F80    PPE at FFFFFCFE7F3F00E0    PDE at FFFFFCFE7E01C698    PTE at FFFFFCFC038D34A0
contains 0000000001208063  contains 0000000001209063  contains 0000000001217063  contains 0000FEF300002064
pfn 1208      ---DA--KWEV  pfn 1209      ---DA--KWEV  pfn 1217      ---DA--KWEV  not valid
																				  PageFile:  2
																				  Offset: def3
																				  Protect: 3 - ExecuteRead
	其实这里的分页就是现代操作系统的内存压缩。

	*/


#endif

	//获得指定函数所在页的开始处
	auto tmp = (PVOID)(((ULONG_PTR)(this->fp).GuestVA >> 12) << 12);
	//GuestPA为GuestVA这个页面起始的物理地址
	//GuestVA必须初始化后不能改变
	this->fp.GuestPA = MmGetPhysicalAddress(tmp);
#if 1 //提供分页函数支持
	if (!pfMmAccessFault)
		pfMmAccessFault = (MmAccessFaultType)(KernelBase + OffsetMmAccessFault);

	if (!this->fp.GuestPA.QuadPart)
	{
		pfMmAccessFault(PAGE_FAULT_READ, this->fp.GuestVA, KernelMode, NULL);
		//再提供一次机会
		this->fp.GuestPA = MmGetPhysicalAddress(tmp);
	}
#endif
	this->fp.PageContent = ExAllocatePoolWithQuota(NonPagedPool, PAGE_SIZE);
	memcpy(this->fp.PageContent, tmp, PAGE_SIZE);
	this->fp.PageContentPA = MmGetPhysicalAddress(this->fp.PageContent);
	if (!fp.GuestPA.QuadPart || !fp.PageContentPA.QuadPart)
	{
		HYPERPLATFORM_COMMON_DBG_BREAK();
		Log("MmGetPhysicalAddress error %s %d\n",__func__,__LINE__);
		return;
	}

	auto exclusivity = ExclGainExclusivity();
	//
	//
	//mov rax,xx
	//jmp rax
	//
	//
	static char hook[] = { 0x48,0xB8,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0xFF,0xE0 };
	size_t CodeLength = 0;
	while (CodeLength < 12)
	{
		HdeDisassemble((void*)((ULONG_PTR)(this->fp.GuestVA) + CodeLength), &gIns);
		CodeLength += gIns.len;
	}
	this->HookCodeLen = CodeLength;
	/*
	* 1.分配一个动态内存(Orixxxxx)保存函数开头至少12个字节,还得加上一个jmpxxx的字节，因为Ori还得jmp回去
	* 2.然后修改函数开头为move rax,xx jump rax,xx
	* 3.
	*/

	*(this->TrampolineFunc) = ExAllocatePoolWithTag(NonPagedPool, CodeLength + 14, 'a');
	if (!*(this->TrampolineFunc))
	{
		Log("ExAllocatePoolWithTag failed ,no memory!\n");
		return;
	}
	
	memcpy(*(this->TrampolineFunc), this->fp.GuestVA, CodeLength);
	static char hook2[] = { 0xff,0x25,0,0,0,0,1,1,1,1,1,1,1,1 };
	ULONG_PTR jmp_return = (ULONG_PTR)this->fp.GuestVA + CodeLength;
	memcpy(hook2 + 6, &jmp_return, 8);
	memcpy((void*)((ULONG_PTR)(*(this->TrampolineFunc)) + CodeLength), hook2, 14);
	auto irql = WPOFFx64();

	PVOID* Ptr = &this->DetourFunc;
	memcpy(hook + 2, Ptr, 8);
	memcpy((PVOID)this->fp.GuestVA, hook, sizeof(hook));

	WPONx64(irql);


	ExclReleaseExclusivity(exclusivity);


	this->isEverythignSuc = true;

}
#pragma optimize( "", on )

void ServiceHook::Destruct()
{
	if (!this->isEverythignSuc)
		return;

#if 0
	NTSTATUS Status = HkRestoreFunction((this->fp).GuestVA, this->TrampolineFunc);
	if (!NT_SUCCESS(Status)) {
		Log("HkRestoreFunction Failed %x\n", Status);
		return;
	}
#endif
	auto Exclu = ExclGainExclusivity();
	//
	//这里要判断一下GuestVA是不是页无效状态
	//不能在提irql完再MmAccessFault
	//
	if(!MmIsAddressValid(this->fp.GuestVA))
	pfMmAccessFault(PAGE_FAULT_READ, this->fp.GuestVA, KernelMode, NULL);

	if (!MmIsAddressValid(this->fp.GuestVA))
	{
		Log("[fatal error]Page cant go in memory!\n");
		return;
	}

	auto irql = WPOFFx64();
	memcpy(this->fp.GuestVA, *(this->TrampolineFunc), this->HookCodeLen);
	WPONx64(irql);
	ExclReleaseExclusivity(Exclu);
	ExFreePool(*(this->TrampolineFunc));

}

void AddServiceHook(PVOID HookFuncStart, PVOID Detour, PVOID *TramPoline)
{
	ServiceHook tmp;
	tmp.DetourFunc = Detour;
	tmp.fp.GuestVA = HookFuncStart;
	tmp.TrampolineFunc = TramPoline;
	tmp.Construct();
	vServcieHook.push_back(tmp);
}

void RemoveServiceHook()
{
	for (auto& hook : vServcieHook)
	{
		hook.Destruct();
	}
}

//
//hook example
//

NTSTATUS DetourNtOpenProcess(
	PHANDLE            ProcessHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PCLIENT_ID         ClientId
)
{
#ifdef DBG

	static int once = 0;
	if (!(once++))
		Log("%s\n", __func__);

#endif // DBG

	return OriNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}

NTSTATUS DetourNtCreateFile(
	PHANDLE            FileHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK   IoStatusBlock,
	PLARGE_INTEGER     AllocationSize,
	ULONG              FileAttributes,
	ULONG              ShareAccess,
	ULONG              CreateDisposition,
	ULONG              CreateOptions,
	PVOID              EaBuffer,
	ULONG              EaLength
)
{
#ifdef DBG
	static int once = 0;
	if (!(once++))
		Log("%s\n", __func__);
#endif // DBG

	return OriNtCreateFile(
		FileHandle,
		DesiredAccess,
		ObjectAttributes,
		IoStatusBlock,
		AllocationSize,
		FileAttributes,
		ShareAccess,
		CreateDisposition,
		CreateOptions,
		EaBuffer,
		EaLength);
}

//
//监视用户态内存写入
//
NTSTATUS DetourNtWriteVirtualMemory(
	IN HANDLE ProcessHandle,
	OUT PVOID BaseAddress,
	IN CONST VOID* Buffer,
	IN SIZE_T BufferSize,
	OUT PSIZE_T NumberOfBytesWritten OPTIONAL
)
{
#ifdef DBG
	static int once = 0;
	if (!(once++))
		Log("%s\n", __func__);
#endif // DBG

	NTSTATUS Status STATUS_UNSUCCESSFUL;

	PEPROCESS Process = NULL;
	Status = ObReferenceObjectByHandle(ProcessHandle,
		PROCESS_VM_WRITE,
		*PsProcessType,
		UserMode,
		(PVOID*)&Process,
		NULL);

	if (Process)
	{
		unsigned char* Image = PsGetProcessImageFileName(Process);

		if (!strcmp((const char*)Image, target_process))
		{
			Log("[%s]\nBaseAddress %llx BufferSize %llx\n",__func__, BaseAddress, BufferSize);
		}








	}
	return OriNtWriteVirtualMemory(
		ProcessHandle,
		BaseAddress,
		Buffer,
		BufferSize,
		NumberOfBytesWritten);
}

NTSTATUS DetourNtCreateThreadEx(
	OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN PVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN PVOID lpStartAddress,
	IN PVOID lpParameter,
	IN ULONG Flags,
	IN SIZE_T StackZeroBits,
	IN SIZE_T SizeOfStackCommit,
	IN SIZE_T SizeOfStackReserve,
	OUT PVOID lpBytesBuffer)
{
#ifdef DBG
	static int once = 0;
	if (!(once++))
		Log("%s\n", __func__);
#endif // DBG

	NTSTATUS Status STATUS_UNSUCCESSFUL;

	PEPROCESS Process = NULL;
	Status = ObReferenceObjectByHandle(ProcessHandle,
		PROCESS_VM_WRITE,
		*PsProcessType,
		UserMode,
		(PVOID*)&Process,
		NULL);

	if (Process)
	{
		unsigned char* Image = PsGetProcessImageFileName(Process);
		const unsigned char* Image2 = PsGetProcessImageFileName(IoGetCurrentProcess());

		if (!strcmp((const char*)Image, target_process) && strcmp((const char*)Image2, target_process))
		{
			Log("[csgo]\nThreadProcedure %llx\n", lpStartAddress);

			if (lpParameter)
				Log("lpParameter value is %llx\n", lpParameter);


		}


	}
	

	return OriNtCreateThreadEx(
		hThread, 
		DesiredAccess,
		ObjectAttributes, 
		ProcessHandle,
		lpStartAddress,
		lpParameter,
		Flags,
		StackZeroBits, 
		SizeOfStackCommit, 
		SizeOfStackReserve,
		lpBytesBuffer);
}

//监控内存分配
NTSTATUS DetourNtAllocateVirtualMemory(
	HANDLE    ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T   RegionSize,
	ULONG     AllocationType,
	ULONG     Protect
)
{
#ifdef DBG
	static int once = 0;
	if (!(once++))
		Log("%s\n", __func__);
#endif // DBG

	NTSTATUS Status STATUS_UNSUCCESSFUL;

	PEPROCESS Process = NULL;
	Status = ObReferenceObjectByHandle(ProcessHandle,
		PROCESS_VM_WRITE,
		*PsProcessType,
		UserMode,
		(PVOID*)&Process,
		NULL);

	if (Process)
	{
		unsigned char* Image = PsGetProcessImageFileName(Process);
		const unsigned char* Image2 = PsGetProcessImageFileName(IoGetCurrentProcess());
		if (!strcmp((const char*)Image, target_process) && strcmp((const char*)Image2, target_process))
		{
			Log("[%s]\nAlloc RegionSize %p\n", __func__, *RegionSize);
		}


	}






	return OriNtAllocateVirtualMemory(
		ProcessHandle,
		BaseAddress,
		ZeroBits,
		RegionSize,
		AllocationType,
		Protect);
}


NTSTATUS DetourNtCreateThread(
	OUT PHANDLE ThreadHandle,
	IN  ACCESS_MASK DesiredAccess,
	IN  POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN  HANDLE ProcessHandle,
	OUT PCLIENT_ID ClientId,
	IN  PCONTEXT ThreadContext,
	IN  PVOID InitialTeb,
	IN  BOOLEAN CreateSuspended
)
{
#ifdef DBG
	static int once = 0;
	if (!(once++))
		Log("%s\n", __func__);
#endif // DBG


	NTSTATUS Status STATUS_UNSUCCESSFUL;

	PEPROCESS Process = NULL;
	Status = ObReferenceObjectByHandle(ProcessHandle,
		PROCESS_VM_WRITE,
		*PsProcessType,
		UserMode,
		(PVOID*)&Process,
		NULL);

	if (Process)
	{
		unsigned char* Image = PsGetProcessImageFileName(Process);
		const unsigned char* Image2 = PsGetProcessImageFileName(IoGetCurrentProcess());

		if (!strcmp((const char*)Image, target_process) && strcmp((const char*)Image2, target_process))
		{
			Log("[%s]\nThreadProcedure %llx\n",__func__ ,ThreadContext->Rcx);
		}


	}

	return OriNtCreateThread(
		ThreadHandle,
		DesiredAccess,
		ObjectAttributes,
		ProcessHandle,
		ClientId,
		ThreadContext,
		InitialTeb,
		CreateSuspended
	);
}