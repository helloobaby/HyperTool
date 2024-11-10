#include "service_hook.h"
#include "include/stdafx.h"
#include "include/vector.hpp"
#include "include/exclusivity.h"
#include "include/write_protect.h"
#include "kernel-hook/khook/hde/hde.h"
#include "include/handle.h"
#include "common.h"
#include "log.h"
#include "util.h"
#include "config.h"

extern "C"
{
#include"kernel-hook/khook/khook/hk.h"
#include "minirtl/minirtl.h"
extern ULONG_PTR KernelBase;
extern ULONG_PTR PspCidTable;
extern ULONG_PTR Win32kfullBase;
extern ULONG Win32kfullSize;
}

extern tagGlobalConfig GlobalConfig;
extern std::vector<std::string> TraceProcessPathList;


using std::vector; 
vector<ServiceHook> vServcieHook;
hde64s gIns;

LARGE_INTEGER MmOneSecond = { (ULONG)(-1 * 1000 * 1000 * 10), -1 };
LARGE_INTEGER MmTwentySeconds = { (ULONG)(-20 * 1000 * 1000 * 10), -1 };
LARGE_INTEGER MmShortTime = { (ULONG)(-10 * 1000 * 10), -1 }; // 10 milliseconds
LARGE_INTEGER MmHalfSecond = { (ULONG)(-5 * 100 * 1000 * 10), -1 };
LARGE_INTEGER Mm30Milliseconds = { (ULONG)(-30 * 1000 * 10), -1 };


void ServiceHook::Construct()
{
	if (!this->DetourFunc || !this->TrampolineFunc || !this->fp.GuestVA)
	{
		HYPERPLATFORM_LOG_WARN("ServiceHook::Construct fail");
		return;
	}

	HYPERPLATFORM_LOG_INFO("ServiceHook::Construct %s", this->funcName.c_str());

	// 获得指定函数所在页的开始处
	auto tmp = (PVOID)(((ULONG_PTR)(this->fp).GuestVA >> 12) << 12);
	
	// GuestPA为GuestVA这个页面起始的物理地址
	// GuestVA必须初始化后不能改变
	//
	//如果pte.vaild为0，MmGetPhysicalAddress返回0
	//
	this->fp.GuestPA = MmGetPhysicalAddress(tmp);
	if (!this->fp.GuestPA.QuadPart)
	{
		HYPERPLATFORM_LOG_WARN("ServiceHook::Construct fail , Address %p is invalid", tmp);
		return;
	}
	this->fp.PageContent = ExAllocatePoolWithQuotaTag(NonPagedPool, PAGE_SIZE,'zxc');

	// 拷贝原页面内容
	memcpy(this->fp.PageContent, tmp, PAGE_SIZE);

	// 
	this->fp.PageContentPA = MmGetPhysicalAddress(this->fp.PageContent);
	if (!this->fp.PageContentPA.QuadPart){
		HYPERPLATFORM_LOG_WARN("ServiceHook::Construct fail , Address %p is invalid", this->fp.PageContentPA.QuadPart);
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
	this->HookCodeLen = (ULONG)CodeLength;

	/*
	* 1.分配一个动态内存(Orixxxxx)保存函数开头至少12个字节,还得加上一个jmpxxx的字节，因为Ori还得jmp回去
	* 2.然后修改函数开头为move rax,xx jump rax,xx
	*/

	*(this->TrampolineFunc) = ExAllocatePoolWithTag(NonPagedPool, CodeLength + 14, 'zxc');
	if (!*(this->TrampolineFunc))
	{
		HYPERPLATFORM_LOG_INFO("ExAllocatePoolWithTag failed ,no memory!");
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

	// 
	this->isEverythignSuc = true;
}

void ServiceHook::Destruct()
{
	if (!this->isEverythignSuc) {
		HYPERPLATFORM_LOG_WARN("ServiceHook::Destruct skip");
		return;
	}

	// 虚拟化的hook不能用传统的hook框架,开了ept之后会有问题
	//NTSTATUS Status = HkRestoreFunction((this->fp).GuestVA, this->TrampolineFunc);

	if(KeGetCurrentIrql()>= DISPATCH_LEVEL)
		KeLowerIrql(APC_LEVEL);
	
	//
	// 这部分代码仅仅是让分页的内存换进来，下面禁用线程切换就换不了了
	//
	char tmp[1];
	memcpy(tmp, this->fp.GuestVA, 1);

	// 没换进来
	if (!MmIsAddressValid(this->fp.GuestVA))
	{
		HYPERPLATFORM_LOG_WARN("GuestVA %llx is invalid", this->fp.GuestVA);
		return;
	}
	//
	auto Exclu = ExclGainExclusivity();
	auto irql = WPOFFx64();
	memcpy(this->fp.GuestVA, *(this->TrampolineFunc), this->HookCodeLen);
	WPONx64(irql);
	ExclReleaseExclusivity(Exclu);

	HYPERPLATFORM_LOG_INFO("ExFreePool %p", *(this->TrampolineFunc));
	ExFreePool(*(this->TrampolineFunc));
}

//
// 开始hook
//
void AddServiceHook(PVOID HookFuncStart, PVOID Detour, PVOID *TramPoline,const char* funcName)
{
	HYPERPLATFORM_LOG_INFO("AddServiceHook %s ", funcName);
	if (!HookFuncStart)
	{
		HYPERPLATFORM_LOG_WARN("HookFuncStart is NULL");
		return;
	}

	ServiceHook tmp;
	tmp.DetourFunc = Detour;
	tmp.fp.GuestVA = HookFuncStart;
	tmp.TrampolineFunc = TramPoline;
	tmp.funcName = funcName;
	tmp.Construct();
	vServcieHook.push_back(tmp);
}

//
// 卸载hook
//
void RemoveServiceHook()
{
	HYPERPLATFORM_LOG_INFO("RemoveServiceHook enter");
	for (auto& hook : vServcieHook)
	{
		while (hook.refCount > 0)
		{
			HYPERPLATFORM_LOG_INFO("%s reference count is %d , delay 30ms",hook.funcName.c_str() ,hook.refCount);
			KeDelayExecutionThread(KernelMode, false, &Mm30Milliseconds);
		}
		hook.Destruct();
		HYPERPLATFORM_LOG_INFO("unload hook func %s success", hook.funcName.c_str());
	}
}

NTSTATUS DetourNtDeviceIoControlFile(
	_In_ HANDLE FileHandle,
	_In_opt_ HANDLE Event,
	_In_opt_ PIO_APC_ROUTINE ApcRoutine,
	_In_opt_ PVOID ApcContext,
	_Out_ PIO_STATUS_BLOCK IoStatusBlock,
	_In_ ULONG IoControlCode,
	_In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
	_In_ ULONG InputBufferLength,
	_Out_writes_bytes_opt_(OutputBufferLength) PVOID OutputBuffer,
	_In_ ULONG OutputBufferLength
) {

	NTSTATUS Status;  // 给操作系统的原本的操作码
	InterlockedAdd(&vServcieHook[NtDeviceIoControlFileHookIndex].refCount, 1);

	Status = OriNtDeviceIoControlFile(
		FileHandle,
		Event,
		ApcRoutine,
		ApcContext,
		IoStatusBlock,
		IoControlCode,
		InputBuffer,
		InputBufferLength,
		OutputBuffer,
		OutputBufferLength);

	PFILE_OBJECT LocalFileObject;
	PUNICODE_STRING ProcessName = UtilGetProcessNameByEPROCESS(IoGetCurrentProcess());
	NTSTATUS MyStatus = ObReferenceObjectByHandle(FileHandle, GENERIC_READ, *IoFileObjectType, KernelMode, (PVOID*)&LocalFileObject, NULL);
	OBJECT_NAME_INFORMATION* objectNameInfo = NULL;
	ULONG ReturnLength;
	auto _ = make_scope_exit([&]() {
		if (objectNameInfo) {
			ExFreePoolWithTag(objectNameInfo, L'GetDeviceObjectName');
		}
		InterlockedAdd(&vServcieHook[NtDeviceIoControlFileHookIndex].refCount, -1); 
		});

	if (NT_SUCCESS(MyStatus) && LocalFileObject->DeviceObject) {
		MyStatus = ObQueryNameString(LocalFileObject->DeviceObject, NULL, 0, &ReturnLength);
		if (MyStatus == STATUS_INFO_LENGTH_MISMATCH)
		{
			objectNameInfo = (OBJECT_NAME_INFORMATION*)ExAllocatePoolWithTag(
				NonPagedPool,
				ReturnLength,
				L'kooh'
			);
			if (objectNameInfo != NULL)
			{
				// 再次调用获取对象名称
				MyStatus = ObQueryNameString(LocalFileObject->DeviceObject, objectNameInfo, ReturnLength, &ReturnLength);
			}
		}
	}
	auto _Hook_Log = [&]() {
		// 进程名;文件名;控制码;驱动名;设备名
		HYPERPLATFORM_LOG_INFO("%wZ;%wZ;%x;%wZ;%wZ", ProcessName, &LocalFileObject->FileName, IoControlCode, &LocalFileObject->DeviceObject->DriverObject->DriverName,objectNameInfo->Name);
		};

	if (ProcessName && NT_SUCCESS(MyStatus)) {
		// 进程列表为空\开启hook日志
		if (TraceProcessPathList.empty() && GlobalConfig.hooks_log && ProcessName) {
			_Hook_Log();
		}
		else {
			for (auto process_path : TraceProcessPathList) {
				if (_strstri_a((char*)PsGetProcessImageFileName(PsGetCurrentProcess()), process_path.c_str())) {
					if (GlobalConfig.hooks_log) {
						_Hook_Log();
					}
				}
			}
		}
	}
	if (ProcessName) { RtlFreeUnicodeString(ProcessName); ExFreePool(ProcessName); }
	return Status;
}