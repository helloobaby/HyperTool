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
#include <stdarg.h>
#include <ntstrsafe.h>
#include <intrin.h>
#include <cassert>

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

// From Driver.cpp
struct tagRepeatMsg {
	~tagRepeatMsg() {}
	ULONG Hash1;
	ULONG IoCtlCode;
};
extern std::vector<tagRepeatMsg> RepeatMsgCache;
extern FAST_MUTEX RepeatMsgCacheLock;

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

	// ���ָ����������ҳ�Ŀ�ʼ��
	auto tmp = (PVOID)(((ULONG_PTR)(this->fp).GuestVA >> 12) << 12);
	
	// GuestPAΪGuestVA���ҳ����ʼ�������ַ
	// GuestVA�����ʼ�����ܸı�
	//
	// ���pte.vaildΪ0��MmGetPhysicalAddress����0
	//
	this->fp.GuestPA = MmGetPhysicalAddress(tmp);
	if (!this->fp.GuestPA.QuadPart)
	{
		HYPERPLATFORM_LOG_WARN("ServiceHook::Construct fail , Address %p is invalid", tmp);
		return;
	}
	this->fp.PageContent = ExAllocatePoolWithQuotaTag(NonPagedPool, PAGE_SIZE,'zxc');

	// ����ԭҳ������
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
	* 1.����һ����̬�ڴ�(Orixxxxx)���溯����ͷ����12���ֽ�,���ü���һ��jmpxxx���ֽڣ���ΪOri����jmp��ȥ
	* 2.Ȼ���޸ĺ�����ͷΪmove rax,xx jump rax,xx
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

	vServcieHook.push_back(*this);
	memcpy((PVOID)this->fp.GuestVA, hook, sizeof(hook));   // ʵ��hook

	WPONx64(irql);

	ExclReleaseExclusivity(exclusivity);
}

void ServiceHook::Destruct()
{
	// ���⻯��hook�����ô�ͳ��hook���,����ept֮���������
	//NTSTATUS Status = HkRestoreFunction((this->fp).GuestVA, this->TrampolineFunc);

	if (KeGetCurrentIrql() >= DISPATCH_LEVEL)
		KeLowerIrql(APC_LEVEL);

	//
	// �ⲿ�ִ���������÷�ҳ���ڴ滻��������������߳��л��ͻ�������
	//
	char tmp[1];
	memcpy(tmp, this->fp.GuestVA, 1);

	// û������
	if (!MmIsAddressValid(this->fp.GuestVA))
	{
		HYPERPLATFORM_LOG_WARN("GuestVA %llx is invalid", this->fp.GuestVA);
		return;
	}

	while (this->refCount > 0)
	{
		HYPERPLATFORM_LOG_INFO("%s reference count is %d , delay 30ms", this->funcName.c_str(), this->refCount);
		KeDelayExecutionThread(KernelMode, false, &Mm30Milliseconds);
	}

	//
	auto Exclu = ExclGainExclusivity();

	auto irql = WPOFFx64();
	memcpy(this->fp.GuestVA, *(this->TrampolineFunc), this->HookCodeLen);
	WPONx64(irql);
	ExclReleaseExclusivity(Exclu);

	ExFreePool(*(this->TrampolineFunc));
}

//
// ��ʼhook
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
	memset(&tmp, 0, sizeof(tmp));
	tmp.DetourFunc = Detour;
	tmp.fp.GuestVA = HookFuncStart;
	tmp.TrampolineFunc = TramPoline;
	tmp.funcName = funcName;
	tmp.Construct();
}

//
// ж��hook
//
void RemoveServiceHook()
{
	HYPERPLATFORM_LOG_INFO("RemoveServiceHook enter");
	for (auto& hook : vServcieHook)
	{
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
	NTSTATUS Status;  // ������ϵͳ��ԭ���Ĳ�����
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
			ExFreePoolWithTag(objectNameInfo, 'kooh');
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
				'kooh'
			);
			if (objectNameInfo != NULL)
			{
				// �ٴε��û�ȡ��������
				MyStatus = ObQueryNameString(LocalFileObject->DeviceObject, objectNameInfo, ReturnLength, &ReturnLength);
			}
		}
	}

	auto _Hook_Log = [&]() {
		tagRepeatMsg t;
		ExAcquireFastMutex(&RepeatMsgCacheLock);
		auto _ = make_scope_exit([&]() {
			ExReleaseFastMutex(&RepeatMsgCacheLock);
			});
		ULONG Hash1 = 0;
		RtlHashUnicodeString(ProcessName, true, HASH_STRING_ALGORITHM_DEFAULT, &Hash1);
		t.Hash1 = Hash1;
		t.IoCtlCode = IoControlCode;

		for (auto s : RepeatMsgCache) {
			if (s.Hash1 == t.Hash1 && s.IoCtlCode == t.IoCtlCode)
				return;
		}

		RepeatMsgCache.push_back(t);

		// ���ڻ�����,��¼
		// ������;�ļ���;������;������;�豸��;���뻺��������
		HYPERPLATFORM_LOG_INFO("%wZ;%wZ;%x;%wZ;%wZ;%x;%x", ProcessName, &LocalFileObject->FileName, IoControlCode, &LocalFileObject->DeviceObject->DriverObject->DriverName, objectNameInfo->Name, InputBufferLength,OutputBufferLength);
	};

	if (ProcessName && NT_SUCCESS(MyStatus)) {
		// �����б�Ϊ��\����hook��־
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