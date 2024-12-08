#include "fuzz.h"
#include "../service_hook.h"
#include "../util.h"
#include "../include/algorithm.hpp"
#include "../log.h"
#include "../regex/pcre_regex.h"
#include "../config.h"

extern tagGlobalConfig GlobalConfig;

namespace fuzz{
	namespace {
		std::vector<ULONG> RepeatMsgCache;
		FAST_MUTEX RepeatMsgCacheLock;
		using NtDeviceIoControlFileType = decltype(&NtDeviceIoControlFile);
		NtDeviceIoControlFileType OriNtDeviceIoControlFile;

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
			ENTER_HOOK("NtDeviceIoControlFile");

			PFILE_OBJECT LocalFileObject;
			PUNICODE_STRING ProcessName = UtilGetProcessNameByEPROCESS(IoGetCurrentProcess());
			NTSTATUS MyStatus = ObReferenceObjectByHandle(FileHandle, GENERIC_READ, *IoFileObjectType, KernelMode, (PVOID*)&LocalFileObject, NULL);
			OBJECT_NAME_INFORMATION* objectNameInfo = NULL;
			ULONG ReturnLength;
			auto _ = make_scope_exit([&]() {
				if (objectNameInfo) {
					ExFreePoolWithTag(objectNameInfo, 'kooh');
				}
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
						// 再次调用获取对象名称
						MyStatus = ObQueryNameString(LocalFileObject->DeviceObject, objectNameInfo, ReturnLength, &ReturnLength);
					}
				}
			}

			auto _Hook_Log = [&]() {
				ExAcquireFastMutex(&RepeatMsgCacheLock);
				auto _ = make_scope_exit([&]() {
					ExReleaseFastMutex(&RepeatMsgCacheLock);
					});
				ULONG Hash1 = 0;
				RtlHashUnicodeString(ProcessName, true, HASH_STRING_ALGORITHM_DEFAULT, &Hash1);
				if (std::find(RepeatMsgCache.begin(), RepeatMsgCache.end(), Hash1) != RepeatMsgCache.end()) {
					return;
				}
				RepeatMsgCache.push_back(Hash1);

				// 不在缓存内,记录fuzz日志
				// 进程名;文件名;控制码;驱动名;设备名;输入缓冲区长度
				HYPERPLATFORM_LOG_INFO("[fuzz-io] %wZ;%wZ;%x;%wZ;%wZ;%x;%x", ProcessName, &LocalFileObject->FileName, IoControlCode, &LocalFileObject->DeviceObject->DriverObject->DriverName, objectNameInfo->Name, InputBufferLength, OutputBufferLength);
			};

			if (ProcessName && NT_SUCCESS(MyStatus)) {
				if (GlobalConfig.APIHook.path.empty() && ProcessName) {
					_Hook_Log();
				}
			}
			if (ProcessName) { RtlFreeUnicodeString(ProcessName); ExFreePool(ProcessName); }


			return OriNtDeviceIoControlFile(
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
		}
	}













	bool FuzzInit() {
		ExInitializeFastMutex(&RepeatMsgCacheLock);
		AddServiceHook(UtilGetSystemProcAddress(L"NtDeviceIoControlFile"), DetourNtDeviceIoControlFile, (PVOID*)&OriNtDeviceIoControlFile, "NtDeviceIoControlFile");
		return true;
	}

}
