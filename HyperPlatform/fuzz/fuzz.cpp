#include "fuzz.h"
#include "../service_hook.h"
#include "../util.h"
namespace fuzz{
	namespace {
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













	void FuzzInit() {
		AddServiceHook(UtilGetSystemProcAddress(L"NtDeviceIoControlFile"), DetourNtDeviceIoControlFile, (PVOID*)&OriNtDeviceIoControlFile, "NtDeviceIoControlFile");
	}

}
