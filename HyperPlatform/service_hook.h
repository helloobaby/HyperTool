#pragma once
#include"include/vector.hpp"
#include"FakePage.h"

#define PROCESS_TERMINATE                  (0x0001)  
#define PROCESS_CREATE_THREAD              (0x0002)  
#define PROCESS_SET_SESSIONID              (0x0004)  
#define PROCESS_VM_OPERATION               (0x0008)  
#define PROCESS_VM_READ                    (0x0010)  
#define PROCESS_VM_WRITE                   (0x0020)  
#define PROCESS_DUP_HANDLE                 (0x0040)  
#define PROCESS_CREATE_PROCESS             (0x0080)  
#define PROCESS_SET_QUOTA                  (0x0100)  
#define PROCESS_SET_INFORMATION            (0x0200)  
#define PROCESS_QUERY_INFORMATION          (0x0400)  
#define PROCESS_SUSPEND_RESUME             (0x0800)  
#define PROCESS_QUERY_LIMITED_INFORMATION  (0x1000)  
#define PROCESS_SET_LIMITED_INFORMATION    (0x2000)  

struct ServiceHook : public ICFakePage
{
	~ServiceHook() {};
	virtual void Construct() override;
	virtual void Destruct() override;
	PVOID DetourFunc;
	PVOID *TrampolineFunc;
	ULONG HookCodeLen;
	bool isEverythignSuc;
};


__kernel_entry NTSYSCALLAPI NTSTATUS NtOpenProcess(
	PHANDLE            ProcessHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PCLIENT_ID         ClientId
);

 NTSYSCALLAPI NTSTATUS NtCreateFile(
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
);

 NTSTATUS NtWriteVirtualMemory(
	 IN HANDLE ProcessHandle,
	 OUT PVOID BaseAddress,
	 IN CONST VOID* Buffer,
	 IN SIZE_T BufferSize,
	 OUT PSIZE_T NumberOfBytesWritten OPTIONAL
 );

 NTSTATUS NtCreateThread(
		 OUT PHANDLE ThreadHandle,
		 IN  ACCESS_MASK DesiredAccess,
		 IN  POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
		 IN  HANDLE ProcessHandle,
		 OUT PCLIENT_ID ClientId,
		 IN  PCONTEXT ThreadContext,
		 IN  PVOID InitialTeb,
		 IN  BOOLEAN CreateSuspended
	 );

using NtCreateThreadExType = NTSTATUS(*)(
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
	OUT PVOID lpBytesBuffer);

//
//这个函数原型有点古老了。
//
NTSTATUS
MmAccessFault(
	IN ULONG_PTR FaultStatus,
	IN PVOID VirtualAddress,
	IN KPROCESSOR_MODE PreviousMode,
	IN PVOID TrapInformation
);

using NtOpenProcessType = decltype(&NtOpenProcess);
using NtCreateFileType = decltype(&NtCreateFile);
using NtWriteVirtualMemoryType = decltype(&NtWriteVirtualMemory);
using NtAllocateVirtualMemoryType = decltype(&NtAllocateVirtualMemory);
using NtCreateThreadType = decltype(&NtCreateThread);
using MmAccessFaultType = decltype(&MmAccessFault);

//
//必须保证你这个要hook的函数在给rax赋值之前不使用rax，因为我们使用rax作为跳板
//一般来说c/c++函数都不会使用rax，汇编函数就不一定了。比如系统调用时候rax为ssdt index
//
void AddServiceHook(PVOID HookFuncStart, PVOID Detour, PVOID *TramPoline);

void RemoveServiceHook();


//Example


// 
//hook NtOpenProcess
// 
inline NtOpenProcessType OriNtOpenProcess;
inline NtCreateFileType OriNtCreateFile;
inline NtWriteVirtualMemoryType OriNtWriteVirtualMemory;
inline NtCreateThreadExType OriNtCreateThreadEx;
inline NtAllocateVirtualMemoryType OriNtAllocateVirtualMemory;
inline NtCreateThreadType OriNtCreateThread;

inline MmAccessFaultType pfMmAccessFault;


NTSTATUS DetourNtOpenProcess(
	PHANDLE            ProcessHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PCLIENT_ID         ClientId
);
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
);

NTSTATUS DetourNtWriteVirtualMemory(
	IN HANDLE ProcessHandle,
	OUT PVOID BaseAddress,
	IN CONST VOID* Buffer,
	IN SIZE_T BufferSize,
	OUT PSIZE_T NumberOfBytesWritten OPTIONAL
);


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
	OUT PVOID lpBytesBuffer);

NTSTATUS DetourNtAllocateVirtualMemory(
	HANDLE    ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T   RegionSize,
	ULONG     AllocationType,
	ULONG     Protect
);

NTSTATUS DetourNtCreateThread(
	OUT PHANDLE ThreadHandle,
	IN  ACCESS_MASK DesiredAccess,
	IN  POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN  HANDLE ProcessHandle,
	OUT PCLIENT_ID ClientId,
	IN  PCONTEXT ThreadContext,
	IN  PVOID InitialTeb,
	IN  BOOLEAN CreateSuspended
);