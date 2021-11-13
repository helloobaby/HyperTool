#pragma once
#include"include/vector.hpp"
#include"FakePage.h"

typedef HANDLE  HWND;

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

typedef struct _MM_SESSION_SPACE                      // 50 elements, 0x5000 bytes (sizeof) 
{
	/*0x000*/      LONG32       ReferenceCount;
	union                                             // 2 elements, 0x4 bytes (sizeof)     
	{
		/*0x004*/          ULONG32      LongFlags;  
	}u;
	/*0x008*/      ULONG32      SessionId;
	/*0x00C*/      LONG32       ProcessReferenceToSession;
	/*0x010*/      struct _LIST_ENTRY ProcessList;                   // 2 elements, 0x10 bytes (sizeof)    
	/*0x020*/      UINT64       SessionPageDirectoryIndex;
	/*0x028*/      UINT64       NonPagablePages;
	/*0x030*/      UINT64       CommittedPages;
	/*0x038*/      VOID* PagedPoolStart;
	/*0x040*/      VOID* PagedPoolEnd;
	/*0x048*/      VOID* SessionObject;
	/*0x050*/      VOID* SessionObjectHandle;
	/*0x058*/      ULONG32      SessionPoolAllocationFailures[4];
}MM_SESSION_SPACE, * PMM_SESSION_SPACE;

struct ServiceHook : public ICFakePage
{
	~ServiceHook() {};
	virtual void Construct() override;
	virtual void Destruct() override;
	PVOID DetourFunc;
	PVOID *TrampolineFunc;
	ULONG HookCodeLen;
	bool isEverythignSuc;
	bool isWin32Hook = false;
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

 HWND NtUserFindWindowEx(  // API FindWindowA/W, FindWindowExA/W
	 IN HWND hwndParent,
	 IN HWND hwndChild,
	 IN PUNICODE_STRING pstrClassName,
	 IN PUNICODE_STRING pstrWindowName);

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

ULONG_PTR MiGetSystemRegionType(ULONG_PTR vaddress);

PEPROCESS MmGetSessionById(int sessionId);
NTSTATUS MiAttachSession(MM_SESSION_SPACE* SessionSpace);
NTSTATUS MiDetachProcessFromSession(int SessionID);

NTSTATUS
MmAccessFault(
	IN ULONG_PTR FaultStatus,
	IN KTRAP_FRAME* TrapInformation,
	IN PVOID VirtualAddress,
	IN KPROCESSOR_MODE PreviousMode
);

using NtOpenProcessType = decltype(&NtOpenProcess);
using NtCreateFileType = decltype(&NtCreateFile);
using NtWriteVirtualMemoryType = decltype(&NtWriteVirtualMemory);
using NtAllocateVirtualMemoryType = decltype(&NtAllocateVirtualMemory);
using NtCreateThreadType = decltype(&NtCreateThread);
using MmAccessFaultType = decltype(&MmAccessFault);
using NtUserFindWindowExType = decltype(&NtUserFindWindowEx);
using MiGetSystemRegionTypeType = decltype(&MiGetSystemRegionType);
using MmGetSessionByIdType = decltype(&MmGetSessionById);
using MiAttachSessionType = decltype(&MiAttachSession);
using MiDetachProcessFromSessionType = decltype(&MiDetachProcessFromSession);

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
inline NtUserFindWindowExType OriNtUserFindWindowEx;
inline MmAccessFaultType pfMmAccessFault;
inline MiGetSystemRegionTypeType pfMiGetSystemRegionType;
inline MmGetSessionByIdType pfMmGetSessionById;
inline MM_SESSION_SPACE* SystemSesstionSpace;
inline MiAttachSessionType pfMiAttachSession;
inline MiDetachProcessFromSessionType pfMiDetachProcessFromSession;

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

HWND DetourNtUserFindWindowEx(  // API FindWindowA/W, FindWindowExA/W
	IN HWND hwndParent,
	IN HWND hwndChild,
	IN PUNICODE_STRING pstrClassName,
	IN PUNICODE_STRING pstrWindowName);