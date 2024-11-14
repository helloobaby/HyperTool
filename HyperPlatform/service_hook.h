#pragma once
#include"include/vector.hpp"
#include"include/string.hpp"
#include"FakePage.h"
#include<stdint.h>

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

struct ServiceHook : public ICFakePage
{
	~ServiceHook() {};
	virtual void Construct() override;
	virtual void Destruct() override;


	std::string funcName;       // 被hook的函数名称

// 安全卸载相关
	LONG refCount = 0;			// 钩子函数的引用,为0才能安全卸载
	
//private:
	PVOID DetourFunc;
	PVOID *TrampolineFunc;
	ULONG HookCodeLen;
	bool isWin32Hook = false;   // 涉及到Win32kfull模块内函数的hook置为true
};

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
// 必须保证你这个要hook的函数在给rax赋值之前不使用rax，因为我们使用rax作为跳板
// 一般来说c/c++函数都不会使用rax，汇编函数就不一定了。比如系统调用时候rax为ssdt index
//
void AddServiceHook(PVOID HookFuncStart, PVOID Detour, PVOID *TramPoline,const char* funcName);
// 卸载所有钩子
void RemoveServiceHook();
