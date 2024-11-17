#pragma once
#include "include/vector.hpp"
#include "include/string.hpp"
#include "util.h"
#include "FakePage.h"
#include <stdint.h>



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
extern std::vector<ServiceHook> vServcieHook;
#define ENTER_HOOK(FUNC_NAME)  			for (auto &h : vServcieHook) {					\
				if (!strcmp(h.funcName.c_str(), FUNC_NAME)) {		\
					InterlockedAdd(&h.refCount, 1);			\
				}											\
			}												\
			auto a7808419_a956_4174_865a_4e62a3e7f969 = make_scope_exit([&]() {				\
				for (auto& h : vServcieHook) {				\
					if (!strcmp(h.funcName.c_str(), FUNC_NAME)) { \
						InterlockedAdd(&h.refCount, -1);	\
					}										\
				}											\
				});											

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
