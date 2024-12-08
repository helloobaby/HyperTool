#pragma once
#include "include/stdafx.h"
#include "include/string.hpp"

// 一般卸载的时候置为True
inline bool ConfigExitVar = false;

// 系统线程句柄
inline HANDLE hConfigThread;

void ConfigUpdateThread(
	PVOID StartContext
);

struct tagGlobalAPIHookConfig {
	tagGlobalAPIHookConfig() = default;
	~tagGlobalAPIHookConfig() = default;
	std::string path;
};

struct tagSyscallHookConfig {
	tagSyscallHookConfig() = default;
	~tagSyscallHookConfig() = default;
	std::string path;
	int hexbytes;

};

struct tagGlobalConfig {
	tagGlobalConfig() = default;
	~tagGlobalConfig() = default;

	tagGlobalAPIHookConfig APIHook;
	tagSyscallHookConfig SyscallHook;
	std::string anti_capture_white;  
};

HANDLE OpenFile(wchar_t* filepath);
ULONG GetFileSize(HANDLE pFileHandle);
NTSTATUS ReadFile(HANDLE pFileHandle, void* buffer, unsigned long size);
NTSTATUS CloseFile(HANDLE pFileHandle);