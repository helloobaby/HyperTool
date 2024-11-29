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


struct tagGlobalConfig {
	tagGlobalConfig() = default;
	~tagGlobalConfig() = default;
	bool hooks_log;
	std::string path;     // hook的过滤路径
	std::string capture;  // 截屏的白名单
};

HANDLE OpenFile(wchar_t* filepath);
ULONG GetFileSize(HANDLE pFileHandle);
NTSTATUS ReadFile(HANDLE pFileHandle, void* buffer, unsigned long size);
NTSTATUS CloseFile(HANDLE pFileHandle);