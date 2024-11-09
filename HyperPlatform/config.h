#pragma once
#include "include/stdafx.h"

// 一般卸载的时候置为True
inline bool ConfigExitVar = false;

// 系统线程句柄
inline HANDLE hConfigThread;

void ConfigUpdateThread(
	PVOID StartContext
);


struct tagGlobalConfig {
	bool hooks_log;
};

HANDLE OpenFile(wchar_t* filepath);
ULONG GetFileSize(HANDLE pFileHandle);
NTSTATUS ReadFile(HANDLE pFileHandle, void* buffer, unsigned long size);
NTSTATUS CloseFile(HANDLE pFileHandle);