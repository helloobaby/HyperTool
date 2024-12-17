// Copyright (c) 2015-2019, Satoshi Tanda. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Implements an entry point of the driver.

#ifndef POOL_NX_OPTIN
#define POOL_NX_OPTIN 1
#endif
#include "include/write_protect.h"
#include "driver.h"
#include "common.h"
#include "global_object.h"
#include "hotplug_callback.h"
#include "log.h"
#include "power_callback.h"
#include "util.h"
#include "vm.h"
#include "performance.h"
#include "systemcall.h"
#include "include/global.hpp"
#include "service_hook.h"
#include "device.h"
#include "config.h"
#include "minirtl/minirtl.h"
#include "minirtl/_filename.h"
#include "regex/pcre_regex.h"
#include "fuzz/fuzz.h"
#include "anti_scrshoot.h"

extern "C"
{
#include "kernel-hook/khook/khook/hk.h"
}

// systemcall.cpp
extern NTSTATUS InitSystemVar();
extern void DoSystemCallHook();
extern fpSystemCall SystemCallFake;
extern char SystemCallRecoverCode[15];
//

extern bool is_cet_enable;

extern LARGE_INTEGER MmHalfSecond;
extern LARGE_INTEGER MmOneSecond;

PNPAGED_LOOKASIDE_LIST g_1K_LookasideList;
 
extern "C" {
////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//

////////////////////////////////////////////////////////////////////////////////
//
// constants and macros
//

////////////////////////////////////////////////////////////////////////////////
//
// types
//

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

DRIVER_INITIALIZE DriverEntry;

static DRIVER_UNLOAD DriverpDriverUnload;

_IRQL_requires_max_(PASSIVE_LEVEL) bool DriverpIsSuppoetedOS();

#if defined(ALLOC_PRAGMA)
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, DriverpDriverUnload)
#pragma alloc_text(INIT, DriverpIsSuppoetedOS)
#endif

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

// A driver entry point
_Use_decl_annotations_ NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object,
                                            PUNICODE_STRING registry_path) {
  UNREFERENCED_PARAMETER(registry_path);
  PAGED_CODE()
      
  static const wchar_t kLogFilePath[] = L"\\SystemRoot\\HyperPlatform.log";
  static const auto kLogLevel =
      (IsReleaseBuild()) ? kLogPutLevelInfo | kLogOptDisableFunctionName
                         : kLogPutLevelDebug | kLogOptDisableFunctionName;

  auto status = STATUS_UNSUCCESSFUL;
  driver_object->DriverUnload = DriverpDriverUnload;

  //https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/single-binary-opt-in-pool-nx-optin
// Request NX Non-Paged Pool when available
  ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

  // Initialize log functions
  bool need_reinitialization = false;
  status = LogInitialization(kLogLevel, kLogFilePath);
  if (status == STATUS_REINITIALIZATION_NEEDED) {
      need_reinitialization = true;
  }
  else if (!NT_SUCCESS(status)) {
      return status;
  }

  // Test if the system is supported
  if (!DriverpIsSuppoetedOS()) {
      LogTermination();
      return STATUS_CANCELLED;
  }

  // 初始化运行库(调用类的默认构造函数等)
  _CRT_INIT();

  HYPERPLATFORM_LOG_DEBUG("DriverEntry enter");

  ULONG64 cr4 = __readcr4();
  if (cr4 & 0x800000) {
      is_cet_enable = true;
      HYPERPLATFORM_LOG_INFO_SAFE("CR4.CET is enable");
  }

  // 初始化系统相关变量
  status = InitSystemVar();
  if (!NT_SUCCESS(status))
  {
      LogTermination();
      return STATUS_UNSUCCESSFUL;
  }


  status = HyperInitDeviceAll(driver_object);

  if (!NT_SUCCESS(status))
  {
      LogTermination();
      return STATUS_UNSUCCESSFUL;
  }

  EnableSystemCallHook();

  if (!fuzz::FuzzInit())
  {
      LogTermination();
      RemoveSyscallHook(); 
      RemoveServiceHook(); 
      return STATUS_UNSUCCESSFUL;
  }

  if (!anti::AntiCapturesInit())
  {
      LogTermination();
      RemoveSyscallHook();
      RemoveServiceHook(); 
      return STATUS_UNSUCCESSFUL;
  }


  // Initialize perf functions
  status = PerfInitialization();
  if (!NT_SUCCESS(status)) {
    //GlobalObjectTermination();
    _CRT_UNLOAD();
    LogTermination();
    return status;
  }

  // Initialize utility functions
  status = UtilInitialization(driver_object);
  if (!NT_SUCCESS(status)) {
    PerfTermination();
    //GlobalObjectTermination();
    _CRT_UNLOAD();
    LogTermination();
    return status;
  }

  // Initialize power callback
  status = PowerCallbackInitialization();
  if (!NT_SUCCESS(status)) {
    UtilTermination();
    PerfTermination();
    //GlobalObjectTermination();
    _CRT_UNLOAD();
    LogTermination();
    return status;
  }

  // Initialize hot-plug callback
  status = HotplugCallbackInitialization();
  if (!NT_SUCCESS(status)) {
    PowerCallbackTermination();
    UtilTermination();
    PerfTermination();
    //GlobalObjectTermination();
    _CRT_UNLOAD();
    LogTermination();
    return status;
  }

  g_1K_LookasideList =
      (PNPAGED_LOOKASIDE_LIST)ExAllocatePoolWithTag(NonPagedPool, sizeof(NPAGED_LOOKASIDE_LIST), 'urfh');

  ExInitializeNPagedLookasideList(g_1K_LookasideList, NULL, NULL, 0, 1024, 'urfh', 0);

  // 创建配置更新线程
  PsCreateSystemThread(&hConfigThread, 0, NULL, NULL, NULL, &ConfigUpdateThread, NULL);

  // 从这里返回,以关闭虚拟化
  // 有些异常导致exit,然后又异常,直接触发多重错误,Dump都没机会生成
  // 就算生成Dump里的错误也不会是初次造成异常的信息
  // 因此关闭虚拟化可以降低找BUG的难度
  
  // TODO : 有个开发机的VmWare虚拟机开启虚拟化会卡死,物理机不会
  //return STATUS_SUCCESS;

  // Virtualize all processors
  status = VmInitialization();
  if (!NT_SUCCESS(status)) {
    HotplugCallbackTermination();
    PowerCallbackTermination();
    UtilTermination();
    PerfTermination();
    //GlobalObjectTermination();
    _CRT_UNLOAD();
    LogTermination();
    RemoveSyscallHook();
    RemoveServiceHook();
    ConfigExitVar = true;
    KeDelayExecutionThread(KernelMode, false, &MmOneSecond);
    return status;
  }

  // Register re-initialization for the log functions if needed
  if (need_reinitialization) {
    LogRegisterReinitialization(driver_object);
  }

  HYPERPLATFORM_LOG_INFO("The VMM has been installed.");

  return status;
}

// Unload handler
_Use_decl_annotations_ static void DriverpDriverUnload(
    PDRIVER_OBJECT driver_object) {
  UNREFERENCED_PARAMETER(driver_object);
  PAGED_CODE()

  HYPERPLATFORM_LOG_INFO("Driver unload");

  // 卸载日志更新线程
  ConfigExitVar = true;
  KeDelayExecutionThread(KernelMode, false, &MmOneSecond);

  VmTermination();
  HotplugCallbackTermination();
  PowerCallbackTermination();
  UtilTermination();
  PerfTermination();
  RemoveSyscallHook(); // 卸载syscall hook
  RemoveServiceHook(); // 卸载api hook
  HyperDestroyDeviceAll(driver_object); // 卸载device
  LogTermination(); // 日志最后卸载

}

// Test if the system is one of supported OS versions
_Use_decl_annotations_ bool DriverpIsSuppoetedOS() {
  PAGED_CODE()

  RTL_OSVERSIONINFOW os_version = {};
  auto status = RtlGetVersion(&os_version);
  if (!NT_SUCCESS(status)) {
    return false;
  }
  // 支持win10 及以上,放弃win7的支持
  if (os_version.dwMajorVersion != 10) {
    return false;
  }
  // 4-gigabyte tuning (4GT) should not be enabled
  if (!IsX64() && 
      reinterpret_cast<ULONG_PTR>(MmSystemRangeStart) != 0x80000000) {
    return false;
  }
  return true;
}

}  // extern "C"
