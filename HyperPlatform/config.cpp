#include "config.h"
#include "json/kcrt.h"
#include "json/cJSON.h"
#include "log.h"
#include "include/string.hpp"
#include "include/vector.hpp"
extern "C" {
#include "minirtl/minirtl.h"
}
#include "util.h"

extern LARGE_INTEGER MmOneSecond;
extern LARGE_INTEGER MmHalfSecond;
extern LARGE_INTEGER Mm30Milliseconds;

// 其他extern的地方只读不写
tagGlobalConfig GlobalConfig;

void ConfigUpdateThread(
    PVOID StartContext
) {
    UNREFERENCED_PARAMETER(StartContext);
    HYPERPLATFORM_LOG_INFO("ConfigUpdateThread enter");
    while (1) {
        if (ConfigExitVar) {
            HYPERPLATFORM_LOG_INFO("ConfigUpdateThread Exit");
            PsTerminateSystemThread(STATUS_SUCCESS);
        }

        // 每1s更新一次Config
        KeDelayExecutionThread(KernelMode, false, &MmOneSecond);
        {
            HANDLE handle = NULL;
            void* buffer = NULL;
            cJSON* root = NULL;
            auto _ = make_scope_exit([&]() {  // RAII管理资源
                if (handle != NULL)
                    CloseFile(handle);
                if(buffer)
                    ExFreePoolWithTag(buffer, 'fnoc');
                if(root != NULL)
                    cJSON_Delete(root);
                });

            handle = OpenFile((wchar_t*)L"\\SystemRoot\\Config.json");
            if (handle) {
                ULONG fileSize = GetFileSize(handle);
                if (fileSize != 0)
                {
                    buffer = ExAllocatePoolWithTag(NonPagedPool, fileSize + 1, 'fnoc');
                    NT_ASSERT(buffer);
                    memset(buffer, 0, fileSize + 1);
                    if (buffer != NULL)
                    {
                        if (NT_SUCCESS(ReadFile(handle, buffer, fileSize)))
                        {
                            root = cJSON_Parse((char*)buffer);
                            if (root) {

                                    cJSON* hooks = cJSON_GetObjectItem(root, "hooks");
                                    if (hooks == NULL || !cJSON_IsObject(hooks)) {
                                        HYPERPLATFORM_LOG_ERROR("json parse hooks fail");
                                        continue;
                                    }

                                    cJSON* path = cJSON_GetObjectItem(hooks, "path");
                                    if (path != NULL && cJSON_IsString(path)) {
                                        GlobalConfig.APIHook.path = path->valuestring;
                                    }
                                    else {
                                        HYPERPLATFORM_LOG_ERROR("json parse GlobalConfig.APIHook.path fail");
                                    }

                                    cJSON* capture = cJSON_GetObjectItem(root, "anti_capture_white");
                                    if (capture == NULL || !cJSON_IsString(capture)) {
                                        HYPERPLATFORM_LOG_INFO("json parse anti_capture_white fail");
                                        continue;
                                    }
                                    else {
                                        GlobalConfig.anti_capture_white = capture->valuestring;
                                        HYPERPLATFORM_LOG_DEBUG("GlobalConfig.anti_capture_white %s", GlobalConfig.anti_capture_white.c_str());
                                    }

                                    cJSON* syscall = cJSON_GetObjectItem(root, "syscall");
                                    if (syscall == NULL || !cJSON_IsString(syscall)) {
                                        HYPERPLATFORM_LOG_INFO("syscall == NULL || !cJSON_IsString(syscall)");
                                        continue;
                                    }
                                    else {
                                        GlobalConfig.syscall = syscall->valuestring;
                                        HYPERPLATFORM_LOG_DEBUG("GlobalConfig.syscall %s", GlobalConfig.syscall.c_str());
                                    }

                                    // 
                                    cJSON* hexbytes = cJSON_GetObjectItem(root, "hexbytes");
                                    if (hexbytes == NULL || !cJSON_IsNumber(hexbytes)) {
                                        HYPERPLATFORM_LOG_INFO("hexbytes == NULL || !cJSON_IsNumber(hexbytes)");
                                        continue;
                                    }
                                    else {
                                        GlobalConfig.hexbytes = hexbytes->valueulong;
                                        HYPERPLATFORM_LOG_DEBUG("GlobalConfig.hexbytes %d", GlobalConfig.hexbytes);
                                    }
                                
                            }
                            else {
                                HYPERPLATFORM_LOG_ERROR("cJSON_Parse fail");
                            }
                        }
                    }
                }
            }
            else {
                HYPERPLATFORM_LOG_ERROR("Cant find \\SystemRoot\\Config.json");
            }
        }
    }
}

HANDLE OpenFile(wchar_t* filepath)
{
    NTSTATUS ntStatus;
    HANDLE fileHandle = NULL;
    OBJECT_ATTRIBUTES objectAttributes = { 0 };
    IO_STATUS_BLOCK ioStatusBlock = { 0 };
    UNICODE_STRING unicode_filename = { 0 };
    RtlInitUnicodeString(&unicode_filename, filepath);
    do
    {
        InitializeObjectAttributes(&objectAttributes, &unicode_filename, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
        ntStatus = ZwOpenFile(&fileHandle,
            GENERIC_ALL,
            &objectAttributes,
            &ioStatusBlock,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_SYNCHRONOUS_IO_NONALERT);
        if (NT_SUCCESS(ntStatus) == FALSE)
        {
            break;
        }
    } while (FALSE);
    return fileHandle;
}

ULONG GetFileSize(HANDLE pFileHandle)
{
    NTSTATUS ntStatus;
    FILE_STANDARD_INFORMATION fileInformation;
    IO_STATUS_BLOCK ioStatusBlock = { 0 };
    ULONG file_size = 0;
    do
    {
        if (pFileHandle == NULL)
        {
            break;
        }
        ntStatus = ZwQueryInformationFile(pFileHandle, &ioStatusBlock, &fileInformation, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
        if (NT_SUCCESS(ntStatus) == FALSE)
        {
            break;
        }
        file_size = (ULONG)fileInformation.EndOfFile.QuadPart;
    } while (FALSE);
    return file_size;
}

NTSTATUS ReadFile(HANDLE pFileHandle, void* buffer, unsigned long size)
{
    NTSTATUS ntStatus;
    LARGE_INTEGER byteOffset;
    byteOffset.QuadPart = 0;
    IO_STATUS_BLOCK ioStatusBlock = { 0 };

    do
    {
        if (pFileHandle == NULL || buffer == NULL)
        {
            ntStatus = STATUS_BAD_DATA;
            break;
        }
        ntStatus = ZwReadFile(pFileHandle, NULL, NULL, NULL, &ioStatusBlock, buffer, size, &byteOffset, NULL);
    } while (FALSE);
    return ntStatus;
}
NTSTATUS CloseFile(HANDLE pFileHandle)
{
    return ZwClose(pFileHandle);
}