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

cJSON* ExtractConfigValue(cJSON* root, const char* key) {
    return cJSON_GetObjectItem(root, key);
}

template <typename... Keys>
cJSON* ExtractConfigValue(cJSON* root, const char* first, Keys... args) {
    cJSON* next = cJSON_GetObjectItem(root, first);
    if (!next) {
        HYPERPLATFORM_LOG_ERROR("ExtractConfigValue fail , root %s ,first %s",root,first);
        return nullptr;
    }
    return ExtractConfigValue(next, args...);
}

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
            cJSON* value = NULL;
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
                                value = ExtractConfigValue(root, "anti_capture_white");
                                if (value) {
                                    HYPERPLATFORM_LOG_DEBUG("GlobalConfig.anti_capture_white %s", value->valuestring);
                                    GlobalConfig.anti_capture_white = value->valuestring;
                                }

                                value = ExtractConfigValue(root, "hooks", "path");
                                if (value) {
                                    HYPERPLATFORM_LOG_DEBUG("GlobalConfig.APIHook.path %s", value->valuestring);
                                    GlobalConfig.APIHook.path = value->valuestring;
                                }
                                value = ExtractConfigValue(root, "syscall", "path");
                                if (value) {
                                    HYPERPLATFORM_LOG_DEBUG("GlobalConfig.SyscallHook.path %s", value->valuestring);
                                    GlobalConfig.SyscallHook.path = value->valuestring;
                                }
                                value = ExtractConfigValue(root, "syscall", "hexbytes");
                                if (value) {
                                    HYPERPLATFORM_LOG_DEBUG("GlobalConfig.SyscallHook.hexbytes %lld", value->valueulong);
                                    GlobalConfig.SyscallHook.hexbytes = value->valueulong;
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