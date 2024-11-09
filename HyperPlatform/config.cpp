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
tagGlobalConfig GlobalConfig;
ULONGLONG Config_timestamp;


// 如果这个列表不为空的话,所有的API记录和Syscall这种能绑定到进程(路径)的都会走一遍这个过滤
// 过滤算法其实就是最简单的类似strstr,暂时不考虑正则表达式
std::vector<std::string> TraceProcessPathList;

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

        // 每30ms更新一次Config
        KeDelayExecutionThread(KernelMode, false, &Mm30Milliseconds);
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
                    memset(buffer, 0, fileSize + 1);
                    if (buffer != NULL)
                    {
                        if (NT_SUCCESS(ReadFile(handle, buffer, fileSize)))
                        {
                            root = cJSON_Parse((char*)buffer);
                            if (root) {

                                // 还是得手动触发式更新规则,实时自动更新的话很多地方设计起来很麻烦
                                cJSON* timestamp = cJSON_GetObjectItem(root, "timestamp");
                                if (timestamp == NULL || !cJSON_IsNumber(timestamp)) {
                                    HYPERPLATFORM_LOG_ERROR("timestamp == NULL || !cJSON_IsNumber(timestamp)");
                                    continue;
                                }
                                if (timestamp->valueulong != Config_timestamp) {

                                    HYPERPLATFORM_LOG_INFO("Detect Config_timestamp change , UpdateConfig");
                                    Config_timestamp = timestamp->valueulong;

                                    // 解析hooks
                                    cJSON* hooks = cJSON_GetObjectItem(root, "hooks");
                                    if (hooks == NULL || !cJSON_IsObject(hooks)) {
                                        HYPERPLATFORM_LOG_ERROR("hooks == NULL || !cJSON_IsObject(hooks)");
                                        continue;
                                    }

                                    // 解析hooks::log
                                    cJSON* log = cJSON_GetObjectItem(hooks, "log");
                                    if (log != NULL && cJSON_IsString(log)) {
                                        if (!_strcmpi_a("true", log->valuestring)) {
                                            GlobalConfig.hooks_log = true;
                                            HYPERPLATFORM_LOG_INFO("GlobalConfig.hooks_log = true");
                                        }
                                        else if (!_strcmpi_a("false", log->valuestring)) {
                                            GlobalConfig.hooks_log = false;
                                            HYPERPLATFORM_LOG_INFO("GlobalConfig.hooks_log = false");
                                        }
                                    }
                                    else {
                                        HYPERPLATFORM_LOG_ERROR("log != NULL && cJSON_IsString(log)");
                                    }

                                    // 解析path
                                    cJSON* path_array = cJSON_GetObjectItem(root, "path");
                                    if (path_array == NULL || !cJSON_IsArray(path_array)) {
                                        HYPERPLATFORM_LOG_INFO("path_array == NULL || !cJSON_IsArray(path_array)");
                                        continue;
                                    }

                                    int path_count = cJSON_GetArraySize(path_array);

                                    // 先清空,类似clear()
                                    TraceProcessPathList.erase(TraceProcessPathList.begin(), TraceProcessPathList.end());
                                    for (int i = 0; i < path_count; i++) {
                                        cJSON* path_item = cJSON_GetArrayItem(path_array, i);
                                        if (cJSON_IsString(path_item) && path_item->valuestring != NULL) {
                                            HYPERPLATFORM_LOG_INFO("TraceProcessPathList Push Path %s", path_item->valuestring);
                                            TraceProcessPathList.push_back(path_item->valuestring);
                                        }
                                    }
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