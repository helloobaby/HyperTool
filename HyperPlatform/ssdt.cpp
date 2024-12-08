#include "ssdt.h"
#include "KernelBase.h"
#include <ntimage.h>
#include "log.h"
#include "pe.hpp"

extern "C"
{
    NTSYSAPI PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(_In_ PVOID Base);
}

namespace ssdt {
    bool GetKeServiceDescriptorTable(ULONG_PTR* SSDTAddress)
    {
        //x64 code
        ULONG_PTR kernelBase = (ULONG_PTR)GetKernelBase();
        if (kernelBase == 0)
            return false;

        // Find .text section
        PIMAGE_NT_HEADERS ntHeaders = RtlImageNtHeader((PVOID)kernelBase);
        PIMAGE_SECTION_HEADER textSection = nullptr;
        PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
        for (ULONG i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i)
        {
            char sectionName[IMAGE_SIZEOF_SHORT_NAME + 1];
            RtlCopyMemory(sectionName, section->Name, IMAGE_SIZEOF_SHORT_NAME);
            sectionName[IMAGE_SIZEOF_SHORT_NAME] = '\0';
            if (strncmp(sectionName, ".text", sizeof(".text") - sizeof(char)) == 0)
            {
                textSection = section;
                break;
            }
            section++;
        }
        if (textSection == nullptr)
            return false;

        // Find KiSystemServiceStart in .text
        const unsigned char KiSystemServiceStartPattern[] = { 0x8B, 0xF8, 0xC1, 0xEF, 0x07, 0x83, 0xE7, 0x20, 0x25, 0xFF, 0x0F, 0x00, 0x00 };
        const ULONG signatureSize = sizeof(KiSystemServiceStartPattern);
        bool found = false;
        ULONG KiSSSOffset;
        for (KiSSSOffset = 0; KiSSSOffset < textSection->Misc.VirtualSize - signatureSize; KiSSSOffset++)
        {
            if (RtlCompareMemory(((unsigned char*)kernelBase + textSection->VirtualAddress + KiSSSOffset), KiSystemServiceStartPattern, signatureSize) == signatureSize)
            {
                found = true;
                break;
            }
        }
        if (!found)
            return false;

        // lea r10, KeServiceDescriptorTable
        ULONG_PTR address = kernelBase + textSection->VirtualAddress + KiSSSOffset + signatureSize;
        LONG relativeOffset = 0;
        if ((*(unsigned char*)address == 0x4c) &&
            (*(unsigned char*)(address + 1) == 0x8d) &&
            (*(unsigned char*)(address + 2) == 0x15))
        {
            relativeOffset = *(LONG*)(address + 3);
        }
        if (relativeOffset == 0)
            return false;

        *SSDTAddress = (address + relativeOffset + 7);

        return true;
    }

    PVOID GetSSDTEntry(ULONG TableIndex)
    {
        LONG* ServiceTable = ((SSDTStruct*)SSDTAddress)->pServiceTable;
        ULONG Offset = ServiceTable[TableIndex] >> 4;
        //HYPERPLATFORM_LOG_DEBUG_SAFE("[SSDT] TableIndex %d Offset %x -> %llx", TableIndex, Offset, PVOID(Offset + (ULONG_PTR)ServiceTable));
        return PVOID(Offset + (ULONG_PTR)ServiceTable);
    }

    std::hashtable<ULONG, std::string>& InitGetSymbolTable() {

        // 初始化ntdll的导出符号
        UNICODE_STRING FileName;
        OBJECT_ATTRIBUTES ObjectAttributes;
        RtlInitUnicodeString(&FileName, L"\\SystemRoot\\system32\\ntdll.dll");
        InitializeObjectAttributes(&ObjectAttributes, &FileName,
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
            NULL, NULL);

        ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

        HANDLE FileHandle;
        IO_STATUS_BLOCK IoStatusBlock;
        NTSTATUS NtStatus = ZwCreateFile(&FileHandle,
            GENERIC_READ,
            &ObjectAttributes,
            &IoStatusBlock, NULL,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ,
            FILE_OPEN,
            FILE_SYNCHRONOUS_IO_NONALERT,
            NULL, 0);

        unsigned char* FileData = NULL;
        ULONG FileSize = 0;
        if (NT_SUCCESS(NtStatus))
        {
            FILE_STANDARD_INFORMATION StandardInformation = { 0 };
            NtStatus = ZwQueryInformationFile(FileHandle, &IoStatusBlock, &StandardInformation, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
            if (NT_SUCCESS(NtStatus))
            {
                FileSize = StandardInformation.EndOfFile.LowPart;
                HYPERPLATFORM_LOG_INFO("FileSize of ntdll.dll is %08X", StandardInformation.EndOfFile.LowPart);
                FileData = (unsigned char*)ExAllocatePoolWithTag(NonPagedPool, FileSize, 'tdss');

                LARGE_INTEGER ByteOffset;
                ByteOffset.LowPart = ByteOffset.HighPart = 0;
                NtStatus = ZwReadFile(FileHandle,
                    NULL, NULL, NULL,
                    &IoStatusBlock,
                    FileData,
                    FileSize,
                    &ByteOffset, NULL);

                if (!NT_SUCCESS(NtStatus))
                {
                    ExFreePool(FileData);
                    HYPERPLATFORM_LOG_ERROR("ZwReadFile failed with status %08X...", NtStatus);
                }
                else {

                    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)FileData;
                    PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((PUCHAR)FileData + dosHeader->e_lfanew);
                    PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)FileData +
                        RvaToOffset(ntHeaders, ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, FileSize));

                    PULONG names = (PULONG)((PUCHAR)FileData + exportDirectory->AddressOfNames);

                    for (ULONG i = 0; i < exportDirectory->NumberOfNames; i++)
                    {
                        if (RvaToOffset(ntHeaders, names[i], FileSize) == PE_ERROR_VALUE)
                            continue;

                        PCHAR functionName = (PCHAR)((PUCHAR)FileData + RvaToOffset(ntHeaders, names[i], FileSize));
                        if (!MmIsAddressValid(functionName))
                            continue;

                        ULONG SSDT_INDEX = GetExportSsdtIndex(FileData, FileSize, functionName);
                        if (SSDT_INDEX != PE_ERROR_VALUE) {
                            SSDTSymbolTable.insert(SSDT_INDEX, functionName);
                            HYPERPLATFORM_LOG_DEBUG_SAFE("%x -> %s", SSDT_INDEX, functionName);
                        }
                    }


                }
            }
            else
                HYPERPLATFORM_LOG_ERROR("ZwQueryInformationFile failed with status %08X...", NtStatus);
            ZwClose(FileHandle);
        }
        else
            HYPERPLATFORM_LOG_ERROR("ZwCreateFile failed with status %08X...", NtStatus);

        if (FileData)
            ExFreePool(FileData);


        return SSDTSymbolTable;
    }

    std::string GetSymbolFromAddress(ULONG SSDT_INDEX) {
        auto node = SSDTSymbolTable[SSDT_INDEX];
        if (node) {
            return node->val;
        }
        return "";
    }

}

