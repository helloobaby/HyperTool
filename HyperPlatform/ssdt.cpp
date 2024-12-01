#include "ssdt.h"
#include "KernelBase.h"
#include <ntimage.h>
#include "log.h"

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
#endif

        return true;
    }

    PVOID GetSSDTEntry(ULONG TableIndex)
    {
        LONG* ServiceTable = ((SSDTStruct*)SSDTAddress)->pServiceTable;
        ULONG Offset = ServiceTable[TableIndex] >> 4;
        HYPERPLATFORM_LOG_DEBUG_SAFE("[SSDT] TableIndex %d Offset %x -> %llx", TableIndex, Offset, PVOID(Offset + (ULONG_PTR)ServiceTable));
        return PVOID(Offset + (ULONG_PTR)ServiceTable);
    }

    auto InitSymbolTable() {
        static std::hashtable<PVOID, std::string> _symboltable;





        return _symboltable;
    }

    std::string GetSymbolFromAddress(PVOID Address) {

    }

}