#include "KernelBase.h"
#include "include/stdafx.h"

void* GetKernelBase2() {
    PVOID
    (*RtlPcToFileHeader)(
        PVOID PcValue,
        PVOID * BaseOfImage) = NULL;

    UNICODE_STRING s = RTL_CONSTANT_STRING(L"RtlPcToFileHeader");
    RtlPcToFileHeader = (decltype(RtlPcToFileHeader))MmGetSystemRoutineAddress(&s);
    if (!RtlPcToFileHeader)
        return NULL;

    PVOID BaseOfImage = NULL;
    return RtlPcToFileHeader(&NtOpenProcess,&BaseOfImage);
}