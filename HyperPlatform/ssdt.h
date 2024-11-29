#pragma once

// Copy From TitanHide

#include "include/stdafx.h"

// SYSTEM_SERVICE_DESCRIPTOR_TABLE
struct SSDTStruct
{
    LONG* pServiceTable;
    PVOID pCounterTable;
#ifdef _WIN64
    ULONGLONG NumberOfServices;
#else
    ULONG NumberOfServices;
#endif
    PCHAR pArgumentTable;
};

// SSDT µÿ÷∑
inline ULONG_PTR SSDTAddress;

namespace ssdt {
    bool GetKeServiceDescriptorTable(ULONG_PTR* SSDTAddress);
    PVOID GetSSDTEntry(ULONG TableIndex);
}