#pragma once

// Copy From TitanHide

#include "include/stdafx.h"
#include "include/string.hpp"
#include "include/hashtable.hpp"

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

inline std::hashtable<ULONG, std::string> SSDTSymbolTable;

namespace ssdt {
    bool GetKeServiceDescriptorTable(ULONG_PTR* SSDTAddress);
    PVOID GetSSDTEntry(ULONG TableIndex);
    std::hashtable<ULONG, std::string>& InitGetSymbolTable();
    std::string GetSymbolFromAddress(ULONG SSDT_INDEX);


}



ULONG GetExportOffset(const unsigned char* FileData, ULONG FileSize, const char* ExportName);