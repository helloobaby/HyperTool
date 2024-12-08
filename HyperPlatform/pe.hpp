#pragma once 
#include "include/stdafx.h"
#include <ntimage.h>
#define PE_ERROR_VALUE (ULONG)-1
ULONG RvaToOffset(PIMAGE_NT_HEADERS pnth, ULONG Rva, ULONG FileSize);
int GetExportSsdtIndex(unsigned char* FileData, ULONG FileSize, const char* ExportName);