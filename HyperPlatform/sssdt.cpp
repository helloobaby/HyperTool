#include "sssdt.h"

namespace sssdt {
	BOOLEAN
		GetKeServiceDescriptorTableShadow(OUT PULONG_PTR SSSDTAddress)
	{
#ifdef _WIN64
		PUINT8	StartSearchAddress = (PUINT8)__readmsr(0xC0000082);   
		PUINT8	EndSearchAddress = StartSearchAddress + 0x500;
		PUINT8	i = NULL;
		UINT8   v1 = 0, v2 = 0, v3 = 0;
		INT32   iOffset = 0;   
		UINT64  VariableAddress = 0;

		*SSSDTAddress = 0;
		for (i = StartSearchAddress; i < EndSearchAddress; i++)
		{
			if (MmIsAddressValid(i) && MmIsAddressValid(i + 1) && MmIsAddressValid(i + 2))
			{
				v1 = *i;
				v2 = *(i + 1);
				v3 = *(i + 2);
				if (v1 == 0x4c && v2 == 0x8d && v3 == 0x1d)		// lea r11
				{
					memcpy(&iOffset, i + 3, 4);
					*SSSDTAddress = iOffset + (UINT64)i + 7;
					*SSSDTAddress += sizeof(UINT_PTR) * 4;		
					break;
				}
			}
		}

		if (*SSSDTAddress == 0)
		{
			return FALSE;
		}
		return TRUE;
#else
#pragma error("Must X64 PlatForm")
#endif
	}
}