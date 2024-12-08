#include"handle.h"

PVOID GetObject(PHANDLE_TABLE HandleTable, UINT64 Handle)
{
	PVOID Object = NULL;
	_EXHANDLE t;

	t.Value = Handle;
	auto Entry = ExpLookupHandleTableEntry(HandleTable, t);

	if (Entry == NULL)
		return NULL;

	*(UINT64*)&Object = Entry->ObjectPointerBits;
	*(UINT64*)&Object <<= 4;
	*(UINT64*)&Object |= 0xFFFF000000000000;
	return Object;
}

PHANDLE_TABLE_ENTRY
ExpLookupHandleTableEntry(
	IN PHANDLE_TABLE HandleTable,
	IN _EXHANDLE Handle
) {
	return NULL;
}