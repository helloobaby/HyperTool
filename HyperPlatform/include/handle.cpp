#include"handle.h"
#include<intrin.h>

#define TABLE_PAGE_SIZE PAGE_SIZE
#define LOWLEVEL_COUNT7 (TABLE_PAGE_SIZE / sizeof(HANDLE_TABLE_ENTRY7))
#define MIDLEVEL_COUNT7 (PAGE_SIZE / sizeof(PHANDLE_TABLE_ENTRY7))

#define LOWLEVEL_THRESHOLD7 LOWLEVEL_COUNT7
#define MIDLEVEL_THRESHOLD7 (MIDLEVEL_COUNT7 * LOWLEVEL_COUNT7)
#define HIGHLEVEL_THRESHOLD7 (MIDLEVEL_COUNT7 * MIDLEVEL_COUNT7 * LOWLEVEL_COUNT7)

#define HANDLE_VALUE_INC 4

PHANDLE_TABLE_ENTRY7
ExpLookupHandleTableEntry7(
    IN PHANDLE_TABLE7 HandleTable, // EPROCESS 里的HANDLE_TABLE
    IN EXHANDLE Handle //伪句柄
)
{
	ULONG_PTR i, j, k;
	ULONG_PTR CapturedTable;
	ULONG TableLevel;
	PHANDLE_TABLE_ENTRY7 Entry = NULL;

	typedef PHANDLE_TABLE_ENTRY7 L1P;
	typedef volatile L1P* L2P;
	typedef volatile L2P* L3P;

	L1P TableLevel1;
	L2P TableLevel2;
	L3P TableLevel3;

	ULONG_PTR RemainingIndex;
	ULONG_PTR MaxHandle;
	ULONG_PTR Index;

	MaxHandle = *(volatile ULONG*)&HandleTable->NextHandleNeedingPool;
	if (Handle.Value >= MaxHandle)
	{
		return NULL;
	}


	//后两位TagBits不用
	
	//__debugbreak();



	Index = Handle.Index;

	CapturedTable = *(ULONG_PTR*)&HandleTable->TableCode;

	TableLevel = CapturedTable & 3;

	CapturedTable = CapturedTable & ~3;

	switch (TableLevel)
	{
	case 0:

		TableLevel1 = (L1P)CapturedTable;
		Entry = &(TableLevel1[Index]);

		break;
	case 1:

		TableLevel2 = (L2P)CapturedTable;

		i = Index / LOWLEVEL_COUNT7;
		j = Index % LOWLEVEL_COUNT7;

		Entry = &(TableLevel2[i][j]);

		break;
	case 3:

		TableLevel3 = (L3P)CapturedTable;

		//
		//  Calculate the 3 indexes we need
		//

		i = Index / (MIDLEVEL_THRESHOLD7);
		RemainingIndex = Index - i * MIDLEVEL_THRESHOLD7;
		j = RemainingIndex / LOWLEVEL_COUNT7;
		k = RemainingIndex % LOWLEVEL_COUNT7;
		Entry = &(TableLevel3[i][j][k]);

		break;
	}

	return Entry;
}

PHANDLE_TABLE_ENTRY10
ExpLookupHandleTableEntry10(
	IN PHANDLE_TABLE10 HandleTable, // EPROCESS 里的HANDLE_TABLE
	IN EXHANDLE Handle
)
{
	ULONG_PTR i, j, k;
	ULONG_PTR CapturedTable;
	ULONG TableLevel;
	PHANDLE_TABLE_ENTRY10 Entry = NULL;

	PUCHAR TableLevel1;
	PUCHAR TableLevel2;
	PUCHAR TableLevel3;

	ULONG_PTR MaxHandle;

	Handle.TagBits = 0;

	MaxHandle = *(volatile ULONG*)&HandleTable->NextHandleNeedingPool;
	if (Handle.Value >= MaxHandle)
	{
		return NULL;
	}

	CapturedTable = *(volatile ULONG_PTR*)&HandleTable->TableCode;
	TableLevel = (ULONG)(CapturedTable & 3);
	CapturedTable = CapturedTable - TableLevel;

	switch (TableLevel)
	{
	case 0:
	{
		TableLevel1 = (PUCHAR)CapturedTable;

		//Handle.Value相当于应用层传的伪句柄
		Entry = (PHANDLE_TABLE_ENTRY10)&TableLevel1[Handle.Value * 4];

		break;
	}

	case 1:
	{
		TableLevel2 = (PUCHAR)CapturedTable;
		/*
		%0x400 = & 0x3ff
		取最低十位 因为句柄后2位无效，加上一个页只能放256项，也就是8位
		*/

		//
		//_HANDLE_TABLE_ENTRY在win7和win10上有区别，但是大小一样，所以LEVEL_COUNT可以用win7的
		//
		i = Handle.Value % (LOWLEVEL_COUNT7 * HANDLE_VALUE_INC);
		//最后十位清0
		Handle.Value -= i;
		// 右移10位然后×4 获得第二张表的索引
		j = Handle.Value / ((LOWLEVEL_COUNT7 * HANDLE_VALUE_INC) / sizeof(PHANDLE_TABLE_ENTRY10));

		TableLevel1 = (PUCHAR) * (PHANDLE_TABLE_ENTRY10*)&TableLevel2[j];
		Entry = (PHANDLE_TABLE_ENTRY10)&TableLevel1[i * (sizeof(HANDLE_TABLE_ENTRY10) / HANDLE_VALUE_INC)];

		break;
	}

	case 2:
	{
		/*
ULONG_PTR i; 最低层的表索引
ULONG_PTR j; 中间层的表索引
ULONG_PTR k; 最上层的表索引

		*/
		TableLevel3 = (PUCHAR)CapturedTable;
		//一页最多能存几个项，×4是最大的序号
		//#define LOWLEVEL_COUNT (TABLE_PAGE_SIZE / sizeof(HANDLE_TABLE_ENTRY))
		i = Handle.Value % (LOWLEVEL_COUNT7 * HANDLE_VALUE_INC);
		Handle.Value -= i;
		k = Handle.Value / ((LOWLEVEL_COUNT7 * HANDLE_VALUE_INC) / sizeof(PHANDLE_TABLE_ENTRY10));
		j = k % (MIDLEVEL_COUNT7 * sizeof(PHANDLE_TABLE_ENTRY10));
		k -= j;
		k /= MIDLEVEL_COUNT7;

		TableLevel2 = (PUCHAR) * (PHANDLE_TABLE_ENTRY10*)&TableLevel3[k];
		TableLevel1 = (PUCHAR) * (PHANDLE_TABLE_ENTRY10*)&TableLevel2[j];
		Entry = (PHANDLE_TABLE_ENTRY10)&TableLevel1[i * (sizeof(HANDLE_TABLE_ENTRY10) / HANDLE_VALUE_INC)];

		break;
	}

	default: _assume(0);
	}

	return Entry;
}


PVOID GetObject10(PHANDLE_TABLE10 HandleTable, ULONG_PTR Handle)
{
	PVOID Object = NULL;
	EXHANDLE t;

	t.Value = Handle;
	auto Entry = ExpLookupHandleTableEntry10((PHANDLE_TABLE10)HandleTable, t);

	if (Entry == NULL)
		return NULL;

	*(ULONG_PTR*)&Object = Entry->ObjectPointerBits;
	*(ULONG_PTR*)&Object <<= 4;
	*(ULONG_PTR*)&Object |= 0xFFFF000000000000;
	//*(ULONG_PTR*)&Object += 0x30;

	return Object;
}

PVOID GetObject7(PHANDLE_TABLE7 HandleTable, ULONG_PTR Handle)
{
	EXHANDLE t;
	t.Value = Handle;

	auto Entry = ExpLookupHandleTableEntry7((PHANDLE_TABLE7)HandleTable, t);
	if (Entry == NULL)
		return NULL;
	void* pObject = Entry->Object;
	if (pObject == NULL)
	{
		return NULL;
	}
	//清空低三位
	pObject = (void*)((ULONG_PTR)pObject & ~7);
	return pObject;
}