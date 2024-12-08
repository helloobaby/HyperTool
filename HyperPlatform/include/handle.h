// 兼容win10\win11相关的句柄操作

#pragma once
#include"stdafx.h"


////////////////////////////////////////////////////////////////////////////////////////////////////
extern "C"
{
    NTKERNELAPI POBJECT_TYPE ObGetObjectType(PVOID Object);

    UCHAR* PsGetProcessImageFileName(PEPROCESS Process);
}
////////////////////////////////////////////////////////////////////////////////////////////////////
struct _EXHANDLE// Size=0x8 (Id=1154)
{
    union // Size=0x8 (Id=0)
    {
        struct // Size=0x4 (Id=0)
        {
            unsigned long TagBits : 2;// Offset=0x0 Size=0x4 BitOffset=0x0 BitSize=0x2
            unsigned long Index : 30;// Offset=0x0 Size=0x4 BitOffset=0x2 BitSize=0x1e
        };
        void* GenericHandleOverlay;// Offset=0x0 Size=0x8
        unsigned long long Value;// Offset=0x0 Size=0x8
    };
};
typedef struct _EX_PUSH_LOCK                 // 7 elements, 0x8 bytes (sizeof) 
{
    union                                    // 3 elements, 0x8 bytes (sizeof) 
    {
        struct                               // 5 elements, 0x8 bytes (sizeof) 
        {
            /*0x000*/             UINT64       Locked : 1;         // 0 BitPosition                  
            /*0x000*/             UINT64       Waiting : 1;        // 1 BitPosition                  
            /*0x000*/             UINT64       Waking : 1;         // 2 BitPosition                  
            /*0x000*/             UINT64       MultipleShared : 1; // 3 BitPosition                  
            /*0x000*/             UINT64       Shared : 60;        // 4 BitPosition                  
        };
        /*0x000*/         UINT64       Value;
        /*0x000*/         VOID* Ptr;
    };
};
typedef struct _HANDLE_TABLE_FREE_LIST               // 5 elements, 0x40 bytes (sizeof) 
{
    /*0x000*/     struct _EX_PUSH_LOCK FreeListLock;               // 7 elements, 0x8 bytes (sizeof)  
    /*0x008*/     union _HANDLE_TABLE_ENTRY* FirstFreeHandleEntry;
    /*0x010*/     union _HANDLE_TABLE_ENTRY* LastFreeHandleEntry;
    /*0x018*/     LONG32       HandleCount;
    /*0x01C*/     ULONG32      HighWaterMark;
    /*0x020*/     UINT8        _PADDING0_[0x20];
}HANDLE_TABLE_FREE_LIST, * PHANDLE_TABLE_FREE_LIST;
typedef struct _HANDLE_TABLE// Size=0x80 (Id=519)
{
    unsigned long NextHandleNeedingPool;// Offset=0x0 Size=0x4
    long ExtraInfoPages;// Offset=0x4 Size=0x4
    unsigned long long TableCode;// Offset=0x8 Size=0x8
    struct _EPROCESS* QuotaProcess;// Offset=0x10 Size=0x8
    struct _LIST_ENTRY HandleTableList;// Offset=0x18 Size=0x10
    unsigned long UniqueProcessId;// Offset=0x28 Size=0x4
    union // Size=0x4 (Id=0)
    {
        unsigned long Flags;// Offset=0x2c Size=0x4
        struct // Size=0x1 (Id=0)
        {
            unsigned char StrictFIFO : 1;// Offset=0x2c Size=0x1 BitOffset=0x0 BitSize=0x1
            unsigned char EnableHandleExceptions : 1;// Offset=0x2c Size=0x1 BitOffset=0x1 BitSize=0x1
            unsigned char Rundown : 1;// Offset=0x2c Size=0x1 BitOffset=0x2 BitSize=0x1
            unsigned char Duplicated : 1;// Offset=0x2c Size=0x1 BitOffset=0x3 BitSize=0x1
            unsigned char RaiseUMExceptionOnInvalidHandleClose : 1;// Offset=0x2c Size=0x1 BitOffset=0x4 BitSize=0x1
        };
    };
    unsigned char __align0[3];// Offset=0x2d Size=0x3
    struct _EX_PUSH_LOCK HandleContentionEvent;// Offset=0x30 Size=0x8
    struct _EX_PUSH_LOCK HandleTableLock;// Offset=0x38 Size=0x8
    union // Size=0x40 (Id=0)
    {
        struct _HANDLE_TABLE_FREE_LIST FreeLists[1];// Offset=0x40 Size=0x40
        unsigned char ActualEntry[32];// Offset=0x40 Size=0x20
    };
    struct _HANDLE_TRACE_DEBUG_INFO* DebugInfo;// Offset=0x60 Size=0x8
}HANDLE_TABLE, * PHANDLE_TABLE;
typedef union _HANDLE_TABLE_ENTRY// Size=0x10 (Id=1091)
{
    long long VolatileLowValue;// Offset=0x0 Size=0x8
    long long LowValue;// Offset=0x0 Size=0x8
    struct _HANDLE_TABLE_ENTRY_INFO* InfoTable;// Offset=0x0 Size=0x8
    long long HighValue;// Offset=0x8 Size=0x8
    union _HANDLE_TABLE_ENTRY* NextFreeHandleEntry;// Offset=0x8 Size=0x8
    struct _EXHANDLE LeafHandleValue;// Offset=0x8 Size=0x8
    long long RefCountField;// Offset=0x0 Size=0x8
    struct // Size=0xc (Id=0)
    {
        unsigned long long Unlocked : 1;// Offset=0x0 Size=0x8 BitOffset=0x0 BitSize=0x1
        unsigned long long RefCnt : 16;// Offset=0x0 Size=0x8 BitOffset=0x1 BitSize=0x10
        unsigned long long Attributes : 3;// Offset=0x0 Size=0x8 BitOffset=0x11 BitSize=0x3
        unsigned long long ObjectPointerBits : 44;// Offset=0x0 Size=0x8 BitOffset=0x14 BitSize=0x2c
        unsigned long GrantedAccessBits : 25;// Offset=0x8 Size=0x4 BitOffset=0x0 BitSize=0x19
        unsigned long NoRightsUpgrade : 1;// Offset=0x8 Size=0x4 BitOffset=0x19 BitSize=0x1
        unsigned long Spare1 : 6;// Offset=0x8 Size=0x4 BitOffset=0x1a BitSize=0x6
    };
    unsigned long Spare2;// Offset=0xc Size=0x4
}HANDLE_TABLE_ENTRY, * PHANDLE_TABLE_ENTRY;

PHANDLE_TABLE_ENTRY
ExpLookupHandleTableEntry(
    IN PHANDLE_TABLE HandleTable,
    IN _EXHANDLE Handle
);

/**
* @参数1 句柄表  
* @参数2 句柄值
* @返回值 句柄指向的具体对象主体，而不是对象头部
*/
PVOID GetObject(PHANDLE_TABLE HandleTable, UINT64 Handle);
