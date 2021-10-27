#include"stdafx.h"


////////////////////////////////////////////////////////////////////////////////////////////////////
extern "C"
{
    NTKERNELAPI POBJECT_TYPE ObGetObjectType(PVOID Object);

    UCHAR* PsGetProcessImageFileName(PEPROCESS Process);
}
////////////////////////////////////////////////////////////////////////////////////////////////////

typedef struct _EXHANDLE
{
    union
    {
        struct
        {
            ULONG32 TagBits : 2; // 低2位是0，所以句柄是4开始，并且是4的倍数
            ULONG32 Index : 30;
        };
        HANDLE GenericHandleOverlay;
        ULONG_PTR Value;
    };
} EXHANDLE, * PEXHANDLE;

typedef struct _HANDLE_TABLE_ENTRY7                  // 8 elements, 0x10 bytes (sizeof) 
{
    union                                           // 4 elements, 0x8 bytes (sizeof)  
    {
        /*0x000*/         VOID* Object;
        /*0x000*/         ULONG32      ObAttributes;
        /*0x000*/         struct _HANDLE_TABLE_ENTRY_INFO7* InfoTable;
        /*0x000*/         UINT64       Value;
    };
    union                                           // 3 elements, 0x8 bytes (sizeof)  
    {
        /*0x008*/         ULONG32      GrantedAccess;
        struct                                      // 2 elements, 0x8 bytes (sizeof)  
        {
            /*0x008*/             UINT16       GrantedAccessIndex;
            /*0x00A*/             UINT16       CreatorBackTraceIndex;
            /*0x00C*/             UINT8        _PADDING0_[0x4];
        };
        /*0x008*/         ULONG32      NextFreeTableEntry;
    };
}HANDLE_TABLE_ENTRY7, * PHANDLE_TABLE_ENTRY7;

typedef struct _HANDLE_TABLE_ENTRY_INFO7 // 1 elements, 0x4 bytes (sizeof) 
{
    /*0x000*/     ULONG32      AuditMask;
}HANDLE_TABLE_ENTRY_INFO7;


typedef struct _EX_PUSH_LOCK7                 // 7 elements, 0x8 bytes (sizeof) 
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
}EX_PUSH_LOCK7, * PEX_PUSH_LOCK7;



typedef struct _HANDLE_TABLE7                         // 15 elements, 0x68 bytes (sizeof) 
{
    /*0x000*/     UINT64       TableCode;
    /*0x008*/     struct _EPROCESS* QuotaProcess;
    /*0x010*/     VOID* UniqueProcessId;
    /*0x018*/     struct _EX_PUSH_LOCK7 HandleLock;                 // 7 elements, 0x8 bytes (sizeof)   
    /*0x020*/     struct _LIST_ENTRY HandleTableList;              // 2 elements, 0x10 bytes (sizeof)  
    /*0x030*/     struct _EX_PUSH_LOCK7 HandleContentionEvent;      // 7 elements, 0x8 bytes (sizeof)   
    /*0x038*/     struct _HANDLE_TRACE_DEBUG_INFO7* DebugInfo;
    /*0x040*/     LONG32       ExtraInfoPages;
    union                                            // 2 elements, 0x4 bytes (sizeof)   
    {
        /*0x044*/         ULONG32      Flags;
        /*0x044*/         UINT8        StrictFIFO : 1;                 // 0 BitPosition                    
    };
    /*0x048*/     ULONG32      FirstFreeHandle;
    /*0x04C*/     UINT8        _PADDING0_[0x4];
    /*0x050*/     struct _HANDLE_TABLE_ENTRY* LastFreeHandleEntry;
    /*0x058*/     ULONG32      HandleCount;
    /*0x05C*/     ULONG32      NextHandleNeedingPool;
    /*0x060*/     ULONG32      HandleCountHighWatermark;
    /*0x064*/     UINT8        _PADDING1_[0x4];
}HANDLE_TABLE7, * PHANDLE_TABLE7;

typedef struct _HANDLE_TABLE_ENTRY_INFO10 // 2 elements, 0x8 bytes (sizeof) 
{
    /*0x000*/     ULONG32      AuditMask;
    /*0x004*/     ULONG32      MaxRelativeAccessMask;
}HANDLE_TABLE_ENTRY_INFO10, * PHANDLE_TABLE_ENTRY_INFO10;


typedef union _HANDLE_TABLE_ENTRY10                           // 15 elements, 0x10 bytes (sizeof) 
{
    /*0x000*/     INT64        VolatileLowValue;
    /*0x000*/     INT64        LowValue;
    struct                                                  // 2 elements, 0x10 bytes (sizeof)  
    {
        /*0x000*/         struct _HANDLE_TABLE_ENTRY_INFO10* InfoTable;
        union                                               // 3 elements, 0x8 bytes (sizeof)   
        {
            /*0x008*/             INT64        HighValue;
            /*0x008*/             union _HANDLE_TABLE_ENTRY10* NextFreeHandleEntry;
            /*0x008*/             struct _EXHANDLE LeafHandleValue;               // 4 elements, 0x8 bytes (sizeof)   
        };
    };
    /*0x000*/     INT64        RefCountField;
    struct                                                  // 4 elements, 0x8 bytes (sizeof)   
    {
        /*0x000*/         UINT64       Unlocked : 1;                          // 0 BitPosition                    
        /*0x000*/         UINT64       RefCnt : 16;                           // 1 BitPosition                    
        /*0x000*/         UINT64       Attributes : 3;                        // 17 BitPosition                   
        /*0x000*/         UINT64       ObjectPointerBits : 44;                // 20 BitPosition                   
    };
    struct                                                  // 3 elements, 0x4 bytes (sizeof)   
    {
        /*0x008*/         ULONG32      GrantedAccessBits : 25;                // 0 BitPosition                    
        /*0x008*/         ULONG32      NoRightsUpgrade : 1;                   // 25 BitPosition                   
        /*0x008*/         ULONG32      Spare1 : 6;                            // 26 BitPosition                   
    };
    /*0x00C*/     ULONG32      Spare2;
}HANDLE_TABLE_ENTRY10, * PHANDLE_TABLE_ENTRY10;


typedef struct _EX_PUSH_LOCK10              // 7 elements, 0x8 bytes (sizeof) 
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
}EX_PUSH_LOCK10, * PEX_PUSH_LOCK10;

typedef struct _HANDLE_TABLE_FREE_LIST10               // 5 elements, 0x40 bytes (sizeof) 
{
    /*0x000*/     struct _EX_PUSH_LOCK10 FreeListLock;               // 7 elements, 0x8 bytes (sizeof)  
    /*0x008*/     union _HANDLE_TABLE_ENTRY10* FirstFreeHandleEntry;
    /*0x010*/     union _HANDLE_TABLE_ENTRY10* LastFreeHandleEntry;
    /*0x018*/     LONG32       HandleCount;
    /*0x01C*/     ULONG32      HighWaterMark;
    /*0x020*/     UINT8        _PADDING0_[0x20];
}HANDLE_TABLE_FREE_LIST10, * PHANDLE_TABLE_FREE_LIST10;

typedef struct _HANDLE_TABLE10                                       // 17 elements, 0x80 bytes (sizeof) 
{
    /*0x000*/     ULONG32      NextHandleNeedingPool;
    /*0x004*/     LONG32       ExtraInfoPages;
    /*0x008*/     UINT64       TableCode;
    /*0x010*/     struct _EPROCESS* QuotaProcess;
    /*0x018*/     struct _LIST_ENTRY HandleTableList;                            // 2 elements, 0x10 bytes (sizeof)  
    /*0x028*/     ULONG32      UniqueProcessId;
    union                                                          // 2 elements, 0x4 bytes (sizeof)   
    {
        /*0x02C*/         ULONG32      Flags;
        struct                                                     // 5 elements, 0x1 bytes (sizeof)   
        {
            /*0x02C*/             UINT8        StrictFIFO : 1;                           // 0 BitPosition                    
            /*0x02C*/             UINT8        EnableHandleExceptions : 1;               // 1 BitPosition                    
            /*0x02C*/             UINT8        Rundown : 1;                              // 2 BitPosition                    
            /*0x02C*/             UINT8        Duplicated : 1;                           // 3 BitPosition                    
            /*0x02C*/             UINT8        RaiseUMExceptionOnInvalidHandleClose : 1; // 4 BitPosition                    
        };
    };
    /*0x030*/     struct _EX_PUSH_LOCK10 HandleContentionEvent;                    // 7 elements, 0x8 bytes (sizeof)   
    /*0x038*/     struct _EX_PUSH_LOCK10 HandleTableLock;                          // 7 elements, 0x8 bytes (sizeof)   
    union                                                          // 2 elements, 0x40 bytes (sizeof)  
    {
        /*0x040*/         struct _HANDLE_TABLE_FREE_LIST10 FreeLists[1];
        struct                                                     // 2 elements, 0x40 bytes (sizeof)  
        {
            /*0x040*/             UINT8        ActualEntry[32];
            /*0x060*/             struct _HANDLE_TRACE_DEBUG_INFO10* DebugInfo;
            /*0x068*/             UINT8        _PADDING0_[0x18];
        };
    };
}HANDLE_TABLE10, * PHANDLE_TABLE10;

    

PHANDLE_TABLE_ENTRY7
ExpLookupHandleTableEntry7(
    IN PHANDLE_TABLE7 HandleTable, // EPROCESS 里的HANDLE_TABLE
    IN EXHANDLE Handle
);

PHANDLE_TABLE_ENTRY10
ExpLookupHandleTableEntry10(
    IN PHANDLE_TABLE10 HandleTable, // EPROCESS 里的HANDLE_TABLE
    IN EXHANDLE Handle
);

/**
* @参数1 句柄表  
* @参数2 句柄值
* @返回值 句柄指向的具体对象主体，而不是对象头部
*/
PVOID GetObject10(PHANDLE_TABLE10 HandleTable, ULONG_PTR Handle);

/**
* 2021.9.15 
* 因没有win7环境，故未测试
*/
PVOID GetObject7(PHANDLE_TABLE7 HandleTable, ULONG_PTR Handle);