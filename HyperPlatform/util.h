// Copyright (c) 2015-2019, Satoshi Tanda. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Declares interfaces to utility functions.

#ifndef HYPERPLATFORM_UTIL_H_
#define HYPERPLATFORM_UTIL_H_

#include "ia32_type.h"

extern "C" {
////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//
#define IS_PRINTABLE(c) (c >= 0x20 && c < 0x7f)
#define IS_ENDLINE(c) (c == 0x0A || c == 0xD)
////////////////////////////////////////////////////////////////////////////////
//
// constants and macros
//

////////////////////////////////////////////////////////////////////////////////
//
// types
//

/// Represents ranges of addresses
struct PhysicalMemoryRun {
  ULONG_PTR base_page;   //!< A base address / PAGE_SIZE (ie, 0x1 for 0x1000)
  ULONG_PTR page_count;  //!< A number of pages
};
#if defined(_AMD64_)
static_assert(sizeof(PhysicalMemoryRun) == 0x10, "Size check");
#else
static_assert(sizeof(PhysicalMemoryRun) == 0x8, "Size check");
#endif


typedef struct _SYSTEM_HANDLE_INFORMATION
{
    ULONG ProcessId;
    UCHAR ObjectTypeNumber;
    UCHAR Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;
}SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX
{
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_INFORMATION Information[1];
}SYSTEM_HANDLE_INFORMATION_EX, * PSYSTEM_HANDLE_INFORMATION_EX;

/// Represents a physical memory ranges of the system
struct PhysicalMemoryDescriptor {
  PFN_COUNT number_of_runs;    //!< A number of PhysicalMemoryDescriptor::run
  PFN_NUMBER number_of_pages;  //!< A physical memory size in pages
  PhysicalMemoryRun run[1];    //!< ranges of addresses
};
#if defined(_AMD64_)
static_assert(sizeof(PhysicalMemoryDescriptor) == 0x20, "Size check");
#else
static_assert(sizeof(PhysicalMemoryDescriptor) == 0x10, "Size check");
#endif

/// Indicates a result of VMX-instructions
///
/// This convention was taken from the VMX-intrinsic functions by Microsoft.
enum class VmxStatus : unsigned __int8 {
  kOk = 0,                  //!< Operation succeeded
  kErrorWithStatus = 1,     //!< Operation failed with extended status available
  kErrorWithoutStatus = 2,  //!< Operation failed without status available
};

/// Provides |= operator for VmxStatus
constexpr VmxStatus operator|=(_In_ VmxStatus lhs, _In_ VmxStatus rhs) {
  return static_cast<VmxStatus>(static_cast<unsigned __int8>(lhs) |
                                static_cast<unsigned __int8>(rhs));
}

/// Available command numbers for VMCALL
enum class HypercallNumber : unsigned __int32 {
  kMinimumHypercallNumber,
  kTerminateVmm = kMinimumHypercallNumber,  //!< Terminates VMM
  kPingVmm,                                 //!< Sends ping to the VMM
  kGetSharedProcessorData,                  //!< Returns shared processor data
  kMaximumHypercallNumber = kGetSharedProcessorData,
};

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

/// Makes the Util functions ready for use
/// @param driver_object   The current driver's driver object
/// @return STATUS_SUCCESS on success
_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS
    UtilInitialization(_In_ PDRIVER_OBJECT driver_object);

/// Frees all resources allocated for the sake of the Util functions
_IRQL_requires_max_(PASSIVE_LEVEL) void UtilTermination();

/// Returns a module base address of \a address
/// @param address An address to get a base address
/// @return A base address of a range \a address belongs to, or nullptr
void *UtilPcToFileHeader(_In_ void *address);

/// Returns ranges of physical memory on the system
/// @return Physical memory ranges; never fails
const PhysicalMemoryDescriptor *UtilGetPhysicalMemoryRanges();

/// Executes \a callback_routine on each processor
/// @param callback_routine   A function to execute
/// @param context  An arbitrary parameter for \a callback_routine
/// @return STATUS_SUCCESS when \a returned STATUS_SUCCESS on all processors
_IRQL_requires_max_(APC_LEVEL) NTSTATUS
    UtilForEachProcessor(_In_ NTSTATUS (*callback_routine)(void *),
                         _In_opt_ void *context);

/// Queues \a deferred_routine on all processors
/// @param deferred_routine   A DPC routine to be queued
/// @param context  An arbitrary parameter for \a deferred_routine
/// @return STATUS_SUCCESS when DPC was queued to all processors
///
/// \a deferred_routine must free the pointer to a DPC structure like this:
/// ExFreePoolWithTag(dpc, kHyperPlatformCommonPoolTag).
_IRQL_requires_max_(DISPATCH_LEVEL) NTSTATUS
    UtilForEachProcessorDpc(_In_ PKDEFERRED_ROUTINE deferred_routine,
                            _In_opt_ void *context);

/// Suspends the execution of the current thread
/// @param millisecond  Time to suspend in milliseconds
/// @return STATUS_SUCCESS on success
_IRQL_requires_max_(APC_LEVEL) NTSTATUS UtilSleep(_In_ LONG millisecond);

/// Searches a byte pattern from a given address range
/// @param search_base  An address to start search
/// @param search_size  A length to search in bytes
/// @param pattern  A byte pattern to search
/// @param pattern_size   A size of \a pattern
/// @return An address of the first occurrence of the patten if found, or
/// nullptr
void *UtilMemMem(_In_ const void *search_base, _In_ SIZE_T search_size,
                 _In_ const void *pattern, _In_ SIZE_T pattern_size);

/// Get an address of an exported symbol by the kernel or HAL
/// @param proc_name  A name of a symbol to locate an address
/// @return An address of the symbol or nullptr
void *UtilGetSystemProcAddress(_In_ const wchar_t *proc_name);

/// Checks if the system is a PAE-enabled x86 system
/// @return true if the system is a PAE-enabled x86 system
bool UtilIsX86Pae();

/// Checks is the address is present on physical memory
/// @param address  A virtual address to test
/// @return true if the \a address is present on physical memory
bool UtilIsAccessibleAddress(_In_ void *address);

/// VA -> PA
/// @param va   A virtual address to get its physical address
/// @return A physical address of \a va, or nullptr
///
/// @warning
/// It cannot be used for a virtual address managed by a prototype PTE.
ULONG64 UtilPaFromVa(_In_ void *va);

/// VA -> PFN
/// @param va   A virtual address to get its physical address
/// @return A page frame number of \a va, or 0
///
/// @warning
/// It cannot be used for a virtual address managed by a prototype PTE.
PFN_NUMBER UtilPfnFromVa(_In_ void *va);

/// PA -> PFN
/// @param pa   A physical address to get its page frame number
/// @return A page frame number of \a pa, or 0
PFN_NUMBER UtilPfnFromPa(_In_ ULONG64 pa);

/// PA -> VA
/// @param pa   A physical address to get its virtual address
/// @return A virtual address \a pa, or 0
void *UtilVaFromPa(_In_ ULONG64 pa);

/// PNF -> PA
/// @param pfn   A page frame number to get its physical address
/// @return A physical address of \a pfn
ULONG64 UtilPaFromPfn(_In_ PFN_NUMBER pfn);

/// PNF -> VA
/// @param pfn   A page frame number to get its virtual address
/// @return A virtual address of \a pfn
void *UtilVaFromPfn(_In_ PFN_NUMBER pfn);

/// Allocates continuous physical memory
/// @param number_of_bytes  A size to allocate
/// @return A base address of an allocated memory or nullptr
///
/// A returned value must be freed with UtilFreeContiguousMemory().
_Must_inspect_result_ _IRQL_requires_max_(DISPATCH_LEVEL) void
    *UtilAllocateContiguousMemory(_In_ SIZE_T number_of_bytes);

/// Frees an address allocated by UtilAllocateContiguousMemory()
/// @param base_address A return value of UtilAllocateContiguousMemory() to free
_IRQL_requires_max_(DISPATCH_LEVEL) void UtilFreeContiguousMemory(
    _In_ void *base_address);

/// Executes VMCALL
/// @param hypercall_number   A command number
/// @param context  An arbitrary parameter
/// @return STATUS_SUCCESS if VMXON instruction succeeded
NTSTATUS UtilVmCall(_In_ HypercallNumber hypercall_number,
                    _In_opt_ void *context);

/// Debug prints registers
/// @param all_regs   Registers to print out
/// @param stack_pointer  A stack pointer before calling this function
void UtilDumpGpRegisters(_In_ const AllRegisters *all_regs,
                         _In_ ULONG_PTR stack_pointer);

/// Reads natural-width VMCS
/// @param field  VMCS-field to read
/// @return read value
ULONG_PTR UtilVmRead(_In_ VmcsField field);

/// Reads 64bit-width VMCS
/// @param field  VMCS-field to read
/// @return read value
ULONG64 UtilVmRead64(_In_ VmcsField field);

/// Writes natural-width VMCS
/// @param field  VMCS-field to write
/// @param field_value  A value to write
/// @return A result of the VMWRITE instruction
VmxStatus UtilVmWrite(_In_ VmcsField field, _In_ ULONG_PTR field_value);

/// Writes 64bit-width VMCS
/// @param field  VMCS-field to write
/// @param field_value  A value to write
/// @return A result of the VMWRITE instruction
VmxStatus UtilVmWrite64(_In_ VmcsField field, _In_ ULONG64 field_value);

/// Reads natural-width MSR
/// @param msr  MSR to read
/// @return read value
ULONG_PTR UtilReadMsr(_In_ Msr msr);

/// Reads 64bit-width MSR
/// @param msr  MSR to read
/// @return read value
ULONG64 UtilReadMsr64(_In_ Msr msr);

/// Writes natural-width MSR
/// @param msr  MSR to write
/// @param value  A value to write
void UtilWriteMsr(_In_ Msr msr, _In_ ULONG_PTR value);

/// Writes 64bit-width MSR
/// @param msr  MSR to write
/// @param value  A value to write
void UtilWriteMsr64(_In_ Msr msr, _In_ ULONG64 value);

/// Executes the INVEPT instruction and invalidates EPT entry cache
/// @return A result of the INVEPT instruction
VmxStatus UtilInveptGlobal();

/// Executes the INVVPID instruction (type 0)
/// @return A result of the INVVPID instruction
VmxStatus UtilInvvpidIndividualAddress(_In_ USHORT vpid, _In_ void *address);

/// Executes the INVVPID instruction (type 1)
/// @return A result of the INVVPID instruction
VmxStatus UtilInvvpidSingleContext(_In_ USHORT vpid);

/// Executes the INVVPID instruction (type 2)
/// @return A result of the INVVPID instruction
VmxStatus UtilInvvpidAllContext();

/// Executes the INVVPID instruction (type 3)
/// @return A result of the INVVPID instruction
VmxStatus UtilInvvpidSingleContextExceptGlobal(_In_ USHORT vpid);

/// Loads the PDPTE registers from CR3 to VMCS
/// @param cr3_value  CR3 value to retrieve PDPTEs
void UtilLoadPdptes(_In_ ULONG_PTR cr3_value);

/// Does RtlCopyMemory safely even if destination is a read only region
/// @param destination  A destination address
/// @param source  A source address
/// @param length  A size to copy in bytes
/// @return STATUS_SUCCESS if successful
_IRQL_requires_max_(DISPATCH_LEVEL) NTSTATUS
    UtilForceCopyMemory(_In_ void *destination, _In_ const void *source,
                        _In_ SIZE_T length);

/// 根据EPROCESS获得进程全路径
/// @param Process 目标进程结构
/// @return if (ProcessName) { RtlFreeUnicodeString(ProcessName); ExFreePool(ProcessName);}
PUNICODE_STRING UtilGetProcessNameByEPROCESS(PEPROCESS Process);

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

}  // extern "C"

/// Tests if \a value is in between \a min and \a max
/// @param value  A value to test
/// @param min  A minimum acceptable value
/// @param max  A maximum acceptable value
/// @return true if \a value is in between \a min and \a max
template <typename T>
constexpr bool UtilIsInBounds(_In_ const T &value, _In_ const T &min,
                              _In_ const T &max) {
  return (min <= value) && (value <= max);
}

// RAII Support 
namespace detail {

    template <typename Callable> class scope_exit {
        Callable ExitFunction;
        bool Engaged = true; // False once moved-from or release()d.

    public:
        template <typename Fp>
        explicit scope_exit(Fp&& F) : ExitFunction(F) {}

        scope_exit(scope_exit&& Rhs)
            : ExitFunction(Rhs.ExitFunction), Engaged(Rhs.Engaged) {
            Rhs.release();
        }
        scope_exit(const scope_exit&) = delete;
        scope_exit& operator=(scope_exit&&) = delete;
        scope_exit& operator=(const scope_exit&) = delete;

        void release() { Engaged = false; }

        ~scope_exit() {
            if (Engaged)
                ExitFunction();
        }
    };

} // end namespace detail

// Keeps the callable object that is passed in, and execute it at the
// destruction of the returned object (usually at the scope exit where the
// returned object is kept).
//
// Interface is specified by p0052r2.
template <typename Callable>
[[nodiscard]] detail::scope_exit<Callable>
make_scope_exit(Callable&& F) {
    return detail::scope_exit<Callable>(F);
}

PVOID GetTableInfo(ULONG TableType);

// 获得csrss.exe的Pid
HANDLE GetCrsPid();

NTSTATUS BBScanSection(IN PCCHAR section, IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, OUT PVOID* ppFound);
NTSTATUS BBSearchPattern(IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, IN const VOID* base, IN ULONG_PTR size, OUT PVOID* ppFound);

size_t getAsciiLenW(const wchar_t* inp, size_t maxInp);
enum Type {
    TypeUnknowPtr,           // 合法地址,但是不知道具体指向什么类型
    TypePUNICODE_STRING,     // 指针指向UNICODE_STRING
    TypePOBJECT_ATTRIBUTES,  // 指针指向OBJECT_ATTRIBUTES
    TypePWIDECHAR,           // 指针指向WIDE_CHAR
    TypeUnknow               // 完全不知道
};

Type GuessAddressType(ULONG_PTR Address);

#endif  // HYPERPLATFORM_UTIL_H_
