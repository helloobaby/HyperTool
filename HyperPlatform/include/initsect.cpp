/***
*initsect.cpp - RTC support
*
*       Copyright (c) 1998-2001, Microsoft Corporation. All rights reserved.
*
*
*Revision History:
*       11-03-98  KBF   Module incorporated into CRTs
*       05-11-99  KBF   Error if RTC support define not enabled
*       08-10-99  RMS   Use external symbols for BBT support
*
****/

/*MSVC对CRT的行为
* 他会把析构函数传给atexit，我们可以在atexit中用一个vector(可能会引起CRT的重入)捕获所有析构函数，然后在DriverEntry中调用
.text:0000000140001000 _dynamic_initializer_for__testVector__ proc near
.text:0000000140001000                                         ; DATA XREF: .rdata:testVector$initializer$↓o
.text:0000000140001000                                         ; .rdata:__guard_fids_table↓o ...
.text:0000000140001000                 sub     rsp, 28h
.text:0000000140001004                 lea     rcx, testVector
.text:000000014000100B                 call    std__vector_std__string___vector_std__string_
.text:0000000140001010                 lea     rcx, _dynamic_atexit_destructor_for__testVector__
.text:0000000140001017                 call    atexit
.text:000000014000101C                 add     rsp, 28h
.text:0000000140001020                 retn
.text:0000000140001020 _dynamic_initializer_for__testVector__ endp
*/

typedef void(__cdecl* _PVFV)(void);
typedef int(__cdecl* _PIFV)(void);

#include "sect_attribs.h"
#include "vector.hpp"

//https://docs.microsoft.com/en-us/cpp/c-runtime-library/crt-initialization?view=msvc-160
//https://github.com/helloobaby/Nt5Src-Lite/blob/c0c99e7edefbf14e30b4eb4416026575b2a6c96c/base/crts/crtw32/dllstuff/crtdll.c#L223
//https://github.com/helloobaby/Nt5Src-Lite/blob/master/base/crts/crtw32/rtc/initsect.cpp

#pragma const_seg(".rtc$IAA")
extern "C" const _CRTALLOC(".CRT$XCA") _PVFV __rtc_iaa[] = { 0 };


#pragma const_seg(".rtc$IZZ")
extern "C" const _CRTALLOC(".CRT$XCZ") _PVFV __rtc_izz[] = { 0 };

//++++++ [can delete]
#pragma const_seg(".rtc$TAA")
extern "C" const _CRTALLOC(".CRT$XIA") _PVFV __rtc_taa[] = { 0 };


#pragma const_seg(".rtc$TZZ")
extern "C" const _CRTALLOC(".CRT$XIZ") _PVFV __rtc_tzz[] = { 0 };
//------
#pragma const_seg()


#pragma comment(linker, "/MERGE:.CRT=.rdata")

#ifndef _RTC_DEBUG
#pragma optimize("g", on)
#endif

std::vector<_PVFV> vConstructor;

// Run the RTC initializers
void __declspec(nothrow) __cdecl _RTC_Initialize()
{
    // Just step thru every item
    const _PVFV *f;
    for (f = __rtc_iaa + 1; f < __rtc_izz; f++)
    {
	__try {
            if (*f)
                (**f)();
        } __except(1){}
    }
}

// Run the RTC terminators
void __declspec(nothrow) __cdecl _RTC_Terminate()
{
    // Just step thru every item
    /*++
    const _PVFV *f;
    for (f = __rtc_taa + 1; f < __rtc_tzz; f++)
    {
	__try {
            if (*f)
                (**f)();
        } __except(1){}
    }
    --*/
    for (auto func : vConstructor)
    {
        __try {
            if (func)
                (*func)();
        }
        __except (1) {}
    }
}

int __cdecl atexit(
    _PVFV func
)
{
    vConstructor.push_back(func);
    return 0;
}
