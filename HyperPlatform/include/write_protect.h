#pragma once
#include "stdafx.h"
#include <intrin.h>

inline KIRQL WPOFFx64()
{
    //
    //禁止线程切换，防止这条线程跑到其他核心上面
    //
    KIRQL irql = KeRaiseIrqlToDpcLevel();

    UINT64 cr0 = __readcr0();
    cr0 &= 0xfffffffffffeffff;
    __writecr0(cr0);
    return irql;

    //_disable();

}

inline void WPONx64(KIRQL irql)
{
    UINT64 cr0 = __readcr0();
    cr0 |= 0x10000;
    __writecr0(cr0);
    KeLowerIrql(irql);

    //_enable();

}
