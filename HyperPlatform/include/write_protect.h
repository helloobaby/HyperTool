#pragma once
#include "stdafx.h"
#include <intrin.h>
#include "../log.h"

// 判断处理器是否开启影子堆栈
// This flag can be set only if CR0.WP is set, and it must be clear before CR0.WP can be cleared
inline bool is_cet_enable = false;

inline KIRQL WPOFFx64()
{
    //
    //禁止线程切换，防止这条线程跑到其他核心上面
    //
    KIRQL irql = KeRaiseIrqlToDpcLevel();

    if (is_cet_enable) {
        // 先清除它，然后才能清除 CR0.WP
        __writecr4(__readcr4() & 0xFFFFFFFFFF7FFFFF);
    }

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
    if (is_cet_enable) {
        __writecr4(__readcr4() | 0x800000);
    }
    KeLowerIrql(irql);

    //_enable();

}
