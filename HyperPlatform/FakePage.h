#pragma once 
#include<ntdef.h>

struct FakePage
{
    // //要fake的guest线性地址
    PVOID GuestVA;
    PHYSICAL_ADDRESS GuestPA;
    // 包含这个页面的信息，在vmlaunch之前填充好,也就是guest能看到的页面内容
    PVOID PageContent;
    PHYSICAL_ADDRESS PageContentPA;
};

struct ICFakePage
{
    virtual void Construct() = 0;
    virtual void Destruct() = 0;
    FakePage fp;
};
