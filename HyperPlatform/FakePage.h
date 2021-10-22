#pragma once 
#include<ntdef.h>

struct FakePage
{
    PVOID GuestVA;//要fake的guest线性地址
    PHYSICAL_ADDRESS GuestPA;
    PVOID PageContent;//包含这个页面的信息，在vmlaunch之前填充好,也就是guest能看到的页面内容
    PHYSICAL_ADDRESS PageContentPA;
};

struct ICFakePage
{
    virtual void Construct() = 0;
    virtual void Destruct() = 0;
    FakePage fp;
};
