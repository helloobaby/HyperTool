#include "stdafx.h"
#include <windows.h>
#include <intrin.h>

using namespace std;

int filter(EXCEPTION_POINTERS* pException, BOOL* pFound)
{
    auto code = *(BYTE*)pException->ContextRecord->Eip;

    printf("cpuid exception eip = %p code = %02x\n", pException->ContextRecord->Eip, code);

    //code != nop, in vmm
    if (code != 0x90)
        *pFound = TRUE;

    return EXCEPTION_EXECUTE_HANDLER;
}

int filter2(EXCEPTION_POINTERS* pException, BOOL* pFound)
{
    printf("vmcall exception eip = %p, exception = %X\n", pException->ContextRecord->Eip, pException->ExceptionRecord->ExceptionCode);

    //ExceptionCode == #GP, in real OS 
    if (pException->ExceptionRecord->ExceptionCode == 0xC000001D)
        *pFound = FALSE;

    return EXCEPTION_EXECUTE_HANDLER;
}

BOOL vmcall_test()
{
    BOOL bFound = TRUE;
    __try
    {
        //vmcall
        __asm {//这里会出#UD
            _emit 0x0f;
            _emit 0x01;
            _emit 0xc1;
        }
    }
    __except (filter2(GetExceptionInformation(), &bFound))
    {
        ;
    }
    return bFound;
}

BOOL cpuid_test()
{
    BOOL bFound = FALSE;
    __try
    {
        __asm
        {
            mov eax, 0
            pushfd;
            or DWORD ptr[esp], 0x100;//TF flag
            popfd;//set TF=1
            cpuid;
            nop;//normal TF
            int 3//in vmm...
        }
    }
    __except (filter(GetExceptionInformation(), &bFound))
    {
        ;
    }
    return bFound;
}

int main()
{
    auto b = cpuid_test();
    if (b)
        printf("cpuid run in vmm\r\n");
    else
        printf("cpuid run in real\r\n");

    auto c = vmcall_test();
    if (c)
        printf("vmcall run in vmm\r\n");
    else
        printf("vmcall run in real\r\n");

    system("pause");
    return 0;
}