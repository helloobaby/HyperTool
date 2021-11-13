#include <iostream>
#include <Windows.h>

int main()
{
    HANDLE h = FindWindowEx((HWND)0, (HWND)0, NULL, L"x64dbg");
    std::cout << h << std::endl;
}

