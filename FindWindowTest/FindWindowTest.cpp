#include <iostream>
#include <Windows.h>

int main()
{
    FindWindowEx(0, 0, NULL, L"123");
    getchar();
}

