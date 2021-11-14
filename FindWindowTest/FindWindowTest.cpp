#include <iostream>
#include <Windows.h>
using namespace std;
int main()
{
    HANDLE h = FindWindowEx((HWND)0, (HWND)0, NULL, L"x64dbg");
    std::cout << h << std::endl;

    char window_text[MAX_PATH] = { 0 };
    GetWindowTextA((HWND)0x200d6, window_text, MAX_PATH);
    cout << window_text << endl;
}

