#include <iostream>
#include <Windows.h>

using namespace std;

//
// 不用管理员打开应用程序，也会出现拒绝访问
// 多加个FILE_WRITE_ACCESS用户层就会出现拒绝访问，注意一下。
//
#define IOCTL_HYPER_TOOL_TEST (ULONG)CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80E, METHOD_BUFFERED, FILE_READ_ACCESS)

int main()
{
    HANDLE handle = CreateFileW(L"\\\\.\\HyperTool", 
        GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,0, OPEN_EXISTING, 0, 0);
    if (handle != INVALID_HANDLE_VALUE)
        cout << handle << endl;
    else
        cout << "CreateFileW filed with error code " << GetLastError() << endl;

    
    DWORD byteRet;
    bool ok = DeviceIoControl(handle, IOCTL_HYPER_TOOL_TEST, 0, 0, 0, 0, &byteRet, 0);
    if (!ok)
        cout << "DeviceIoControl failed with error code " << GetLastError() << endl;


}

