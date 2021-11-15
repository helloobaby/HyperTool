/*
传统的驱动通信
*/

#include"include/stdafx.h"

#define DEVICE_NAME     L"\\Device\\HyperTool"
#define DOS_DEVICE_NAME L"\\DosDevices\\HyperTool" 




NTSTATUS HyperInitDeviceAll(PDRIVER_OBJECT DriverObject);

NTSTATUS HyperDispatch(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

NTSTATUS HyperDestroyDeviceAll(PDRIVER_OBJECT DriverObject);