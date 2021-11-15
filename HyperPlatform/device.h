/*
传统的驱动通信
*/

#include"include/stdafx.h"

#define DEVICE_NAME     L"\\Device\\HyperTool"
#define DOS_DEVICE_NAME L"\\DosDevices\\HyperTool" 

#define IOCTL_HYPER_TOOL_TEST (ULONG)CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80E, METHOD_BUFFERED, FILE_READ_ACCESS)


NTSTATUS HyperInitDeviceAll(PDRIVER_OBJECT DriverObject);

NTSTATUS HyperDispatchControl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

NTSTATUS HyperDestroyDeviceAll(PDRIVER_OBJECT DriverObject);

NTSTATUS HyperDispatchThunk(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);