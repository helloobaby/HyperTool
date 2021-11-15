#include"device.h"

static UNICODE_STRING uDevice = RTL_CONSTANT_STRING(DEVICE_NAME);
static UNICODE_STRING uSymbol = RTL_CONSTANT_STRING(DOS_DEVICE_NAME);

NTSTATUS HyperInitDeviceAll(PDRIVER_OBJECT DriverObject)
{
	PDEVICE_OBJECT deviceObject = NULL;
	NTSTATUS Status;

	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = HyperDispatch;

	Status = IoCreateDevice(
		DriverObject,
		0,
		&uDevice,
		0xffff,
		0,
		false,
		&deviceObject);
	if (!NTSTATUS(Status))
	{
		Log("HyperTool IoCreateDeivce failed with status 0x%x\n", Status);
		return Status;
	}

	
	Status = IoCreateSymbolicLink(&uSymbol, &uDevice);

	if (!NTSTATUS(Status))
	{
		Log("HyperTool IoCreateSymbolicLink failed with status 0x%x\n", Status);
		return Status;
	}

	return Status;

}

NTSTATUS HyperDestroyDeviceAll(PDRIVER_OBJECT DriverObject)
{
	NTSTATUS Status;
	IoDeleteDevice(DriverObject->DeviceObject);
	Status = IoDeleteSymbolicLink(&uSymbol);
	return Status;
}

NTSTATUS HyperDispatch(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
#ifdef DBG
	Log("HyperDispatch : Entry \n");
#endif // DBG
	NTSTATUS Status = STATUS_SUCCESS;








	return Status;
}

