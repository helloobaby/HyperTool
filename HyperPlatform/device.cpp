#include"device.h"
#include"window.h"
#include"settings.h"

static UNICODE_STRING uDevice = RTL_CONSTANT_STRING(DEVICE_NAME);
static UNICODE_STRING uSymbol = RTL_CONSTANT_STRING(DOS_DEVICE_NAME);

NTSTATUS HyperInitDeviceAll(PDRIVER_OBJECT DriverObject)
{
#if 0
	Log("HyperInitDeviceAll\n");
#endif
	PDEVICE_OBJECT deviceObject = NULL;
	NTSTATUS Status;

	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = HyperDispatchControl;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = HyperDispatchThunk;
	DriverObject->MajorFunction[IRP_MJ_CLEANUP] = HyperDispatchThunk;

	Status = IoCreateDevice(
		DriverObject,
		0,
		&uDevice,
		FILE_DEVICE_UNKNOWN,
		0,
		false,
		&deviceObject);
	if (!NT_SUCCESS(Status))
	{
		Log("HyperTool IoCreateDeivce failed with status 0x%x\n", Status);
		return Status;
	}

	deviceObject->Flags |= DO_BUFFERED_IO;

	
	Status = IoCreateSymbolicLink(&uSymbol, &uDevice);

	if (!NT_SUCCESS(Status))
	{
		Log("HyperTool IoCreateSymbolicLink failed with status 0x%x\n", Status);
		IoDeleteDevice(deviceObject);
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

NTSTATUS HyperDispatchControl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
#if DBG
	Log("HyperDispatch : Entry \n");
#endif // DBG
	NTSTATUS status = STATUS_SUCCESS;
	PIO_STACK_LOCATION irpStack;
	PVOID ioBuffer = NULL;
	ULONG inputBufferLength = 0;
	ULONG outputBufferLength = 0;
	ULONG ioControlCode = 0;

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	irpStack = IoGetCurrentIrpStackLocation(Irp);
	ioBuffer = Irp->AssociatedIrp.SystemBuffer;
	inputBufferLength = irpStack->Parameters.DeviceIoControl.InputBufferLength;
	outputBufferLength = irpStack->Parameters.DeviceIoControl.OutputBufferLength;
	ioControlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;


	switch (ioControlCode)
	{
		
		case IOCTL_HYPER_TOOL_TEST://only for test
			Log("HyperDispatchControl Test Entry\n");
			break;
		case IOCTL_HYPER_HIDE_WINDOW:
#ifdef HIDE_WINDOW
			AttackWindowTable();
#endif // HIDE_WINDOW
			break;
		
	}




	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

NTSTATUS HyperDispatchThunk(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	Irp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}