#include "device.h"
#include "log.h"

static UNICODE_STRING uDevice = RTL_CONSTANT_STRING(DEVICE_NAME);
static UNICODE_STRING uSymbol = RTL_CONSTANT_STRING(DOS_DEVICE_NAME);

NTSTATUS HyperInitDeviceAll(PDRIVER_OBJECT DriverObject)
{
	HYPERPLATFORM_LOG_INFO("HyperInitDevice enter");
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
		HYPERPLATFORM_LOG_INFO("HyperTool IoCreateDeivce failed with status 0x%x\n", Status);
		return Status;
	}

	deviceObject->Flags |= DO_BUFFERED_IO;

	
	Status = IoCreateSymbolicLink(&uSymbol, &uDevice);

	if (!NT_SUCCESS(Status))
	{
		HYPERPLATFORM_LOG_INFO("HyperTool IoCreateSymbolicLink failed with status 0x%x\n", Status);
		IoDeleteDevice(deviceObject);
		return Status;
	}

	HYPERPLATFORM_LOG_INFO("HyperInitDevice suc");
	return Status;
}

NTSTATUS HyperDestroyDeviceAll(PDRIVER_OBJECT DriverObject)
{
	HYPERPLATFORM_LOG_INFO("HyperDestroyDeviceAll enter");
	NTSTATUS Status;
	if (DriverObject->DeviceObject && MmIsAddressValid(DriverObject->DeviceObject))
		IoDeleteDevice(DriverObject->DeviceObject);
	Status = IoDeleteSymbolicLink(&uSymbol);
	return Status;
}

NTSTATUS HyperDispatchControl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
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
		
		case IOCTL_HYPER_TOOL_TEST: // Test
			break;
		case IOCTL_HYPER_HIDE_WINDOW:
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