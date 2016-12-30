/*
=======================================================================

Work event driver
=================

Companion test program to What Makes It Page?

Copyright (c), 2012 by Enrico Martignetti - All rights reserved.




=======================================================================



*/



//----------------------------------------------------------------------
//
// Includes
// --------


extern "C" {
#include <NTDDK.h>
}


// Defs shared with ring 3 components.
//

#include "DrvR3.h"

// Definition of the internal device name and symbolic link. They are 
// derived from DRV_DEVICE_NAME which is the public name defined
// into DrvR3.h and used by client applications.

#define DRV_INT_NAME    L"\\Device\\"DRV_DEVICE_NAME
#define DRV_SYM_LINK    L"\\??\\"DRV_DEVICE_NAME

// These are offsets of unexported functions of ntkrnlmp.exe from
// KeSetEvent. They are used to compute the functions addresses from
// the one of KeSetEvent, which is exported and hence available in the
// program.
//
// The computed addresses are stored into function pointers
// which are used to call the functions.
//
// CAUTION: these offsets are valid for Windows 7 x64 RTM. For any
// other Windows version, they are likely to give invalid addresses
// and lead to a system crash when these functions are called.
//
#define KE_INITIALIZE_GATE_OFFSET				0x70980
#define KE_SIGNAL_GATE_BOOST_PRIORITY_OFFSET	0x2eba0


//----------------------------------------------------------------------
//
// Data Types
// ----------


typedef struct _DEVICE_EXTENSION {
	PDEVICE_OBJECT	pDevice;

	UNICODE_STRING	uSymName;
    KEVENT			EventV[EVENT_COUNT];
	PRKEVENT		EventPtrsV[EVENT_COUNT];
	KGATE			Gate;
	

} DEVICE_EXTENSION, *PDEVICE_EXTENSION;


// Type declarations for the pointers to functions for gate objects
//
typedef VOID (*PKE_SIGNAL_GATE_BOOST_PRIORITY) (PKGATE);
typedef VOID (*PKE_INITIALIZE_GATE) (PKGATE);


//----------------------------------------------------------------------
//
// Statics
// -------

PKE_INITIALIZE_GATE lpKeInitializeGate;
PKE_SIGNAL_GATE_BOOST_PRIORITY lpKeSignalGateBoostPriority;

//----------------------------------------------------------------------
//
// Forward declarations
// --------------------



static VOID DriverUnload (
		IN PDRIVER_OBJECT	pDriverObject	);

static NTSTATUS ClearEvent(
	PDEVICE_EXTENSION	pDevExt,
	PIRP				pIrp );

static NTSTATUS CreateDevice (
		IN PDRIVER_OBJECT	pDriverObject,
		OUT PDEVICE_EXTENSION*	ppDevExt	);

static NTSTATUS DeleteDevices(
		IN PDRIVER_OBJECT	pDriverObject	);

static NTSTATUS DispatchCreate (
		IN PDEVICE_OBJECT	pDevObj,
		IN PIRP				pIrp			);

static NTSTATUS DispatchClose (
		IN PDEVICE_OBJECT	pDevObj,
		IN PIRP				pIrp			);

static NTSTATUS DispatchDioc (
		IN PDEVICE_OBJECT	pDevObj,
		IN PIRP				pIrp			);

static VOID PrintObjAddresses(
	PDEVICE_EXTENSION		pDevExt);

static NTSTATUS SignalEvent(
	IN PDEVICE_EXTENSION	pDevExt,
	IN PIRP					pIrp);

static NTSTATUS SignalGate(
	IN PDEVICE_EXTENSION	pDevExt,
	IN PIRP					pIrp);


//----------------------------------------------------------------------
//
// Functions
// ---------


//++
// Function:	DriverEntry
//
// Description:
//
//      Announces entry points.
//
//		Creates the device object used to send control codes to this
//		module.
//
// Arguments:
//		pDriverObject - Passed from I/O Manager
//		pRegistryPath - UNICODE_STRING pointer to
//						registry info (service key)
//						for this driver
//
// Return value:
//		NTSTATUS signaling success or failure
//--
extern "C" NTSTATUS DriverEntry (
			IN PDRIVER_OBJECT pDriverObject,
			IN PUNICODE_STRING pRegistryPath	) {
	NTSTATUS status;
	PDEVICE_EXTENSION	pDevExt;

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n\n\nWrkEvent - Work event driver, compiled %s %s\n",__DATE__, __TIME__);

	PCHAR lpSetEvent = (PCHAR) &KeSetEvent;
	lpKeSignalGateBoostPriority = (PKE_SIGNAL_GATE_BOOST_PRIORITY) (lpSetEvent - KE_SIGNAL_GATE_BOOST_PRIORITY_OFFSET);
	lpKeInitializeGate = (PKE_INITIALIZE_GATE) (lpSetEvent - KE_INITIALIZE_GATE_OFFSET);
	//lpMpwGate = (PKGATE) (lpSetEvent + 0x1b1650);



	// Announce other driver entry points
	pDriverObject->DriverUnload = DriverUnload;
	pDriverObject->MajorFunction[IRP_MJ_CREATE] =
				DispatchCreate;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] =
				DispatchClose;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] =
				DispatchDioc;
	
	// Create the logical device
	status =
		CreateDevice(pDriverObject, &pDevExt);
	if (!NT_SUCCESS(status))
		return status;


	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\nWrkEvent - Work event driver successfully loaded.");

	return STATUS_SUCCESS;
}


//++
// Function:	DriverUnload
//
// Description:
//
//      Realases any resource stored into the device extension,
//      then realases the device object.
//
// Arguments:
//		pDriverObject - Passed from I/O Manager
//
// Return value:
//		None
//--

static VOID DriverUnload (
		IN PDRIVER_OBJECT	pDriverObject	) {

	// Delete the logical device.
	DeleteDevices(pDriverObject);

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\nWrkEvent - Driver unloaded");


	return;
}


//++
// Function:	ClearEvent
//
// Description:
//		Sets one of the work events to the non-signaled state.
//
//		The event index is passed in the IRP.
//
// Arguments:
//		pDevExt - Address of device extension.
//
// Return value:
//		NTSTATUS. 
//
//--
static NTSTATUS ClearEvent(
	PDEVICE_EXTENSION	pDevExt,
	PIRP				pIrp )
{
	PIO_STACK_LOCATION pIoSl = IoGetCurrentIrpStackLocation(pIrp);
	if (pIoSl->Parameters.DeviceIoControl.InputBufferLength < sizeof INT) {
		return STATUS_INVALID_PARAMETER;
	}
	UINT32 index = *((UINT32*) pIrp->AssociatedIrp.SystemBuffer);
	if (index >= sizeof pDevExt->EventV / sizeof KEVENT) {
		return STATUS_INVALID_PARAMETER;
	}
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\nWrkEvent - Clearing event #%d", index);
	KeClearEvent(&(pDevExt->EventV[index]));
	return STATUS_SUCCESS;
}


//++
// Function:	CreateDevice
//
// Description:
//		Adds a new device.
//
//		Initializes the device extension.
//
// Arguments:
//		pDriverObject - Passed from I/O Manager
//
//		ppDevExt - pointer to a pointer which will receive the
//			address of the device extension returned by the
//			I/O manager.
//
// Return value:
//		NTSTATUS
//
//--
static NTSTATUS CreateDevice (
		IN PDRIVER_OBJECT	pDriverObject,
		OUT PDEVICE_EXTENSION*	ppDevExt	) 
{

	NTSTATUS status;
	PDEVICE_OBJECT pDevObj;
	PDEVICE_EXTENSION pDevExt;
	UNICODE_STRING uRecName;

	RtlInitUnicodeString(&uRecName,
        DRV_INT_NAME);

	status =
		IoCreateDevice( pDriverObject,
						sizeof(DEVICE_EXTENSION),
						&uRecName,
						FILE_DEVICE_UNKNOWN,
						0, FALSE,
						&pDevObj );
	if (!NT_SUCCESS(status))
		return status;

	// Request buffered I/O
	//
	pDevObj->Flags |= DO_BUFFERED_IO;
	pDevObj->Flags &= ~DO_DEVICE_INITIALIZING;

	pDevExt = (PDEVICE_EXTENSION)pDevObj->DeviceExtension;

	pDevExt->pDevice = pDevObj;	// back pointer
	for (INT i = 0; i < sizeof pDevExt->EventV / sizeof (KEVENT); i++) {
		KeInitializeEvent(&pDevExt->EventV[i], NotificationEvent, FALSE);
		pDevExt->EventPtrsV[i] = &pDevExt->EventV[i];
	}
	(*lpKeInitializeGate)(&pDevExt->Gate);
	*ppDevExt = pDevExt;

	// Form the symbolic link name
	RtlInitUnicodeString(&pDevExt->uSymName,
        DRV_SYM_LINK);
	status = 
		IoCreateSymbolicLink( &pDevExt->uSymName,
							  &uRecName );
	if (!NT_SUCCESS(status)) {

		IoDeleteDevice( pDevObj );
		return status;
	}

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\nWrkEvent - Device created");

	PrintObjAddresses(pDevExt);

	return STATUS_SUCCESS;
}


//++
// Function:	DeleteDevices
//
// Description:
//		Deletes the device created by this driver.
//
// Arguments:
//		pDriverObject - pointer to driver object
//
// Return value:
//		NTSTATUS - success or failure code
//--
static NTSTATUS DeleteDevices(IN PDRIVER_OBJECT pDriverObject) 
{

	PDEVICE_OBJECT	pNextObj;
	UNICODE_STRING  uSymName;

	pNextObj = pDriverObject->DeviceObject;
	if (pNextObj != NULL) {

		// Delete the symbolic link
		//
		PDEVICE_EXTENSION pDevExt = (PDEVICE_EXTENSION) pNextObj->DeviceExtension;
		IoDeleteSymbolicLink(&pDevExt->uSymName);

		// Delete the device.
		IoDeleteDevice( pNextObj );
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\nWrkEvent - Device deleted");
	} else {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\nWrkEvent - No devices to delete");
	}
	return STATUS_SUCCESS;

}



//++
// Function:	DispatchClose
//
// Description:
//		Handles call from Win32 CloseHandle request.
//
//		For this driver, does nothing
//
// Arguments:
//		pDevObj - Passed from I/O Manager
//		pIrp - Passed from I/O Manager
//
// Return value:
//		NTSTATUS - always returns STATUS_SUCCESS;
//--
static NTSTATUS DispatchClose (
		IN PDEVICE_OBJECT	pDevObj,
		IN PIRP				pIrp			) {
 
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;	// no bytes xfered
	IoCompleteRequest( pIrp, IO_NO_INCREMENT );

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\nWrkEvent - Device closed");


	return STATUS_SUCCESS;
}


//++
// Function:	DispatchCreate
//
// Description:
//		Handles call from Win32 CreateFile request
//
//		For this driver, does nothing.
//
// Arguments:
//		pDevObj - Passed from I/O Manager
//		pIrp - Passed from I/O Manager
//
// Return value:
//		NTSTATUS - always returns STATUS_SUCCESS;
//--
static NTSTATUS DispatchCreate (
		IN PDEVICE_OBJECT	pDevObj,
		IN PIRP				pIrp			) {

	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;	// no bytes xfered
	IoCompleteRequest( pIrp, IO_NO_INCREMENT );

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\nWrkEvent - Device opened");

	return STATUS_SUCCESS;
}

//++
// Function:	DispatchDioc
//
// Description:
//		Handles call from Win32 DeviceIoControl request.
//
// Arguments:
//		pDevObj - Passed from I/O Manager
//		pIrp - Passed from I/O Manager
//
// Return value:
//		NTSTATUS - success or failure code
//--
static NTSTATUS DispatchDioc (
		IN PDEVICE_OBJECT	pDevObj,
		IN PIRP				pIrp			) {



	NTSTATUS status = STATUS_SUCCESS;

	PIO_STACK_LOCATION pIrpStack = IoGetCurrentIrpStackLocation(pIrp);
	ULONG ctlCode = pIrpStack->Parameters.DeviceIoControl.IoControlCode;

	pIrp->IoStatus.Information = 0;
	
	switch (ctlCode) {
		case IOCTL_WRKEVENT_SIGNAL_EVENT:
			status = SignalEvent((PDEVICE_EXTENSION) pDevObj->DeviceExtension, pIrp);
			break;
		case IOCTL_WRKEVENT_CLEAR_EVENT:
			status = ClearEvent((PDEVICE_EXTENSION) pDevObj->DeviceExtension, pIrp);
			break;
		case IOCTL_WRKEVENT_SIGNAL_GATE:
			status = SignalGate((PDEVICE_EXTENSION) pDevObj->DeviceExtension, pIrp);
			break;
		case IOCTL_WRKEVENT_PRINT_OBJ_ADDRS:
			PrintObjAddresses((PDEVICE_EXTENSION) pDevObj->DeviceExtension);
			status = STATUS_SUCCESS;
			break;
		default:
			status = STATUS_INVALID_DEVICE_REQUEST;
			break;
	}

	// If the request isn't complete, return STATUS_PENDING.
	if (status == STATUS_PENDING)
		return status;

    // Note: IoMarkIrpPending must have already been called
    // by the function which returned STATUS_PENDING.

	// Otherwise, complete the IRP.
	//
	pIrp->IoStatus.Status = status;
	IoCompleteRequest( pIrp, IO_NO_INCREMENT );
	return status;

}


//++
// Function:	PrintObjAddresses
//
// Description:
//		Prints the addresses of the wait objects stored in the device 
//		extension to the debugger console.
//
// Arguments:
//		pDevExt - ptr to device extension
//
// Return value: none
//--
static VOID PrintObjAddresses(
	PDEVICE_EXTENSION		pDevExt)
{
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n\nWrkEvent - Object addresses:");
	for (INT i = 0; i < sizeof pDevExt->EventV / sizeof (KEVENT); i++) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n    WrkEvent[%i] address  : %#p", i, &(pDevExt->EventV[i]));
	}
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n    Ev ptr array address : %#p", pDevExt->EventPtrsV);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n    Gate address         : %#p", &(pDevExt->Gate));
}


//++
// Function:	SignalEvent
//
// Description:
//		Sets one of the work events to signaled. The event index is passed
//		in the IRP.
//
// Arguments:
//		pDevExt - pDevExt->Event signaled
//
// Return value:
//		NTSTATUS - success or failure code
//--
static NTSTATUS SignalEvent(
	IN PDEVICE_EXTENSION	pDevExt,
	IN PIRP					pIrp)
{
	PIO_STACK_LOCATION pIoSl = IoGetCurrentIrpStackLocation(pIrp);
	if (pIoSl->Parameters.DeviceIoControl.InputBufferLength < sizeof INT) {
		return STATUS_INVALID_PARAMETER;
	}
	UINT32 index = *((UINT32*) pIrp->AssociatedIrp.SystemBuffer);
	if (index >= sizeof pDevExt->EventV / sizeof KEVENT) {
		return STATUS_INVALID_PARAMETER;
	}
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\nWrkEvent - Signaling event #%d", index);
	KeSetEvent(&(pDevExt->EventV[index]), 0, FALSE);
	return STATUS_SUCCESS;
}


//++
// Function:	SignalGate
//
// Description:
//		Sets the work gate to signaled.
//
// Arguments:
//		pDevExt - pDevExt->Gate is signaled
//
// Return value:
//		NTSTATUS - success or failure code
//--
static NTSTATUS SignalGate(
	IN PDEVICE_EXTENSION	pDevExt,
	IN PIRP					pIrp)
{
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\nWrkEvent - Signaling the gate");
	(*lpKeSignalGateBoostPriority)(&pDevExt->Gate);
	return STATUS_SUCCESS;
}
