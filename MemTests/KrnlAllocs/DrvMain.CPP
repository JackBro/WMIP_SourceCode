/*


=======================================================================

Kernel memory allocation test driver

Companion test program to What Makes It Page?

Copyright (c), 2012 by Enrico Martignetti - All rights reserved.



=======================================================================



*/



//----------------------------------------------------------------------
//
// Defines
// -------




//----------------------------------------------------------------------
//
// Includes
// --------


extern "C" {
#include <NTDDK.h>
}


// Defs shared with ring 3 components.
//

#include "KaDrvR3.h"

// Definition of the internal device name and symbolic link. They are 
// derived from DRV_DEVICE_NAME which is the public name defined
// into DrvR3.h and used by client applications.

#define DRV_INT_NAME    L"\\Device\\"DRV_DEVICE_NAME
#define DRV_SYM_LINK    L"\\??\\"DRV_DEVICE_NAME



//----------------------------------------------------------------------
//
// Data Types
// ----------


typedef struct _DEVICE_EXTENSION {
	PDEVICE_OBJECT	pDevice;

	UNICODE_STRING	uSymName;
	

} DEVICE_EXTENSION, *PDEVICE_EXTENSION;




//----------------------------------------------------------------------
//
// Statics
// -------

CHAR	gl_DummyByte;
PVOID	lpDrvLockHandle = NULL;
CHAR	MapRegionTag[] = {'S', 'T', 'A', 'K'};


//----------------------------------------------------------------------
//
// Forward declarations
// --------------------




static VOID DriverUnload (
		IN PDRIVER_OBJECT	pDriverObject	);

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

static NTSTATUS IoAllocateMdlTest(
	PIRP				pIrp,
	PDEVICE_OBJECT		pDevObj);

static NTSTATUS IoFreeMdlTest(
	PIRP				pIrp,
	PDEVICE_OBJECT		pDevObj);

static NTSTATUS KmemTouchTest(
	PIRP				pIrp,
	PDEVICE_OBJECT		pDevObj);

static NTSTATUS LockPagFunTest(
	PIRP				pIrp,
	PDEVICE_OBJECT		pDevObj);

static NTSTATUS MdlForUserBufferTest(
	PIRP			pIrp,
	PDEVICE_OBJECT	pDevObj);

static NTSTATUS MmAllocateMappingAddressTest(
	PIRP				pIrp,
	PDEVICE_OBJECT		pDevObj);

static NTSTATUS MmAllocatePagesForMdlExTest(
	PIRP				pIrp,
	PDEVICE_OBJECT		pDevObj);

static NTSTATUS MmFreeMappingAddressTest(
	PIRP				pIrp,
	PDEVICE_OBJECT		pDevObj);

static NTSTATUS MmFreePagesFromMdlTest(
	PIRP				pIrp,
	PDEVICE_OBJECT		pDevObj);

static NTSTATUS MmMapLockedPagesSpecifyCacheTest(
	PIRP				pIrp,
	PDEVICE_OBJECT		pDevObj);

static NTSTATUS MmMapLockedPagesWithReservedMappingTest(
	PIRP				pIrp,
	PDEVICE_OBJECT		pDevObj);

static NTSTATUS MmProbeAndLockPagesTest(
	PIRP				pIrp,
	PDEVICE_OBJECT		pDevObj);

static NTSTATUS MmUnlockPagesTest(
	PIRP				pIrp,
	PDEVICE_OBJECT		pDevObj);

static NTSTATUS MmUnmapLockedPagesTest(
	PIRP				pIrp,
	PDEVICE_OBJECT		pDevObj);

static NTSTATUS MmUnmapReservedMappingTest(
	PIRP				pIrp,
	PDEVICE_OBJECT		pDevObj);

extern "C" {
static NTSTATUS	PageableFunction(
	 PIRP				pIrp,
	 PDEVICE_OBJECT		pDevObj);
}

static NTSTATUS UnlockPagFunTest(
	PIRP				pIrp,
	PDEVICE_OBJECT		pDevObj);



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

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n\n\n" DRV_NAME " - driver, compiled %s %s\n",__DATE__, __TIME__);


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


	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n" DRV_NAME " - driver successfully loaded.");

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

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n" DRV_NAME " - Driver unloaded");


	return;
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
	*ppDevExt = pDevExt;

	// Form the symbolic link name
	//
	RtlInitUnicodeString(&pDevExt->uSymName,
        DRV_SYM_LINK);
	status = 
		IoCreateSymbolicLink( &pDevExt->uSymName,
							  &uRecName );
	if (!NT_SUCCESS(status)) {

		IoDeleteDevice( pDevObj );
		return status;
	}

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n" DRV_NAME " - Device created");

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
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n" DRV_NAME " - Device deleted");
	} else {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n" DRV_NAME " - No devices to delete");
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

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n" DRV_NAME " - Device closed");


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

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n" DRV_NAME " - Device opened");

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
		case IOCTL_MEMTEST_ALLOCATEMDL:
			status = IoAllocateMdlTest(pIrp, pDevObj);
			break;
		case IOCTL_MEMTEST_ALLOCMAPADDR:
			status = MmAllocateMappingAddressTest(pIrp, pDevObj);
			break;
		case IOCTL_MEMTEST_ALLOCPAGESMDL:
			status = MmAllocatePagesForMdlExTest(pIrp, pDevObj);
			break;
		case IOCTL_MEMTEST_CALLPAGEABLE:
			status = PageableFunction(pIrp, pDevObj);
			break;
		case IOCTL_MEMTEST_FREEMAPADDR:
			status = MmFreeMappingAddressTest(pIrp, pDevObj);
			break;
		case IOCTL_MEMTEST_FREEMDL:
			status = IoFreeMdlTest(pIrp, pDevObj);
			break;
		case IOCTL_MEMTEST_FREEPAGESMDL:
			status = MmFreePagesFromMdlTest(pIrp, pDevObj);
			break;
		case IOCTL_MEMTEST_KMEMTOUCH:
			status = KmemTouchTest(pIrp, pDevObj);
			break;
		case IOCTL_MEMTEST_LOCKPAGEABLE:
			status = LockPagFunTest(pIrp, pDevObj);
			break;
		case IOCTL_MEMTEST_MAPLOCKPAGES:
			status = MmMapLockedPagesSpecifyCacheTest(pIrp, pDevObj);
			break;
		case IOCTL_MEMTEST_MAPLPAGESRESMAP:
			status = MmMapLockedPagesWithReservedMappingTest(pIrp, pDevObj);
			break;
		case IOCTL_MEMTEST_MDL_FOR_USER_BUFFER:
			status = MdlForUserBufferTest(pIrp, pDevObj);
			break;
		case IOCTL_MEMTEST_PROBEANDLOCK:
			status = MmProbeAndLockPagesTest(pIrp, pDevObj);
			break;
		case IOCTL_MEMTEST_UNLOCKPAGEABLE:
			status = UnlockPagFunTest(pIrp, pDevObj);
			break;
		case IOCTL_MEMTEST_UNLOCKPAGES:
			status = MmUnlockPagesTest(pIrp, pDevObj);
			break;
		case IOCTL_MEMTEST_UNMAPLOCKPAG:
			status = MmUnmapLockedPagesTest(pIrp, pDevObj);
			break;
		case IOCTL_MEMTEST_UNMAPRESMAP:
			status = MmUnmapReservedMappingTest(pIrp, pDevObj);
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
// Function:	IoAllocateMdlTest
//
//--
static NTSTATUS IoAllocateMdlTest(
	PIRP				pIrp,
	PDEVICE_OBJECT		pDevObj)
{
	NTSTATUS		Status = STATUS_UNSUCCESSFUL;

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n\n\n" DRV_NAME " - IoAllocateMdlTest\n");

	PIO_STACK_LOCATION pIrpStack = IoGetCurrentIrpStackLocation(pIrp);
	ULONG InputLen = pIrpStack->Parameters.DeviceIoControl.InputBufferLength;
	if (InputLen <
		sizeof KADRV_ALLOCMDL_INPUT) {

		Status = STATUS_INVALID_PARAMETER;
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, DRV_NAME " - Input data too short: %d\n",
			InputLen);
		goto CLEANUP;
	}
	PKADRV_ALLOCMDL_INPUT TstInput =
		(PKADRV_ALLOCMDL_INPUT) pIrp->AssociatedIrp.SystemBuffer;
	if (!TstInput->VirtualAddress) {

		Status = STATUS_INVALID_PARAMETER;
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, DRV_NAME " - TstInput->VirtualAddress = 0\n");
		goto CLEANUP;
	}
	if (!TstInput->Length) {

		Status = STATUS_INVALID_PARAMETER;
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, DRV_NAME " - TstInput->Length = 0\n");
		goto CLEANUP;
	}
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
		DRV_NAME " - About to allocate MDL\n");
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
		DRV_NAME "    VirtualAddress = 0x%16p\n", TstInput->VirtualAddress);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
		DRV_NAME "    Length         = 0x%8x\n", TstInput->Length);
	PMDL pMdl = IoAllocateMdl(
		TstInput->VirtualAddress,
		TstInput->Length,
		FALSE,
		FALSE,
		NULL );

	if (pMdl == NULL) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, DRV_NAME " - IoAllocateMdl returned NULL\n");
		goto CLEANUP;
	}
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, DRV_NAME " - Allocated MDL at %#p\n",
		pMdl);
	*((PMDL *) pIrp->AssociatedIrp.SystemBuffer) = pMdl;
	pIrp->IoStatus.Information = sizeof pMdl;
	Status = STATUS_SUCCESS;
CLEANUP:
	return Status;

}


//++
// Function:	IoFreeMdlTest
//
//--
static NTSTATUS IoFreeMdlTest(
	PIRP				pIrp,
	PDEVICE_OBJECT		pDevObj)
{
	NTSTATUS		Status = STATUS_UNSUCCESSFUL;

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n\n\n" DRV_NAME " - IoFreeMdlTest\n");

	PIO_STACK_LOCATION pIrpStack = IoGetCurrentIrpStackLocation(pIrp);
	ULONG InputLen = pIrpStack->Parameters.DeviceIoControl.InputBufferLength;
	if (InputLen <
		sizeof PVOID) {

		Status = STATUS_INVALID_PARAMETER;
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, DRV_NAME " - Input data too short: %d\n",
			InputLen);
		goto CLEANUP;
	}
	PMDL pMdl = *((PMDL *) pIrp->AssociatedIrp.SystemBuffer);
	if (!pMdl) {

		Status = STATUS_INVALID_PARAMETER;
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, DRV_NAME " - pMdl = 0\n");
		goto CLEANUP;
	}
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
		DRV_NAME " - About to free MDL\n");
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
		DRV_NAME "    Address = 0x%16p\n", pMdl);
	IoFreeMdl(pMdl);

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, DRV_NAME " - Freed MDL at %#p\n",
		pMdl);
	pIrp->IoStatus.Information = 0;
	Status = STATUS_SUCCESS;
CLEANUP:
	return Status;

}


//++
// Function:	KmemTouchTest
//
//--
static NTSTATUS KmemTouchTest(
	PIRP				pIrp,
	PDEVICE_OBJECT		pDevObj)
{
	NTSTATUS		Status = STATUS_UNSUCCESSFUL;

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n\n\n" DRV_NAME " - KmemTouchTest\n");

	PIO_STACK_LOCATION pIrpStack = IoGetCurrentIrpStackLocation(pIrp);
	ULONG InputLen = pIrpStack->Parameters.DeviceIoControl.InputBufferLength;
	if (InputLen <
		sizeof KADRV_KMEMTOUCH_INPUT) {

		Status = STATUS_INVALID_PARAMETER;
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, DRV_NAME " - Input data too short: %d\n",
			InputLen);
		goto CLEANUP;
	}
	PKADRV_KMEMTOUCH_INPUT TstInput =
		(PKADRV_KMEMTOUCH_INPUT) pIrp->AssociatedIrp.SystemBuffer;
	if (!TstInput->lpStart) {

		Status = STATUS_INVALID_PARAMETER;
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, DRV_NAME " - TstInput->lpStart = 0\n");
		goto CLEANUP;
	}
	if (!TstInput->cbLength) {

		Status = STATUS_INVALID_PARAMETER;
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, DRV_NAME " - TstInput->cbLength = 0\n");
		goto CLEANUP;
	}
	if ((TstInput->AccessType != ATRead) && (TstInput->AccessType != ATWrite)) {

		Status = STATUS_INVALID_PARAMETER;
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, DRV_NAME " - TstInput->AccessType invalid: %d\n",
			(ULONG) TstInput->AccessType );
		goto CLEANUP;
	}
	PVOID lpEnd = (PCHAR) TstInput->lpStart + TstInput->cbLength;
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
		DRV_NAME " - About to touch region 0x%16p - 0x%16p\n", TstInput->lpStart, lpEnd);

	PCHAR lpTouch = (PCHAR) TstInput->lpStart;
	__try {
		for (;lpTouch < (PCHAR) lpEnd; lpTouch += 0x1000) {
			if (TstInput->AccessType == ATRead) {
				gl_DummyByte = *lpTouch;
			} else {
				* ((PULONGLONG) lpTouch) = (ULONGLONG) lpTouch;
			}
		}
		Status = STATUS_SUCCESS;
	}
	__except(EXCEPTION_EXECUTE_HANDLER) {
		ULONG dwExc = GetExceptionCode();
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, DRV_NAME " - Exception while touching memory. Code = 0x%8x\n",
			dwExc);
	}
CLEANUP:
	return Status;

}


//++
// Function:	LockPagFunTest
//
//--
static NTSTATUS LockPagFunTest(
	PIRP				pIrp,
	PDEVICE_OBJECT		pDevObj)
{
	lpDrvLockHandle = MmLockPagableCodeSection(PageableFunction);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
		DRV_NAME " - PageableFunction locked. Handle = 0x%8p\n",
		lpDrvLockHandle);
	return STATUS_SUCCESS;

}


//++
// Function:	MdlForUserBufferTest
//
//--
static NTSTATUS MdlForUserBufferTest(
	PIRP			pIrp,
	PDEVICE_OBJECT	pDevObj)
{
	BOOLEAN		bPagesLocked = FALSE;
	PVOID		pMapping = NULL;
	PMDL		pMdl = NULL;
	NTSTATUS	Status = STATUS_SUCCESS;

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n\n\n" DRV_NAME " - MDL for User Buffer Test\n");

	PIO_STACK_LOCATION pIrpStack = IoGetCurrentIrpStackLocation(pIrp);
	ULONG InputLen = pIrpStack->Parameters.DeviceIoControl.InputBufferLength;
	if (InputLen <
		sizeof KADRV_MDLFORUSERBUFFER_INPUT) {

		Status = STATUS_INVALID_PARAMETER;
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, DRV_NAME " - Input data too short: %d",
			InputLen);
		goto CLEANUP;
	}
	PKADRV_MDLFORUSERBUFFER_INPUT TstInput =
		(PKADRV_MDLFORUSERBUFFER_INPUT) pIrp->AssociatedIrp.SystemBuffer;

	PVOID pBuffer = TstInput->pBuffer;
	if (!pBuffer) {
		Status = STATUS_INVALID_PARAMETER;
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, DRV_NAME " - buffer address = 0\n");
		goto CLEANUP;
	}
	if ((ULONGLONG) pBuffer > 0x80000000000) {
		Status = STATUS_INVALID_PARAMETER;
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, DRV_NAME " - buffer address not in user range: %#p\n",
			pBuffer);
		goto CLEANUP;
	}

	ULONG BufSize = TstInput->BufSize;
	if (!BufSize) {
		Status = STATUS_INVALID_PARAMETER;
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, DRV_NAME " - buffer size = 0\n");
		goto CLEANUP;
	}

	LOCK_OPERATION Operation;
	switch (TstInput->AccessType) {
		case ATWrite:
			Operation = IoWriteAccess;
			break;
		case ATRead:
			Operation = IoReadAccess;
			break;
		default:
			Status = STATUS_INVALID_PARAMETER;
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, DRV_NAME " - invalid access type: %d\n",
				TstInput->AccessType);
			goto CLEANUP;
	}

	KPROCESSOR_MODE AccessMode;
	switch(TstInput->AccessMode) {
		case AMKernel:
			AccessMode = KernelMode;
			break;
		case AMUser:
			AccessMode = UserMode;
			break;
		default:
			Status = STATUS_INVALID_PARAMETER;
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, DRV_NAME " - invalid access mode: %d\n",
				TstInput->AccessMode);
			goto CLEANUP;
	}
	
	MEMORY_CACHING_TYPE CacheType;
	switch (TstInput->CacheType) {
		case CTNonCached:
			CacheType = MmNonCached;
			break;
		case CTCached:
			CacheType = MmCached;
			break;
		case CTWriteCombined:
			CacheType = MmWriteCombined;
			break;
		default:
			Status = STATUS_INVALID_PARAMETER;
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, DRV_NAME " - invalid cache type: %d\n",
				TstInput->CacheType);
			goto CLEANUP;
	}

	__try {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, DRV_NAME " - about to probe user buffer\n");
		if (Operation == IoWriteAccess) {
			ProbeForWrite(
				pBuffer,
				BufSize,
				1);
		} else {
			ProbeForRead(
				pBuffer,
				BufSize,
				1);
		}
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, DRV_NAME " - user buffer probed\n");
		pMdl = IoAllocateMdl(
			pBuffer,
			BufSize,
			FALSE,
			FALSE,
			NULL);
		if (pMdl == NULL) {
			Status = STATUS_UNSUCCESSFUL;
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, DRV_NAME " - IoAllocateMdl() failed\n");
			__leave;
		}
		MmProbeAndLockPages(
			pMdl,
			AccessMode,
			Operation);
		bPagesLocked = TRUE;
		pMapping = MmMapLockedPagesSpecifyCache(
			pMdl,
			AccessMode,
			CacheType,
			NULL,
			FALSE,
			LowPagePriority);
		if (pMapping == NULL) {
			Status = STATUS_UNSUCCESSFUL;
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, DRV_NAME " - MmMapLockedPagesSpecifyCache() failed\n");
			__leave;
		}
		DbgBreakPoint();
	}
	__except(EXCEPTION_EXECUTE_HANDLER) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
			DRV_NAME " - Caught exception: 0x%8x\n", GetExceptionCode());
		Status = STATUS_UNSUCCESSFUL;
	}
CLEANUP:
	if (pMapping != NULL) MmUnmapLockedPages(pMapping, pMdl);
	if (bPagesLocked) MmUnlockPages(pMdl);
	if (pMdl != NULL) IoFreeMdl(pMdl);
	return Status;
}


//++
// Function:	MmAllocateMappingAddressTest
//
//--
static NTSTATUS MmAllocateMappingAddressTest(
	PIRP				pIrp,
	PDEVICE_OBJECT		pDevObj)
{
	NTSTATUS		Status = STATUS_UNSUCCESSFUL;

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n\n\n" DRV_NAME " - MmAllocateMappingAddressTest\n");

	PIO_STACK_LOCATION pIrpStack = IoGetCurrentIrpStackLocation(pIrp);
	ULONG InputLen = pIrpStack->Parameters.DeviceIoControl.InputBufferLength;
	if (InputLen <
		sizeof KADRV_ALLMAPADDR_INPUT) {

		Status = STATUS_INVALID_PARAMETER;
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, DRV_NAME " - Input data too short: %d\n",
			InputLen);
		goto CLEANUP;
	}
	PKADRV_ALLMAPADDR_INPUT TstInput =
		(PKADRV_ALLMAPADDR_INPUT) pIrp->AssociatedIrp.SystemBuffer;
	if (!TstInput->Size) {

		Status = STATUS_INVALID_PARAMETER;
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, DRV_NAME " - TstInput->Size = 0\n");
		goto CLEANUP;
	}
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
		DRV_NAME " - About to allocate mapping address\n");
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
		DRV_NAME "    Size = 0x%I64x\n", TstInput->Size);
	TstInput->Address = MmAllocateMappingAddress(
		TstInput->Size,
		*((ULONG *) MapRegionTag));

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, DRV_NAME " - Reserved region at %#p, size = %I64x\n",
		TstInput->Address, TstInput->Size);
	pIrp->IoStatus.Information = sizeof KADRV_ALLMAPADDR_INPUT;
	Status = STATUS_SUCCESS;
CLEANUP:
	return Status;

}


//++
// Function:	MmAllocatePagesForMdlExTest
//
//--
static NTSTATUS MmAllocatePagesForMdlExTest(
	PIRP				pIrp,
	PDEVICE_OBJECT		pDevObj)
{
	NTSTATUS		Status = STATUS_UNSUCCESSFUL;

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n\n\n" DRV_NAME " - MmAllocatePagesForMdlExTest\n");

	PIO_STACK_LOCATION pIrpStack = IoGetCurrentIrpStackLocation(pIrp);
	ULONG InputLen = pIrpStack->Parameters.DeviceIoControl.InputBufferLength;
	if (InputLen <
		sizeof KADRV_ALLPAGESFORMDL_INPUT) {

		Status = STATUS_INVALID_PARAMETER;
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, DRV_NAME " - Input data too short: %d\n",
			InputLen);
		goto CLEANUP;
	}
	PKADRV_ALLPAGESFORMDL_INPUT TstInput =
		(PKADRV_ALLPAGESFORMDL_INPUT) pIrp->AssociatedIrp.SystemBuffer;

	PHYSICAL_ADDRESS LowAddress;
	LowAddress.QuadPart = (LONGLONG) TstInput->LowAddress;

	if (!TstInput->HighAddress) {
		Status = STATUS_INVALID_PARAMETER;
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, DRV_NAME " - TstInput->HighAddress = 0\n");
		goto CLEANUP;
	}
	PHYSICAL_ADDRESS HighAddress;
	HighAddress.QuadPart = (LONGLONG) TstInput->HighAddress;

	if (!TstInput->SkipBytes) {
		Status = STATUS_INVALID_PARAMETER;
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, DRV_NAME " - TstInput->SkipBytes = 0\n");
		goto CLEANUP;
	}
	PHYSICAL_ADDRESS SkipBytes;
	SkipBytes.QuadPart = (LONGLONG) TstInput->SkipBytes;

	if (!TstInput->TotalBytes) {
		Status = STATUS_INVALID_PARAMETER;
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, DRV_NAME " - TstInput->TotalBytes = 0\n");
		goto CLEANUP;
	}
	MEMORY_CACHING_TYPE CacheType;
	switch(TstInput->CacheType) {
		case CTNonCached:
			CacheType = MmNonCached;
			break;
		case CTCached:
			CacheType = MmCached;
			break;
		case CTWriteCombined:
			CacheType = MmWriteCombined;
			break;
		default:
			Status = STATUS_INVALID_PARAMETER;
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, DRV_NAME " - TstInput->CacheType invalid: %d\n",
				TstInput->CacheType);
			goto CLEANUP;
	}
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
		DRV_NAME " - About to call MmAllocatePagesForMdlEx()\n");
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
		DRV_NAME "    LowAddress = 0x%I64x\n", LowAddress.QuadPart);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
		DRV_NAME "    HighAddress = 0x%I64x\n", HighAddress.QuadPart);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
		DRV_NAME "    SkipBytes = 0x%I64x\n", SkipBytes.QuadPart);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
		DRV_NAME "    TotalBytes = 0x%I64x\n", TstInput->TotalBytes);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
		DRV_NAME "    CacheType = %d\n", (ULONG) CacheType);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
		DRV_NAME "    Flags = 0x%x\n", TstInput->Flags);
	PMDL pMdl = MmAllocatePagesForMdlEx(
		LowAddress,
		HighAddress,
		SkipBytes,
		TstInput->TotalBytes,
		CacheType,
		TstInput->Flags);
	if (pMdl == NULL) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
			DRV_NAME "MmAllocatePagesForMdlEx() failed");
		goto CLEANUP;
	}
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
		DRV_NAME "MmAllocatePagesForMdlEx() allocated MDL at 0x%16p for %d bytes", 
		pMdl,
		MmGetMdlByteCount(pMdl));


	*((PMDL *) pIrp->AssociatedIrp.SystemBuffer) = pMdl;
	pIrp->IoStatus.Information = sizeof pMdl;

	Status = STATUS_SUCCESS;
CLEANUP:
	return Status;

}


//++
// Function:	MmFreeMappingAddressTest
//
//--
static NTSTATUS MmFreeMappingAddressTest(
	PIRP				pIrp,
	PDEVICE_OBJECT		pDevObj)
{
	NTSTATUS		Status = STATUS_UNSUCCESSFUL;

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n\n\n" DRV_NAME " - MmFreeMappingAddressTest\n");

	PIO_STACK_LOCATION pIrpStack = IoGetCurrentIrpStackLocation(pIrp);
	ULONG InputLen = pIrpStack->Parameters.DeviceIoControl.InputBufferLength;
	if (InputLen <
		sizeof PVOID) {

		Status = STATUS_INVALID_PARAMETER;
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, DRV_NAME " - Input data too short: %d\n",
			InputLen);
		goto CLEANUP;
	}
	PVOID pRegion = *((PVOID *) pIrp->AssociatedIrp.SystemBuffer);
	if (!pRegion) {

		Status = STATUS_INVALID_PARAMETER;
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, DRV_NAME " - pRegion = 0\n");
		goto CLEANUP;
	}
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
		DRV_NAME "About to free mapping address = 0x%16p\n", pRegion);
	MmFreeMappingAddress(pRegion, *((ULONG *) MapRegionTag));

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, DRV_NAME " - Freed region at %#p\n",
		pRegion);
	pIrp->IoStatus.Information = 0;
	Status = STATUS_SUCCESS;
CLEANUP:
	return Status;

}


//++
// Function:	MmFreePagesFromMdlTest
//
//--
static NTSTATUS MmFreePagesFromMdlTest(
	PIRP				pIrp,
	PDEVICE_OBJECT		pDevObj)
{
	NTSTATUS		Status = STATUS_UNSUCCESSFUL;

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n\n\n" DRV_NAME " - MmFreePagesFromMdlTest\n");

	PIO_STACK_LOCATION pIrpStack = IoGetCurrentIrpStackLocation(pIrp);
	ULONG InputLen = pIrpStack->Parameters.DeviceIoControl.InputBufferLength;
	if (InputLen <
		sizeof PVOID) {

		Status = STATUS_INVALID_PARAMETER;
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, DRV_NAME " - Input data too short: %d\n",
			InputLen);
		goto CLEANUP;
	}
	PMDL pMdl = *((PMDL *) pIrp->AssociatedIrp.SystemBuffer);
	if (!pMdl) {

		Status = STATUS_INVALID_PARAMETER;
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, DRV_NAME " - pMdl = 0\n");
		goto CLEANUP;
	}
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
		DRV_NAME " - About to free MDL pages\n");
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
		DRV_NAME "    Address = 0x%16p\n", pMdl);
	MmFreePagesFromMdl(pMdl);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, DRV_NAME " - Pages from MDL at 0x%16p released\n",
		pMdl);
	pIrp->IoStatus.Information = 0;
	Status = STATUS_SUCCESS;
CLEANUP:
	return Status;

}


//++
// Function:	MmMapLockedPagesSpecifyCacheTest
//
//--
static NTSTATUS MmMapLockedPagesSpecifyCacheTest(
	PIRP				pIrp,
	PDEVICE_OBJECT		pDevObj)
{
	NTSTATUS		Status = STATUS_UNSUCCESSFUL;

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n\n\n" DRV_NAME " - MmMapLockedPagesSpecifyCacheTest\n");

	PIO_STACK_LOCATION pIrpStack = IoGetCurrentIrpStackLocation(pIrp);
	ULONG InputLen = pIrpStack->Parameters.DeviceIoControl.InputBufferLength;
	if (InputLen <
		sizeof KADRV_MAPLOCKPAGES_INPUT) {

		Status = STATUS_INVALID_PARAMETER;
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, DRV_NAME " - Input data too short: %d\n",
			InputLen);
		goto CLEANUP;
	}
	PKADRV_MAPLOCKPAGES_INPUT TstInput =
		(PKADRV_MAPLOCKPAGES_INPUT) pIrp->AssociatedIrp.SystemBuffer;
	if (!TstInput->pMdl) {
		Status = STATUS_INVALID_PARAMETER;
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, DRV_NAME " - TstInput->pMdl = 0\n");
		goto CLEANUP;
	}
	MEMORY_CACHING_TYPE CacheType;
	switch(TstInput->CacheType) {
		case CTNonCached:
			CacheType = MmNonCached;
			break;
		case CTCached:
			CacheType = MmCached;
			break;
		case CTWriteCombined:
			CacheType = MmWriteCombined;
			break;
		default:
			Status = STATUS_INVALID_PARAMETER;
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, DRV_NAME " - TstInput->CacheType invalid: %d\n",
				TstInput->CacheType);
			goto CLEANUP;
	}

	KPROCESSOR_MODE AccessMode;
	switch(TstInput->AccessMode) {
		case AMKernel:
			AccessMode = KernelMode;
			break;
		case AMUser:
			AccessMode = UserMode;
			break;
		default:
			Status = STATUS_INVALID_PARAMETER;
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, DRV_NAME " - invalid access mode: %d\n",
				TstInput->AccessMode);
			goto CLEANUP;
	}
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
		DRV_NAME " - About to call MmMapLockedPagesSpecifyCache()\n");
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
		DRV_NAME "    MemoryDescriptorList = 0x%16p\n", TstInput->pMdl);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
		DRV_NAME "    AccessMode           = 0x%d\n", AccessMode);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
		DRV_NAME "    CacheType            = 0x%d\n", CacheType);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
		DRV_NAME "    BaseAddress          = 0x%16p\n", TstInput->pBaseAddress);
	PVOID pMappedRegion = MmMapLockedPagesSpecifyCache(
		(PMDLX) TstInput->pMdl,
		AccessMode,
		CacheType,
		TstInput->pBaseAddress,
		FALSE,
		LowPagePriority);
	if (pMappedRegion == NULL) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
			DRV_NAME "MmMapLockedPagesSpecifyCache() failed");
		goto CLEANUP;
	}
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
		DRV_NAME " - Mapped region at 0x%16p", 
		pMappedRegion);
	*((PVOID *) pIrp->AssociatedIrp.SystemBuffer) = pMappedRegion;
	pIrp->IoStatus.Information = sizeof pMappedRegion;

	Status = STATUS_SUCCESS;
CLEANUP:
	return Status;

}


//++
// Function:	MmAllocatePagesForMdlExTest
//
//--
static NTSTATUS MmMapLockedPagesWithReservedMappingTest(
	PIRP				pIrp,
	PDEVICE_OBJECT		pDevObj)
{
	NTSTATUS		Status = STATUS_UNSUCCESSFUL;

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n\n\n" DRV_NAME " - MmMapLockedPagesWithReservedMappingTest\n");

	PIO_STACK_LOCATION pIrpStack = IoGetCurrentIrpStackLocation(pIrp);
	ULONG InputLen = pIrpStack->Parameters.DeviceIoControl.InputBufferLength;
	if (InputLen <
		sizeof KADRV_MAPLPAGESRESMAP_INPUT) {

		Status = STATUS_INVALID_PARAMETER;
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, DRV_NAME " - Input data too short: %d\n",
			InputLen);
		goto CLEANUP;
	}
	PKADRV_MAPLPAGESRESMAP_INPUT TstInput =
		(PKADRV_MAPLPAGESRESMAP_INPUT) pIrp->AssociatedIrp.SystemBuffer;
	if (!TstInput->MappingAddress) {
		Status = STATUS_INVALID_PARAMETER;
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, DRV_NAME " - TstInput->MappingAddress = 0\n");
		goto CLEANUP;
	}
	if (!TstInput->pMdl) {
		Status = STATUS_INVALID_PARAMETER;
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, DRV_NAME " - TstInput->pMdl = 0\n");
		goto CLEANUP;
	}
	MEMORY_CACHING_TYPE CacheType;
	switch(TstInput->CacheType) {
		case CTNonCached:
			CacheType = MmNonCached;
			break;
		case CTCached:
			CacheType = MmCached;
			break;
		case CTWriteCombined:
			CacheType = MmWriteCombined;
			break;
		default:
			Status = STATUS_INVALID_PARAMETER;
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, DRV_NAME " - TstInput->CacheType invalid: %d\n",
				TstInput->CacheType);
			goto CLEANUP;
	}
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
		DRV_NAME " - About to call MmMapLockedPAgesWithReservedMapping()\n");
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
		DRV_NAME "    MappingAddress       = 0x%16p\n", TstInput->MappingAddress);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
		DRV_NAME "    MemoryDescriptorList = 0x%16p\n", TstInput->pMdl);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
		DRV_NAME "    CacheType            = 0x%d\n", CacheType);
	PVOID pMappedRegion = MmMapLockedPagesWithReservedMapping(
		TstInput->MappingAddress,
		*((ULONG *) MapRegionTag),
		(PMDLX) TstInput->pMdl,
		CacheType );
	if (pMappedRegion == NULL) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
			DRV_NAME "MmMapLockedPagesWithReservedMapping() failed");
		goto CLEANUP;
	}
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
		DRV_NAME " - Mapped region at 0x%16p", 
		pMappedRegion);
	*((PVOID *) pIrp->AssociatedIrp.SystemBuffer) = pMappedRegion;
	pIrp->IoStatus.Information = sizeof pMappedRegion;

	Status = STATUS_SUCCESS;
CLEANUP:
	return Status;

}





//++
// Function:	MmProbeAndLockPagesTest
//
//--
static NTSTATUS MmProbeAndLockPagesTest(
	PIRP				pIrp,
	PDEVICE_OBJECT		pDevObj)
{
	NTSTATUS		Status = STATUS_UNSUCCESSFUL;

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n\n\n" DRV_NAME " - MmProbeAndLockPagesTest\n");

	pIrp->IoStatus.Information = 0;
	PIO_STACK_LOCATION pIrpStack = IoGetCurrentIrpStackLocation(pIrp);
	ULONG InputLen = pIrpStack->Parameters.DeviceIoControl.InputBufferLength;
	if (InputLen <
		sizeof KADRV_PROBEANDLOCK_INPUT) {

		Status = STATUS_INVALID_PARAMETER;
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, DRV_NAME " - Input data too short: %d\n",
			InputLen);
		goto CLEANUP;
	}
	PKADRV_PROBEANDLOCK_INPUT pProbeAndLockIn = (PKADRV_PROBEANDLOCK_INPUT) pIrp->AssociatedIrp.SystemBuffer;
	if (!pProbeAndLockIn->pMdl) {
		Status = STATUS_INVALID_PARAMETER;
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, DRV_NAME " - pProbeAndLockIn->pMdl = 0\n");
		goto CLEANUP;
	}

	KPROCESSOR_MODE AccessMode;
	switch(pProbeAndLockIn->AccessMode) {
		case AMKernel:
			AccessMode = KernelMode;
			break;
		case AMUser:
			AccessMode = UserMode;
			break;
		default:
			Status = STATUS_INVALID_PARAMETER;
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, DRV_NAME " - pProbeAndLockIn->AccessMode invalid : %d\n",
				(ULONG) pProbeAndLockIn->AccessMode);
			goto CLEANUP;
	}

	LOCK_OPERATION Operation;
	switch(pProbeAndLockIn->Operation) {
		case ATRead:
			Operation = IoReadAccess;
			break;
		case ATWrite:
			Operation = IoWriteAccess;
			break;
		default:
			Status = STATUS_INVALID_PARAMETER;
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, DRV_NAME " - pProbeAndLockIn->Operation invalid : %d\n",
				(ULONG) pProbeAndLockIn->Operation);
			goto CLEANUP;
	}

	__try {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
			DRV_NAME "About to probe and lock MDL pages\n");
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
			DRV_NAME "    Mdl address = 0x%16p\n", pProbeAndLockIn->pMdl);
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
			DRV_NAME "    Access mode = %d\n", AccessMode);
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
			DRV_NAME "    Operation   = %d\n", Operation);
		MmProbeAndLockPages(
			(PMDLX) pProbeAndLockIn->pMdl,
			AccessMode,
			Operation);
	}
	__except(EXCEPTION_EXECUTE_HANDLER) {
		ULONG dwExc = GetExceptionCode();
		Status = STATUS_UNSUCCESSFUL;
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, DRV_NAME " - MmProbeAndLockPages() raised exception 0x%8x\n",
			dwExc);
		goto CLEANUP;
	}

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, DRV_NAME " - Probed and locked MDL at %#p\n",
		pProbeAndLockIn->pMdl);

	Status = STATUS_SUCCESS;
CLEANUP:
	return Status;

}


//++
// Function:	MmUnlockPagesTest
//
//--
static NTSTATUS MmUnlockPagesTest(
	PIRP				pIrp,
	PDEVICE_OBJECT		pDevObj)
{
	NTSTATUS		Status = STATUS_UNSUCCESSFUL;

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n\n\n" DRV_NAME " - MmUnlockPagesTest\n");

	PIO_STACK_LOCATION pIrpStack = IoGetCurrentIrpStackLocation(pIrp);
	ULONG InputLen = pIrpStack->Parameters.DeviceIoControl.InputBufferLength;
	if (InputLen <
		sizeof PVOID) {

		Status = STATUS_INVALID_PARAMETER;
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, DRV_NAME " - Input data too short: %d\n",
			InputLen);
		goto CLEANUP;
	}
	PMDLX pMdl = *((PMDLX *) pIrp->AssociatedIrp.SystemBuffer);
	if (!pMdl) {
		Status = STATUS_INVALID_PARAMETER;
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, DRV_NAME " - pMdl = 0\n");
		goto CLEANUP;
	}
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
		DRV_NAME " - About to unlock MDL pages\n");
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
		DRV_NAME "    Mdl address = 0x%16p\n", pMdl);
	MmUnlockPages(pMdl);

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, DRV_NAME " - Unlocked MDL at %#p\n",
		pMdl);

	Status = STATUS_SUCCESS;
CLEANUP:
	return Status;

}


//++
// Function:	MmUnmapLockedPagesTest
//
//--
static NTSTATUS MmUnmapLockedPagesTest(
	PIRP				pIrp,
	PDEVICE_OBJECT		pDevObj)
{
	NTSTATUS		Status = STATUS_UNSUCCESSFUL;

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n\n\n" DRV_NAME " - MmUnmapLockedPagesTest\n");

	PIO_STACK_LOCATION pIrpStack = IoGetCurrentIrpStackLocation(pIrp);
	ULONG InputLen = pIrpStack->Parameters.DeviceIoControl.InputBufferLength;
	if (InputLen <
		sizeof KADRV_UNMAPLOCKPAG_INPUT) {

		Status = STATUS_INVALID_PARAMETER;
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, DRV_NAME " - Input data too short: %d\n",
			InputLen);
		goto CLEANUP;
	}
	PKADRV_UNMAPLOCKPAG_INPUT TstInput =
		(PKADRV_UNMAPLOCKPAG_INPUT) pIrp->AssociatedIrp.SystemBuffer;
	if (!TstInput->BaseAddress) {
		Status = STATUS_INVALID_PARAMETER;
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, DRV_NAME " - TstInput->BaseAddress = 0\n");
		goto CLEANUP;
	}
	if (!TstInput->pMdl) {
		Status = STATUS_INVALID_PARAMETER;
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, DRV_NAME " - TstInput->pMdl = 0\n");
		goto CLEANUP;
	}
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
		DRV_NAME " - About to call MmUnmapLockedPages()\n");
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
		DRV_NAME "    BaseAddress          = 0x%16p\n", TstInput->BaseAddress);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
		DRV_NAME "    MemoryDescriptorList = 0x%16p\n", TstInput->pMdl);
	MmUnmapLockedPages(
		TstInput->BaseAddress,
		(PMDL) TstInput->pMdl);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
		DRV_NAME " - Unmapped region at 0x%16p", 
		TstInput->BaseAddress);

	Status = STATUS_SUCCESS;
CLEANUP:
	return Status;

}


//++
// Function:	MmUnmapReservedMappingTest
//
//--
static NTSTATUS MmUnmapReservedMappingTest(
	PIRP				pIrp,
	PDEVICE_OBJECT		pDevObj)
{
	NTSTATUS		Status = STATUS_UNSUCCESSFUL;

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n\n\n" DRV_NAME " - MmUnmapReservedMappingTest\n");

	PIO_STACK_LOCATION pIrpStack = IoGetCurrentIrpStackLocation(pIrp);
	ULONG InputLen = pIrpStack->Parameters.DeviceIoControl.InputBufferLength;
	if (InputLen <
		sizeof KADRV_UNMAPRESMAP_INPUT) {

		Status = STATUS_INVALID_PARAMETER;
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, DRV_NAME " - Input data too short: %d\n",
			InputLen);
		goto CLEANUP;
	}
	PKADRV_UNMAPRESMAP_INPUT TstInput =
		(PKADRV_UNMAPRESMAP_INPUT) pIrp->AssociatedIrp.SystemBuffer;
	if (!TstInput->BaseAddress) {
		Status = STATUS_INVALID_PARAMETER;
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, DRV_NAME " - TstInput->BaseAddress = 0\n");
		goto CLEANUP;
	}
	if (!TstInput->pMdl) {
		Status = STATUS_INVALID_PARAMETER;
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, DRV_NAME " - TstInput->pMdl = 0\n");
		goto CLEANUP;
	}
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
		DRV_NAME " - About to call MmUnmapReservedMapping()\n");
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
		DRV_NAME "    BaseAddress          = 0x%16p\n", TstInput->BaseAddress);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
		DRV_NAME "    MemoryDescriptorList = 0x%16p\n", TstInput->pMdl);
	MmUnmapReservedMapping(
		TstInput->BaseAddress,
		*((ULONG *) MapRegionTag),
		(PMDLX) TstInput->pMdl);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
		DRV_NAME " - Unmapped region at 0x%16p", 
		TstInput->BaseAddress);

	Status = STATUS_SUCCESS;
CLEANUP:
	return Status;

}


//++
// Function:	PageableFunction
//
//--
#pragma alloc_text("PAGEme", PageableFunction)
extern "C" {
static NTSTATUS	PageableFunction(
	 PIRP				pIrp,
	 PDEVICE_OBJECT		pDevObj)
{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
			DRV_NAME " - PageableFunction called\n");

		return STATUS_SUCCESS;
}

}


//++
// Function:	UnlockPagFunTest
//
//--
static NTSTATUS UnlockPagFunTest(
	PIRP				pIrp,
	PDEVICE_OBJECT		pDevObj)
{
	MmUnlockPagableImageSection(lpDrvLockHandle);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
		DRV_NAME " - PageableFunction unlocked.\n");
	return STATUS_SUCCESS;

}


