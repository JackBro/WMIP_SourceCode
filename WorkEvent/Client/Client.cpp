/*

=======================================================================

WrkEvClient
===========

Companion test program to What Makes It Page?

Copyright (c), 2012 by Enrico Martignetti - All rights reserved.

Minimal client fot the work event driver.

Controls the device through its I/O control codes.

=======================================================================


*/

#include <windows.h>
#include <stdio.h>
#include <tchar.h>

#include <CodeAnalysis/warnings.h>

#pragma warning(push)

#pragma warning(disable: ALL_CODE_ANALYSIS_WARNINGS)

#include <strsafe.h>

#pragma warning(pop)

#include "DrvR3.h"

// Function codes
//
#define CLTFUN_CLEAR_EVENT				L'c'
#define CLTFUN_PRINT_ADDRESSES			L'p'
#define CLTFUN_QUIT						L'q'
#define CLTFUN_SIGNAL_EVENT				L's'
#define CLTFUN_SIGNAL_GATE				L't'

#define DRIVER_NAME			L"WrkEvent.sys"
#define DRV_SVC_NAME		L"WrkEvent"

static BOOL CheckParams(
	INT		ArgC,
	LPWSTR	lpwszArgV[]);

static INT ClearEvent();

static BOOL LoadDriver();

static HANDLE OpenWeDevice();

static VOID PrintFunctions();

static INT PrintObjAddresses();

static BOOL SendIoCtl(
	HANDLE		hDevice, 
	INT			code,
	LPVOID		lpInBuffer,
	INT			inBufSize,
	LPVOID		lpOutBuffer,
	INT			outBufSize );


static INT SignalEvent();

static INT SignalGate();

static BOOL UnloadDriver();


int wmain(/* int argC, wchar_t *lpwszArgV[] */) {
	wprintf(L"\nWrkEvent client, compiled %S %S\n\n",__DATE__, __TIME__);

	BOOL	bEndLoop = FALSE;
	DWORD	dwLastErr = ERROR_SUCCESS;
	WCHAR	Function;

	wprintf(
		L"\n\nCAUTION!!!\n");
	wprintf(
		L"\nThis program is about to load the WrkEvent.sys driver, which works ONLY");
	wprintf(
		L"\non Windows 7 x64 RTM (pre-SP1).");
	wprintf(
		L"\n\nThis driver WILL CRASH THE SYSTEM on any other version of Windows.");
	do {
		wprintf(L"\n\nContinue (y/n)?");
		Function = _getwch();
		wprintf(L"%c", Function);
		if (Function == 'y') break;
		if (Function == 'n') return ERROR_CANCELLED;
		wprintf(L"\nInvalid key: %c", Function);
	} while ((Function != 'y') && (Function != 'n'));

	wprintf(L"\nLoading the driver...");
	if (!LoadDriver()) {
		dwLastErr = GetLastError();
		wprintf(L"\nDriver load failed, attempting cleanup...");
		if (!UnloadDriver()) {
			wprintf(L"\nCleanup failed");
		} else {
			wprintf(L"\nCleanup succeeded");
		}
		return dwLastErr;
	}
	wprintf(L"\nDriver load succeeded");
	do {
		PrintFunctions();
		Function = _getwch();
		switch (Function) {
			case CLTFUN_CLEAR_EVENT:
				ClearEvent();
				break;
			case CLTFUN_PRINT_ADDRESSES:
				PrintObjAddresses();
				break;
			case CLTFUN_SIGNAL_EVENT:
				SignalEvent();
				break;
			case CLTFUN_SIGNAL_GATE:
				SignalGate();
				break;
			case CLTFUN_QUIT:
				bEndLoop = TRUE;
				break;
			default:
				wprintf(L"\nInvalid command: %c", Function);
		}
	} while (!bEndLoop);
	wprintf(L"\nUnloading the driver...");
	if (!UnloadDriver()) return GetLastError();
	wprintf(L"\nDriver unload succeeded");
	return ERROR_SUCCESS;

}





//++
//--
static INT ClearEvent()
{
	DWORD	dwLastErr;
	HANDLE	hWeDevice = INVALID_HANDLE_VALUE;

	UINT Index;
	wprintf(L"\nEnter event index: ");
	if (!wscanf_s(L"%u", &Index)) {
		wprintf(L"\nInvalid index");
		
		// drain the standard input
		while(getwc(stdin) != L'\n'){}
		return ERROR_INVALID_PARAMETER;
	}
	wprintf(L"\nClearing event %d", Index);
	hWeDevice = OpenWeDevice();
	if (hWeDevice == INVALID_HANDLE_VALUE)
		return GetLastError();
	if (!SendIoCtl(
		hWeDevice,
		IOCTL_WRKEVENT_CLEAR_EVENT,
		&Index,
		sizeof Index,
		NULL,
		0)) {
		dwLastErr = GetLastError();
		goto CLEANUP;
	}
	wprintf(L"\nEvent cleared");
	dwLastErr = ERROR_SUCCESS;
CLEANUP:
	if (hWeDevice != INVALID_HANDLE_VALUE) CloseHandle(hWeDevice);
	return dwLastErr;
}

//++
// This function is based on the code of w2k_lib.dll written by
// Sven Schreiber and published on the companion CD to
// Undocumented Windows 2000 Secrets.
//--
static BOOL LoadDriver()
{
	BOOL			bRet = TRUE;
	DWORD			dwLastErr = ERROR_SUCCESS;
	SC_HANDLE		hManager = NULL;
	SC_HANDLE		hService = NULL;
	WCHAR			wszDrvPathName[MAX_PATH];



	hManager = OpenSCManager(
		NULL,
		SERVICES_ACTIVE_DATABASE,
		SC_MANAGER_ALL_ACCESS);
	if (hManager == NULL) {
		dwLastErr = GetLastError();
		wprintf(L"\nOpenSCManager() failed with GetLastError() = %d", 
			dwLastErr);
		bRet = FALSE;
		goto CLEANUP;
	}

	DWORD dwBufLen = sizeof wszDrvPathName / sizeof WCHAR;
	DWORD dwNameLen = GetFullPathName(
		DRIVER_NAME,
		dwBufLen,
		wszDrvPathName,
		NULL);
	if (!dwNameLen) {
		dwLastErr = GetLastError();
		wprintf(L"\nGetFullPathName() failed with GetLastError() = %d",
			dwLastErr);
		bRet = FALSE;
		goto CLEANUP;
	}
	if (dwNameLen > dwBufLen) {
		wprintf(L"\nInsufficent pathname buffer");
		SetLastError(ERROR_INVALID_PARAMETER);
		bRet = FALSE;
		goto CLEANUP;
	}
	
	hService = CreateService(
		hManager,
		DRV_SVC_NAME,
		DRV_SVC_NAME,
		SERVICE_ALL_ACCESS,
		SERVICE_KERNEL_DRIVER,
		SERVICE_DEMAND_START,
		SERVICE_ERROR_NORMAL,
		wszDrvPathName,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL);
	if (hService == NULL) {
		dwLastErr = GetLastError();
		if (dwLastErr == ERROR_SERVICE_EXISTS) {

			// This usually happen if the system crashed with the driver
			// loaded. We can try to open the existing service.
			//
			dwLastErr = ERROR_SUCCESS;
			hService = OpenService(
				hManager,
				DRV_SVC_NAME,
				SERVICE_ALL_ACCESS);
			if (hService == NULL) {
				dwLastErr = GetLastError();
				bRet = FALSE;
				wprintf(L"\nOpenService() failed with GetLastError() = %d",
					dwLastErr);
				goto CLEANUP;
			}
		} else {
			bRet = FALSE;
			wprintf(L"\nCreateService() failed with GetLastError() = %d",
				dwLastErr);
			goto CLEANUP;
		}
	}




	if (!StartService(
		hService,
		0,
		NULL )) {
		dwLastErr = GetLastError();
		wprintf(L"\nStartService() failed with GetLastError() = %d",
			dwLastErr);
		bRet = FALSE;
		goto CLEANUP;
	}
	bRet = TRUE;
	dwLastErr = ERROR_SUCCESS;

CLEANUP:
	if (hManager != NULL) CloseServiceHandle(hManager);
	if (hService != NULL) CloseServiceHandle(hService);
	SetLastError(dwLastErr);
	return bRet;

}


//++
//--
static HANDLE OpenWeDevice()
{
	DWORD		dwLastErr;
	HANDLE		hDevice;
	WCHAR		wszDevPath[MAX_PATH];

	HRESULT res = StringCbPrintfW(
		wszDevPath,
		sizeof wszDevPath,
		L"\\\\.\\%s",
		DRV_DEVICE_NAME);
	if (!SUCCEEDED(res)) {
		wprintf(L"\nOpenWeDevice - StringCbPrintfW() returned %#x", res);
		SetLastError(ERROR_NOT_ENOUGH_MEMORY); // When in doubt, blame it on the memory
		return INVALID_HANDLE_VALUE;
	}

    hDevice = 
        CreateFile( wszDevPath,
					GENERIC_READ | GENERIC_WRITE,
					FILE_SHARE_READ | FILE_SHARE_WRITE,
					NULL,	// no security
					OPEN_EXISTING,
					FILE_ATTRIBUTE_NORMAL,
					NULL );		// no template
	if (hDevice == INVALID_HANDLE_VALUE) {
		dwLastErr = GetLastError();
		wprintf(L"\nCreateFile() for device %s failed. GetLastError() = 0x%8x", wszDevPath, dwLastErr);
		SetLastError(dwLastErr);
		return INVALID_HANDLE_VALUE;
	}
	return hDevice;
}


//++
//--
static VOID PrintFunctions() 
{
	wprintf(L"\n\n");
	wprintf(L"\n%c - Print objects addresses", CLTFUN_PRINT_ADDRESSES);
	wprintf(L"\n%c - Set event", CLTFUN_SIGNAL_EVENT);
	wprintf(L"\n%c - Clear event", CLTFUN_CLEAR_EVENT);
	wprintf(L"\n%c - Signal gate", CLTFUN_SIGNAL_GATE);
	wprintf(L"\n%c - Quit", CLTFUN_QUIT);
	wprintf(L"\n\n");
}


//++
//--
static INT PrintObjAddresses()
{
	DWORD		dwLastErr;
	HANDLE		hWeDevice = INVALID_HANDLE_VALUE;

	hWeDevice = OpenWeDevice();
	if (hWeDevice == INVALID_HANDLE_VALUE)
		return GetLastError();
	if (!SendIoCtl(
		hWeDevice,
		IOCTL_WRKEVENT_PRINT_OBJ_ADDRS,
		NULL,
		0,
		NULL,
		0)) {
		dwLastErr = GetLastError();
		goto CLEANUP;
	}
	wprintf(L"\nAddresses printed to the debugger console");
	dwLastErr = ERROR_SUCCESS;

CLEANUP:
	if (hWeDevice != INVALID_HANDLE_VALUE) CloseHandle(hWeDevice);
	return dwLastErr;
}


//++
//--
static BOOL SendIoCtl(
	HANDLE		hDevice, 
	INT			code,
	LPVOID		lpInBuffer,
	INT			inBufSize,
	LPVOID		lpOutBuffer,
	INT			outBufSize )
{
	BOOL	bResult;
	DWORD	dwBytesRet;
	DWORD	dwLastErr;

	bResult = DeviceIoControl(
		hDevice,
		code,
		lpInBuffer,
		inBufSize,
		lpOutBuffer,
		outBufSize,
		&dwBytesRet,
		NULL);

	if (!bResult) {
		dwLastErr = GetLastError();
		wprintf( L"\nFailed to send IOCTL. Code: 0x%8x, GetLastError() = 0x%8x",
			code,
			dwLastErr);
		SetLastError(dwLastErr);
		return FALSE;
	}

	return bResult;
}



//++
//--
static INT SignalEvent()
{
	DWORD	dwLastErr;
	HANDLE	hWeDevice = INVALID_HANDLE_VALUE;

	UINT Index = 0;
	wprintf(L"\nEnter event index: ");
	if (!wscanf_s(L"%u", &Index)) {
		wprintf(L"\nInvalid index");
		
		// drain the standard input
		while(getwc(stdin) != L'\n'){}
		return ERROR_INVALID_PARAMETER;
	}
	wprintf(L"\nSignaling event %d", Index);
	hWeDevice = OpenWeDevice();
	if (hWeDevice == INVALID_HANDLE_VALUE) {
		dwLastErr = GetLastError();
		wprintf(L"\nSignalEvent(): device open failed");
		return dwLastErr;
	}
	if (!SendIoCtl(
		hWeDevice,
		IOCTL_WRKEVENT_SIGNAL_EVENT,
		&Index,
		sizeof Index,
		NULL,
		0)) {
		dwLastErr = GetLastError();
		wprintf(L"\nSignalEvent(): device ioctl failed");
		goto CLEANUP;
	}
	wprintf(L"\nEvent signaled");
	dwLastErr = ERROR_SUCCESS;

CLEANUP:
	if (hWeDevice != INVALID_HANDLE_VALUE) CloseHandle(hWeDevice);
	return dwLastErr;
}


//++
//--
static INT SignalGate()
{
	DWORD	dwLastErr;
	HANDLE	hWeDevice = INVALID_HANDLE_VALUE;

	wprintf(L"\nSignaling the gate");
	hWeDevice = OpenWeDevice();
	if (hWeDevice == INVALID_HANDLE_VALUE) {
		dwLastErr = GetLastError();
		wprintf(L"\nSignalGate(): device open failed");
		return dwLastErr;
	}
	if (!SendIoCtl(
		hWeDevice,
		IOCTL_WRKEVENT_SIGNAL_GATE,
		NULL,
		0,
		NULL,
		0)) {
		dwLastErr = GetLastError();
		wprintf(L"\nSignalGate(): device ioctl failed");
		goto CLEANUP;
	}
	wprintf(L"\nGate signaled");
	dwLastErr = ERROR_SUCCESS;

CLEANUP:
	if (hWeDevice != INVALID_HANDLE_VALUE) CloseHandle(hWeDevice);
	return dwLastErr;
}


//++
//--
static BOOL UnloadDriver()
{
	BOOL			bRet = TRUE;
	DWORD			dwLastErr = ERROR_SUCCESS;
	SC_HANDLE		hManager = NULL;
	SC_HANDLE		hService = NULL;
	SERVICE_STATUS	SrvStatus;

	ZeroMemory(&SrvStatus, sizeof SrvStatus);
	hManager = OpenSCManager(
		NULL,
		SERVICES_ACTIVE_DATABASE,
		SC_MANAGER_ALL_ACCESS);
	if (hManager == NULL) {
		dwLastErr = GetLastError();
		wprintf(L"\nOpenSCManager() failed with GetLastError() = %d", 
			dwLastErr);
		bRet = FALSE;
		goto CLEANUP;
	}
	hService = OpenService(
		hManager,
		DRV_SVC_NAME,
		SERVICE_ALL_ACCESS);
	if (hService == NULL) {
		dwLastErr = GetLastError();
		wprintf(L"\nOpenService() failed with GetLastError() = %d",
			dwLastErr);
		bRet = FALSE;
		goto CLEANUP;
	}
	if (!ControlService(
		hService,
		SERVICE_CONTROL_STOP,
		&SrvStatus)) {

		// Print the error code but don't abort.
		//
		dwLastErr = GetLastError();
		wprintf(L"\nControlService() failed with GetLastError() =%d. Attempting to delete the service anyway",
			dwLastErr);
		dwLastErr = ERROR_SUCCESS;
	}
	if (!DeleteService(hService)) {
		dwLastErr = GetLastError();
		if (dwLastErr == ERROR_SERVICE_MARKED_FOR_DELETE) {
			wprintf(L"\nDeleteService() failed with GetLastError() = ERROR_SERVICE_MARKED_FOR_DELETE");

			// Go on and return success

		} else {
			wprintf(L"\nDeleteService() failed with GetLastError() = %d",
				dwLastErr);
			bRet = FALSE;
			goto CLEANUP;
		}
	}
	bRet = TRUE;
	dwLastErr = ERROR_SUCCESS;

CLEANUP:
	if (hService != NULL) CloseServiceHandle(hService);
	if (hManager != NULL) CloseServiceHandle(hManager);
	SetLastError(dwLastErr);
	return bRet;

}