/*

=======================================================================

MemTests
========

Companion test program to What Makes It Page?

Copyright (c), 2012 by Enrico Martignetti - All rights reserved.

=======================================================================


*/
#include <windows.h>
#include <Ntsecapi.h>

#include <stdio.h>
#include <wchar.h>
#include <conio.h>

#include <CodeAnalysis/warnings.h>

#pragma warning(push)
#pragma warning(disable: ALL_CODE_ANALYSIS_WARNINGS)

#include <strsafe.h>

#pragma warning(pop)

#include "KaDrvR3.h"

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS  ((NTSTATUS)0x00000000L)
#endif


#define PGM_NAME			L"MemTests"
#define VER_MAJ				L"1"
#define VER_MIN				L"0"



#define PDE_RANGE_START		0xFFFFF6FB40000000
#define PDPTE_RANGE_START	0xFFFFF6FB7DA00000
#define PTE_RANGE_START		0xFFFFF68000000000



#define BYTE_PTR_SHIFT(lpByte, Shift)		((PBYTE) ((DWORD_PTR) lpByte >> Shift))

// Shift: 27 for PDPTE, 18 for PD, 9 for PT
// Range: PxE range start
#define VA_TO_PS_ADDR(lpVa, Shift, Range)			(((lpVa >> Shift) + Range) & 0xfffffffffffffff8);

BOOL			bExit;
BYTE			dummyByte;
SIZE_T			dwSize;
KADRV_ALLMAPADDR_INPUT gl_AllMapIn;
BOOL			gl_bMdlLocked;
PVOID			gl_lpMappedSystemRegion;

// Address within the range described by gl_AllMapin, at which
// pages are mapped by MmMapLockedPagesWithReservedMapping
//
PVOID			gl_lpResMappedRegion;
PVOID			gl_pMdl;
HANDLE			hFileGlob;
HANDLE			hFileMapping;
PVOID			lpMappedRegionStart;
PVOID			lpMappedRegionEnd;
PVOID			lpPrivateRegionStart;
PVOID			lpPrivateRegionEnd;
PWCHAR			lpwszFileNameGlob;
PWCHAR			lpwszMapNameGlob;
WCHAR			wchOption;
WCHAR			wszFileNameGlob[MAX_PATH];
WCHAR			wszMappingName[501];


static BOOL AccessRegion(
	PVOID		lpRegionStart,
	PVOID		lpRegionEnd);

static BOOL AccessRegionInterface();

static BOOL AddPrivilege(
	 PWSTR		lpwszPriv );

static BOOL CallPageableFunTest();

static BOOL CloseFile(
	PHANDLE		lphFile,
	BOOL		bInteractive);

static BOOL ConfirmOper();

static HANDLE CreateFileWr(
	PWSTR		lpwszFileName,
	DWORD		dwAccess,
	DWORD		dwShareMode,
	DWORD		dwCrDisp);

static BOOL EnablePrivilege(
	PWSTR		lpwszPrvName);

static HANDLE FileCreate(
	PWSTR		lpwszFileName,
	BOOL		bIncrementalExp,
	ULONGLONG	ullFileSize);

static BOOL FileCreateInterface();

static BOOL FileMappingTest(
	HANDLE		hFileToMap,
	DWORD		dwMapProtect,
	PULONGLONG	lpMapSize,
	DWORD		dwViewAccess,
	DWORD		dwOffsetLow,
	DWORD		dwOffsetHigh,
	PSIZE_T		lpdwViewSize,
	BOOL		bExplicitNumaNode,
	DWORD		dwNumaNode,
	PWCHAR		lpwszMappingName,
	PVOID		*lplpRegion,
	LPHANDLE	lphMap);

static BOOL FileMappingOpenTest(
	DWORD		dwAccess, 
	PWCHAR		lpwszName,
	DWORD		dwOffLow,
	DWORD		dwOffHigh,
	PSIZE_T		lpSize,
	PVOID*		lplpMappedRegion,
	PHANDLE		lphMapping);

static BOOL FileMappingOpenTestInterface();

static BOOL FileMappingTestInterface();

static BOOL FileOpenCreateInterface();

static BOOL FileReadTest(
	HANDLE		hFile,
	ULONGLONG	ullOffset,
	DWORD		dwLength);

static BOOL FileReadTestInterface();

static BOOL FileWriteTest(
	HANDLE		hFile,
	ULONGLONG	ullOffset,
	ULONGLONG	ullByteCount);

static BOOL FileWriteTestInterface();


static BOOL GetKey(
	PWCHAR		lpwchKey,
	PWSTR		lpwszMsg,
	BOOL		bDefault,
	PWSTR		lpwszSeparator,
	PWSTR		lpwszValidChars);

static BOOL GetValue(
	PWSTR		lpwszFormat,
	PVOID		lpValue,
	BOOL		bDefault);

static BOOL GetValue2(
	LPWSTR		lpwszFormat,
	PVOID		lpValue);

static VOID InitStatus();

static BOOL IoAllocateMdlTest();

static BOOL IoFreeMdlTest();

static BOOL KMemTouchTest();

static BOOL LoadSysRegDrv();

static BOOL LockPageableDrvTest();

static BOOL MmAllocateMappingAddressTest();

static BOOL MmAllocatePagesForMdlExTest();

static BOOL MmFreeMappingAddressTest();

static BOOL MmFreePagesFromMdlTest();

static BOOL MmMapLockedPagesSpecifyCacheTest();

static BOOL MmMapLockedPagesWithReservedMappingTest();

static BOOL MmProbeAndLockPagesTest();

static BOOL MmUnlockPagesTest();

static BOOL MmUnmapLockedPagesTest();

static BOOL MmUnmapReservedMappingTest();

static HANDLE MyOpenFile(
	PWSTR		lpwszFileName,
	DWORD		dwAccess);

static BOOL OpenFileInterface();

static HANDLE OpenSysRegDev();

static VOID PrintMenu();

static void PrintPagStructAddrs(
	PBYTE		lpbStart,
	SIZE_T		dwSize );

static VOID PrintStatus();

static BOOL ProcessOption();

static BOOL ReleaseAll();

static BOOL ReleaseFileMapping(
	BOOL	bInteractive);

static BOOL ReleasePrivateRegion(
	BOOL		bInteractive);

static BOOL SendIoCtl(
	HANDLE		hDevice, 
	INT			code,
	LPVOID		lpInBuffer,
	INT			inBufSize,
	LPVOID		lpOutBuffer,
	INT			outBufSize );

static BOOL ShrinkWs();

static BOOL SRSChoice(
	PBOOL		&bQuit);

static BOOL StackFaultTest();

static BOOL SystemRangeSubmenu();

static BOOL UnloadSysRegDrv();

static BOOL UnlockPageableDrvTest();

static BOOL VirtAllocTest(
	PVOID		lpAddress,
	SIZE_T		Size,
	DWORD		flAllocationType,
	DWORD		flProtect,
	BOOL		bExplicitNumaNode,
	DWORD		dwNumaNode,
	PVOID*		lplpStart,
	PVOID*		lplpEnd);

static BOOL VirtAllocTestInterface();

static BOOL VirtProtTestInterface();

static BOOL WriteFileWr(
	HANDLE		hFile,
	LPVOID		lpBuffer,
	DWORD		cbBCount);



int wmain(/* int ArgC, wchar_t *lpwszArgV[] */)
{
	InitStatus();
	bExit = FALSE;
	while(!bExit) {
		wprintf(L"\n\n");
		PrintStatus();
		wprintf(L"\n");
		PrintMenu();
		wprintf(L"\n");
		wchOption = _getwch();
		ProcessOption();
		if (!bExit) {
			wprintf(L"\nany key to return to main menu...");
			_getwch();
		}
	}
	ReleaseAll();
}


//++
// Function: AccessRegion
//
// CreateFile wrapper
// 
//--
static BOOL AccessRegion(
	PVOID		lpRegionStart,
	PVOID		lpRegionEnd)
{
	BOOL	bRet = TRUE;
	DWORD	dwLastErr = ERROR_CANCELLED;

	PBYTE lpEndLocal;
	PBYTE lpStart;
	PBYTE lpTouch;
	WCHAR wchKey;
	wprintf(L"\n");
	if (!GetKey(&wchKey, L"r - read memory, w - write memory", FALSE, NULL, L"rw")) goto CLEANUP;
	lpStart = (PBYTE) lpRegionStart;
	wprintf(L"\n\nstart address [%#p] = ", lpStart);
	if (!GetValue(L"%I64i", &lpStart, TRUE)) {
		goto CLEANUP;
	}
	lpEndLocal = (PBYTE) lpRegionEnd;
	wprintf(L"\nend address [%#p] = ", lpEndLocal);
	if (!GetValue(L"%I64i", &lpEndLocal, TRUE)) {
		goto CLEANUP;
	}
	wprintf(
		L"\nabout to %s from %#p to %#p",
		(wchKey == L'r' ? L"read" : L"write"),
		lpStart,
		lpEndLocal);
	if (!ConfirmOper()) {
		dwLastErr = ERROR_CANCELLED;
		goto CLEANUP;
	}
	lpTouch = lpStart;
	__try {
		for (; lpTouch < lpEndLocal; lpTouch += 0x1000) {
			if (wchKey == L'r') {
				dummyByte = *lpTouch;
			} else {
				*((PVOID *) lpTouch) = lpTouch;
			}
		}
		wprintf(L"\nMemory access completed");
		bRet = TRUE;
		dwLastErr = ERROR_SUCCESS;
	}
	__except(EXCEPTION_EXECUTE_HANDLER) {
		wprintf(L"\nCaught exception: 0x%8x", GetExceptionCode());
		dwLastErr = ERROR_NOT_ENOUGH_MEMORY;
		bRet = FALSE;
	}

CLEANUP:
	SetLastError(dwLastErr);
	return bRet;
}


//++
// Function: AccessRegionInterface
//
// 
//--
static BOOL AccessRegionInterface()
{
	BOOL	bRet = TRUE;
	DWORD	dwLastErr = ERROR_CANCELLED;
	WCHAR	wchKey;
	wchKey = L'p';
	if (!GetKey(
		&wchKey, 
		L"m - default to mapped region, p - default to private region, n - no default",
		TRUE,
		L":",
		L"mpn")) goto CLEANUP;
	switch(wchKey) {
		case L'm':
			bRet = AccessRegion(lpMappedRegionStart, lpMappedRegionEnd);
			if (!bRet) {
				dwLastErr = GetLastError();
				goto CLEANUP;
			}
			break;
		case L'p':
			bRet = AccessRegion(lpPrivateRegionStart, lpPrivateRegionEnd);
			if (!bRet) {
				dwLastErr = GetLastError();
				goto CLEANUP;
			}
			break;
		case L'n':
			bRet = AccessRegion(NULL, NULL);
			if (!bRet) {
				dwLastErr = GetLastError();
				goto CLEANUP;
			}
			break;
	}
CLEANUP:
	SetLastError(dwLastErr);
	return bRet;

}


//++
// Function: AddPrivilege
//
// The code for this function is based on the sample code for
// Microsoft KB article 132958, available, as of 4/11/12, at 
// http://support.microsoft.com/kb/132958/en-us?fr=1
// 
//--
static BOOL AddPrivilege(
	 PWSTR		lpwszPriv )
{
	BOOL		bRet = FALSE;
	DWORD		dwLastErr;
	LSA_HANDLE	hPolicy = INVALID_HANDLE_VALUE;
	HANDLE		hToken = INVALID_HANDLE_VALUE;
    NTSTATUS	Status;

	if (!OpenProcessToken(
		GetCurrentProcess(),
		TOKEN_QUERY,
		&hToken)) {

		dwLastErr = GetLastError();
		hToken = INVALID_HANDLE_VALUE;
		wprintf(L"\nOpenProcessToken() failed with GetLastError() = %d",
			dwLastErr);
		goto CLEANUP;
	}
	PTOKEN_USER lpTokUser = NULL;
	DWORD dwRetLen = 0;
	GetTokenInformation(
		hToken,
		TokenUser,
		lpTokUser,
		0,
		&dwRetLen);
	dwLastErr = GetLastError();
	if (dwLastErr != ERROR_INSUFFICIENT_BUFFER) {

		wprintf(L"\nGetTokenInformation() failed with GetLastError() = %d",
			dwLastErr);
		goto CLEANUP;
	}
	lpTokUser = (PTOKEN_USER) HeapAlloc(GetProcessHeap(), 0, dwRetLen);
	if (lpTokUser == NULL) {
		dwLastErr = ERROR_NOT_ENOUGH_MEMORY;
		wprintf(L"\nHeapAlloc() failed for allocation size = %d", dwRetLen);
		goto CLEANUP;
	}
	if (!GetTokenInformation(
		hToken,
		TokenUser,
		lpTokUser,
		dwRetLen,
		&dwRetLen)) {

		dwLastErr = GetLastError();
		wprintf(L"\nGetTokenInformation() failed with GetLastError() = %d",
			dwLastErr);
		goto CLEANUP;
	}

    LSA_OBJECT_ATTRIBUTES ObjectAttributes;
    ZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));

	Status = LsaOpenPolicy(
        NULL,
        &ObjectAttributes,
        POLICY_CREATE_ACCOUNT | POLICY_LOOKUP_NAMES,
        &hPolicy );
	if (Status != STATUS_SUCCESS) {
		dwLastErr = LsaNtStatusToWinError(Status);
		hPolicy = INVALID_HANDLE_VALUE;
		wprintf(L"\nLsaOpenPolicy() failed with status = 0x%8x",
			Status);
		goto CLEANUP;
	}
	
    LSA_UNICODE_STRING PrivilegeString;

    SIZE_T StringLength = wcslen(lpwszPriv);
    PrivilegeString.Buffer = lpwszPriv;
    PrivilegeString.Length = (USHORT) StringLength * sizeof(WCHAR);
    PrivilegeString.MaximumLength=(USHORT)(StringLength+1) * sizeof(WCHAR);

	Status = LsaAddAccountRights(
        hPolicy,       
		lpTokUser->User.Sid,         
        &PrivilegeString,   
        1 );
	if (Status != STATUS_SUCCESS) {
		dwLastErr = LsaNtStatusToWinError(Status);
		wprintf(L"\nLsaAddAccountRights() failed with status = 0x%8x",
			Status);
		goto CLEANUP;
	}

	bRet = TRUE;
	dwLastErr = ERROR_SUCCESS;

CLEANUP:
    if (hPolicy != INVALID_HANDLE_VALUE) LsaClose(hPolicy);
    if (hToken != INVALID_HANDLE_VALUE) CloseHandle(hToken);
	SetLastError(dwLastErr);
	return bRet;
}


//++
// Function: CallPageableFunTest
//
// 
//--
static BOOL CallPageableFunTest()
{
	BOOL		bRet = FALSE;
	DWORD		dwLastErr = STATUS_SUCCESS;
	HANDLE		hDevice = INVALID_HANDLE_VALUE;

	hDevice = OpenSysRegDev();
	if (hDevice == INVALID_HANDLE_VALUE) {
		dwLastErr = GetLastError();
		goto CLEANUP;
	}
	if (!SendIoCtl(
		hDevice,
		IOCTL_MEMTEST_CALLPAGEABLE,
		NULL,
		0,
		NULL,
		0)) {

		dwLastErr = GetLastError();
		goto CLEANUP;
	}
	bRet = TRUE;
	dwLastErr = ERROR_SUCCESS;

CLEANUP:
	if (hDevice != INVALID_HANDLE_VALUE) CloseHandle(hDevice);
	SetLastError(dwLastErr);
	return bRet;
}


//++
// Function: CloseFile
//
// 
//--
static BOOL CloseFile(
	PHANDLE		lphFile,
	BOOL		bInteractive)
{
	DWORD		dwLastErr;
	HANDLE		hHndlBuf;

	if ((*lphFile != INVALID_HANDLE_VALUE) && (*lphFile != NULL)) {
		if (bInteractive) {
			wprintf(L"\nabout to close the file");
			if (!ConfirmOper()) {
				SetLastError(ERROR_CANCELLED);
				return TRUE;
			}
		}
		hHndlBuf = *lphFile;
		*lphFile = INVALID_HANDLE_VALUE;
		if (!CloseHandle(hHndlBuf)) {
			dwLastErr = GetLastError();
			wprintf(L"CloseHandle() failed with GetLastError() = %d", dwLastErr);
			SetLastError(dwLastErr);
			return FALSE;
		}
	}
	return TRUE;
}


//++
// Function: ConfirmOper
//
// 
//--
static BOOL ConfirmOper()
{
	WCHAR wchKeyBuf;

	wprintf(L"\nc - cancel, b - break, any other key to proceed");
	wchKeyBuf = _getwch();
	switch(wchKeyBuf){
		case L'c':
			return FALSE;
			break;
		case L'b':
			DebugBreak();
			return TRUE;
			break;
	}
	return TRUE;
}


//++
// Function: CreateFileWr
//
// CreateFile wrapper
// 
//--
static HANDLE CreateFileWr(
	PWSTR		lpwszFileName,
	DWORD		dwAccess,
	DWORD		dwShareMode,
	DWORD		dwCrDisp)
{
	DWORD		dwLastErr;
	HANDLE		hFile;

	hFile = CreateFileW(
		lpwszFileName,
		dwAccess,
		dwShareMode,
		NULL,
		dwCrDisp,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		dwLastErr = GetLastError();
		wprintf(L"\nCreateFile failed with GetLastError() = %d", dwLastErr);
		SetLastError(dwLastErr);
		return INVALID_HANDLE_VALUE;
	}
	return hFile;
}


//++
// Function: EnablePrivilege
//
//
// 
//--
static BOOL EnablePrivilege(
	PWSTR		lpwszPrvName)
{
	BOOL		bRet = TRUE;
	DWORD		dwLastErr = ERROR_SUCCESS;
	HANDLE		hToken = INVALID_HANDLE_VALUE;
	TOKEN_PRIVILEGES	tp;

	if (!OpenProcessToken(
		GetCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES,
		&hToken)) {

		dwLastErr = GetLastError();
		hToken = INVALID_HANDLE_VALUE;
		bRet = FALSE;
		wprintf(L"\nOpenProcessToken() failed with GetLastError() = %d",
			dwLastErr);
		goto CLEANUP;
	}
	
	if (!LookupPrivilegeValue(NULL, lpwszPrvName, &(tp.Privileges[0].Luid))) {
		dwLastErr = GetLastError();
		bRet = FALSE;
		wprintf(L"\nLookupPrivilegeValue() failed with GetLastError() = %d",
			dwLastErr);
		goto CLEANUP;
	}
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	tp.PrivilegeCount = 1;

	if (!AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tp,
		0,
		NULL,
		NULL)) {

		dwLastErr = GetLastError();
		bRet = FALSE;
		wprintf(L"\nAdjustTokenPrivileges() failed with GetLastError() = %d",
			dwLastErr);
		goto CLEANUP;
	}
	dwLastErr = GetLastError();
	if (dwLastErr == ERROR_NOT_ALL_ASSIGNED) {
		bRet = FALSE;
		wprintf(L"\nPrivilege %s not assigned. Must add privilege to account.", 
			lpwszPrvName);
		goto CLEANUP;
	}
	else if (dwLastErr != ERROR_SUCCESS) {
		wprintf(L"\nAdjustTokenPrivileges() succeeded but GetLastError() = %d",
			dwLastErr );
	}

	bRet = TRUE;
	dwLastErr = ERROR_SUCCESS;

CLEANUP:
	if (hToken != INVALID_HANDLE_VALUE) CloseHandle(hToken);
	SetLastError(dwLastErr);
	return bRet;
}


//++
// Function: FileCreate
//
//
// 
//--
static HANDLE FileCreate(
	PWSTR		lpwszFileName,
	BOOL		bIncrementalExp,
	ULONGLONG	ullFileSize)
{
	BOOL		bCloseAll = TRUE;
	DWORD		dwLastErr = ERROR_SUCCESS;
	HANDLE		hRet = INVALID_HANDLE_VALUE;

	wprintf(L"\nabout to create the file");
	if (!ConfirmOper()) {
		dwLastErr = ERROR_CANCELLED;
		goto CLEANUP;
	}
	hRet = CreateFileWr(
		lpwszFileName,
		GENERIC_READ | GENERIC_WRITE,
		0,
		CREATE_ALWAYS);
	if (hRet == INVALID_HANDLE_VALUE) {
		dwLastErr = GetLastError();
		goto CLEANUP;
	}
	if (bIncrementalExp) {
		wprintf(L"\nabout to expand the file");
		if (!ConfirmOper()) {
			SetLastError(ERROR_CANCELLED);
			goto CLEANUP;
		}
		for (ULONGLONG i = 0; i < ullFileSize / sizeof i + 1; i++) {
			if (!WriteFileWr(
				hRet,
				&i,
				sizeof i)) {
				
				dwLastErr = GetLastError();
				goto CLEANUP;
			}
		}
	}
	bCloseAll = FALSE;
	wprintf(L"\nfile %s created", lpwszFileName);
CLEANUP:
	if (bCloseAll) {
		if ((hRet != INVALID_HANDLE_VALUE) && (hRet != NULL)) {
			CloseHandle(hRet);
			hRet = INVALID_HANDLE_VALUE;
		}
	}
	SetLastError(dwLastErr);
	return hRet;
}


//++
// Function: FileCreateInterface
//
//
// 
//--
static BOOL FileCreateInterface()
{
	BOOL		bRet = TRUE;
	DWORD		dwLastErr = ERROR_CANCELLED;

	BOOL		bIncExp;
	ULONGLONG	ullFileSize = 0;
	WCHAR		wchBuf;

	wcscpy_s(wszFileNameGlob, sizeof wszFileNameGlob / sizeof wszFileNameGlob[0],
		L"memtests.tmp");
	wprintf(L"\nfile name [%s]: ", wszFileNameGlob);
	if (!GetValue(L"%s", wszFileNameGlob, TRUE)) goto CLEANUP;
	wszFileNameGlob[sizeof wszFileNameGlob / sizeof wszFileNameGlob[0] - 1] = L'\0';
	wprintf(L"\n");
	wchBuf = L'n';
	if (!GetKey(
		&wchBuf,
		L"incremental expansion",
		TRUE,
		L"? ",
		L"yn")) goto CLEANUP;
	bIncExp = (wchBuf == L'y');
	if (bIncExp) {
		wprintf(L"\nfile size = ");
		if (!GetValue(L"%I64i", &ullFileSize, FALSE)) goto CLEANUP;
	}
	hFileGlob = FileCreate(wszFileNameGlob, bIncExp, ullFileSize);
	if (hFileGlob == INVALID_HANDLE_VALUE) {

		// If last error is ERROR_CANCELLED, return success. Cancelling
		// is not returned as an error from any function.
		//
		dwLastErr = GetLastError();
		bRet = (dwLastErr == ERROR_CANCELLED);
		goto CLEANUP;
	}
	dwLastErr = ERROR_SUCCESS;

CLEANUP:
	SetLastError(dwLastErr);
	return bRet;
}


//++
// Function: FileMappingOpenTest
//
// File mapping tests
//
// 
//--
static BOOL FileMappingOpenTest(
	DWORD		dwAccess, 
	PWCHAR		lpwszName,
	DWORD		dwOffLow,
	DWORD		dwOffHigh,
	PSIZE_T		lpSize,
	PVOID*		lplpMappedRegion,
	PHANDLE		lphMapping)
{
	BOOL		bRet = TRUE;
	BOOL		bRelease = TRUE;
	DWORD		dwLastErr = ERROR_SUCCESS;

	*lphMapping = INVALID_HANDLE_VALUE;
	*lplpMappedRegion = NULL;

	// Open the file mapping
	//
	wprintf(L"\ndwAccess  = 0x%x", dwAccess);
	wprintf(L"\nlpwszName = %s", lpwszName);
	wprintf(L"\nOffset    = 0x%I64x", (((ULONGLONG) dwOffHigh) << 32) + dwOffLow);
	wprintf(L"\nSize      = 0x%I64x", *lpSize);
	wprintf(L"\n\nabout to open the mapping");
	if (!ConfirmOper()) {
		SetLastError(ERROR_CANCELLED);
		return TRUE;
	}
	*lphMapping = OpenFileMapping(
		dwAccess,
		FALSE,
		lpwszName);
	if (*lphMapping == NULL) {
		dwLastErr = GetLastError();
		wprintf(L"\nOpenFileMapping() failed with GetLastError() = %d",
			dwLastErr);
		SetLastError(dwLastErr);
		return FALSE;
	}

	wprintf(L"\nabout to map the view");
	if (!ConfirmOper()) {
		dwLastErr = ERROR_CANCELLED;
		goto CLEANUP;
	}
	*lplpMappedRegion = MapViewOfFileEx(
		*lphMapping,
		dwAccess,
		dwOffHigh,
		dwOffLow,
		*lpSize,
		NULL);
	if (*lplpMappedRegion == NULL) {
		dwLastErr = GetLastError();
		wprintf(L"\nMapViewOfFileEx() failed with GetLastError() = %d",
			dwLastErr);
		bRet = FALSE;
		goto CLEANUP;
	}
	if (!(*lpSize)) {
		MEMORY_BASIC_INFORMATION MemInfo;
		SecureZeroMemory(&MemInfo, sizeof MemInfo);
		VirtualQueryEx(
			GetCurrentProcess(),
			*lplpMappedRegion,
			&MemInfo,
			sizeof MemInfo);
		*lpSize = MemInfo.RegionSize;
	}
	wprintf(
		L"\nView range: %#p - %#p",
		*lplpMappedRegion,
		(PBYTE) *lplpMappedRegion + *lpSize);
	bRet = TRUE;
	dwLastErr = ERROR_SUCCESS;
	bRelease = FALSE;

CLEANUP:
	if (bRelease) {
		if ((*lphMapping != INVALID_HANDLE_VALUE) && (*lphMapping != NULL)) {
			CloseHandle(*lphMapping);
			*lphMapping = INVALID_HANDLE_VALUE;
		}
		if (*lplpMappedRegion != NULL) {
			UnmapViewOfFile(*lplpMappedRegion);
			*lplpMappedRegion = NULL;
		}
	}
	SetLastError(dwLastErr);
	return bRet;
}


//++
// Function: FileMappingOpenTestInterface
//
//--
static BOOL FileMappingOpenTestInterface()
{
	BOOL		bRet = TRUE;
	DWORD		dwLastErr = ERROR_CANCELLED;

	wprintf(L"\n\nOpen and map existing mapping\n");

	DWORD dwMapAcc = FILE_MAP_READ | FILE_MAP_WRITE;
	wprintf(L"\nAccess [0x%x]:", dwMapAcc);
	wprintf(L"\n"
		L"    FILE_MAP_ALL_ACCESS = 0x%x", FILE_MAP_ALL_ACCESS);
	wprintf(L"\n"
		L"    FILE_MAP_COPY       = 0x%x", FILE_MAP_COPY);
	wprintf(L"\n"
		L"    FILE_MAP_EXECUTE    = 0x%x", FILE_MAP_EXECUTE);
	wprintf(L"\n"
		L"    FILE_MAP_READ       = 0x%x", FILE_MAP_READ);
	wprintf(L"\n"
		L"    FILE_MAP_WRITE      = 0x%x", FILE_MAP_WRITE);
	wprintf(L"\n");
	if (!GetValue(L"%i", &dwMapAcc, TRUE)) goto CLEANUP;

	wcscpy_s(wszMappingName, sizeof wszMappingName / sizeof wszMappingName[0], L"map");
	wprintf(L"\nMapping name [%s]: ", wszMappingName);
	if (!GetValue(L"%s", wszMappingName, TRUE)) goto CLEANUP;
	wszMappingName[sizeof wszMappingName / sizeof wszMappingName[0] - 1] = L'\0';


	LONGLONG llValue = 0;
	wprintf(L"\noffset [0x%I64x]: ", llValue);
	DWORD dwOffHigh, dwOffLow;
	if (!GetValue(L"%I64i", &llValue, TRUE)) goto CLEANUP;
	dwOffHigh = (DWORD) (llValue >> 32);
	dwOffLow = (DWORD) llValue;

	SIZE_T Size = 0;
	wprintf(L"\nview size [0x%I64x]: ", Size);
	if (!GetValue(L"%I64i", &Size, TRUE)) goto CLEANUP;

	if (!FileMappingOpenTest(
		dwMapAcc, 
		wszMappingName,
		dwOffLow,
		dwOffHigh,
		&Size,
		&lpMappedRegionStart,
		&hFileMapping)) {

		dwLastErr = GetLastError();
		bRet = FALSE;
		goto CLEANUP;
	}
	lpMappedRegionEnd = (PBYTE) lpMappedRegionStart + Size;
	dwLastErr = ERROR_SUCCESS;

CLEANUP:
	SetLastError(dwLastErr);
	return bRet;
}


//++
// Function: FileMappingTest
//
// File mapping tests
//
// 
//--
static BOOL FileMappingTest(
	HANDLE		hFileToMap,
	DWORD		dwMapProtect,
	PULONGLONG	lpMapSize,
	DWORD		dwViewAccess,
	DWORD		dwOffsetLow,
	DWORD		dwOffsetHigh,
	PSIZE_T		lpdwViewSize,
	BOOL		bExplicitNumaNode,
	DWORD		dwNumaNode,
	PWCHAR		lpwszMappingName,
	PVOID		*lplpRegion,
	LPHANDLE	lphMap)
{


	BOOL	bRet = TRUE;
	BOOL	bRelease = TRUE;
	DWORD	dwLastErr = ERROR_SUCCESS;


	wprintf(
		L"\nhFileToMap        = %x", hFileToMap);
	wprintf(
		L"\ndwMapProtect      = 0x%x", dwMapProtect);
	wprintf(
		L"\nMapSize           = 0x%I64x", *lpMapSize);
	wprintf(
		L"\nlpwszMappingName  = %s", lpwszMappingName);
	wprintf(
		L"\ndwViewAccess      = 0x%x", dwViewAccess);
	wprintf(
		L"\ndwOffsetLow       = 0x%x", dwOffsetLow);
	wprintf(
		L"\ndwOffsetHigh      = 0x%x", dwOffsetHigh);
	wprintf(
		L"\ndwViewSize        = 0x%p", *lpdwViewSize);
	wprintf(
		L"\nbExplicitNumaNode = %s", 
		bExplicitNumaNode ? L"TRUE" : L"FALSE" );
	if (bExplicitNumaNode) {
		wprintf(
		L"\ndwNumaNode        = %d", dwNumaNode);
	}

	*lplpRegion = NULL;
	*lphMap = INVALID_HANDLE_VALUE;

	if(!ConfirmOper()) {
		SetLastError(ERROR_CANCELLED);
		return TRUE;
	}

	ULONGLONG ActualMapSize = *lpMapSize;

	if (hFileToMap != INVALID_HANDLE_VALUE) {
		if (!ActualMapSize) {
			LARGE_INTEGER FileSize;
			if (!GetFileSizeEx(hFileToMap, &FileSize)) {
				dwLastErr = GetLastError();
				wprintf(L"\nGetFileSizeEx() failed with GetLastError() = %d",
					dwLastErr);
				SetLastError(dwLastErr);
				bRet = FALSE;
				goto CLEANUP;
			}
			ActualMapSize = FileSize.QuadPart;
		}
	}

	// Create the file mapping
	//
	wprintf(L"\nabout to create the mapping");
	if (!ConfirmOper()) {
		dwLastErr = ERROR_CANCELLED;
		goto CLEANUP;
	}
	*lphMap = CreateFileMapping(
		hFileToMap,
		NULL,
		dwMapProtect,
		*lpMapSize >> 32,
		*lpMapSize & 0xffffffff,
		lpwszMappingName);
	if (*lphMap == NULL) {
		dwLastErr = GetLastError();
		wprintf(L"\nCreateFileMapping() failed with GetLastError() = %d", dwLastErr);
		bRet = FALSE;
		goto CLEANUP;
	}
	wprintf(L"\nabout to map the view");
	if (!ConfirmOper()) {
		dwLastErr = ERROR_CANCELLED;
		goto CLEANUP;
	}
	if (bExplicitNumaNode) {
		*lplpRegion = (LPBYTE) MapViewOfFileExNuma(
			*lphMap,
			dwViewAccess,
			dwOffsetHigh,
			dwOffsetLow,
			*lpdwViewSize,
			NULL,
			dwNumaNode);
	} else {
		*lplpRegion = (LPBYTE) MapViewOfFileEx(
			*lphMap,
			dwViewAccess,
			dwOffsetHigh,
			dwOffsetLow,
			*lpdwViewSize,
			NULL);
	}
	if (*lplpRegion == NULL) {
		dwLastErr = GetLastError();
		wprintf(L"\nMapViewOfFileEx() failed with GetLastError() = %d", dwLastErr);
		bRet = FALSE;
		goto CLEANUP;
	}
	SIZE_T ActualViewSize = *lpdwViewSize;
	if (!ActualViewSize) {
		ActualViewSize = (SIZE_T) (ActualMapSize - (((ULONGLONG) dwOffsetHigh) << 32) - dwOffsetLow);
	}
	wprintf(
		L"\nView range: %#p - %#p",
		*lplpRegion,
		(PBYTE) *lplpRegion + ActualViewSize);

	*lpMapSize = ActualMapSize;
	*lpdwViewSize = ActualViewSize;
	bRet = TRUE;
	bRelease = FALSE;
	dwLastErr = ERROR_SUCCESS;
CLEANUP:
	if (bRelease) {
		if (*lplpRegion != NULL) {
			UnmapViewOfFile(*lplpRegion);
			*lplpRegion = NULL;
		}
		if ((*lphMap != NULL) && (*lphMap != INVALID_HANDLE_VALUE)) {
			CloseHandle(*lphMap);
			*lphMap = INVALID_HANDLE_VALUE;
		}
	}
	SetLastError(dwLastErr);
	return bRet;
}


//++
// Function: FileMappingTestInterface
//
// 
//--
static BOOL FileMappingTestInterface()
{
	BOOL		bRet = TRUE;
	DWORD		dwLastErr = ERROR_CANCELLED;
	WCHAR		wchCharVal;

	wprintf(L"\n\nFile mapping test\n");

	HANDLE hFileToMap = INVALID_HANDLE_VALUE;
	wprintf(L"\n");
	wchCharVal = 'm';
	if (!GetKey(
		&wchCharVal,
		L"map type (m = shared memory, f = mapped file)",
		TRUE,
		L":",
		L"mf")) goto CLEANUP;
	switch(wchCharVal) {
		case L'm':
			hFileToMap = INVALID_HANDLE_VALUE;
			break;
		case L'f':

			// If no file is open, create or open one

			if (hFileGlob == INVALID_HANDLE_VALUE) {
				wchCharVal = L'o';
				wprintf(L"\n");
				if (!GetKey(&wchCharVal, L"c - createfile, o - open file", TRUE, L":", L"co")) goto CLEANUP;
				switch (wchCharVal) {
					case L'c':
						if (!FileCreateInterface()) {
							dwLastErr = GetLastError();
							bRet = FALSE;
							goto CLEANUP;
						}
						if (GetLastError() == ERROR_CANCELLED) goto CLEANUP;
						break;
					case L'o':
						if (!OpenFileInterface()) {
							dwLastErr = GetLastError();
							bRet = FALSE;
							goto CLEANUP;
						}
						if (GetLastError() == ERROR_CANCELLED) goto CLEANUP;
						break;
				}
			}
			hFileToMap = hFileGlob;
			break;
	}

	DWORD dwMapProt = PAGE_READWRITE;
	wprintf(L"\nmap protection [0x%x]:", dwMapProt);
	wprintf(L"\n"
		L"    PAGE_READONLY          = 0x%x", PAGE_READONLY);
	wprintf(L"\n"
		L"    PAGE_READWRITE         = 0x%x", PAGE_READWRITE);
	wprintf(L"\n"
		L"    PAGE_WRITECOPY         = 0x%x", PAGE_WRITECOPY);
	wprintf(L"\n"
		L"    PAGE_EXECUTE_READ      = 0x%x", PAGE_EXECUTE_READ);
	wprintf(L"\n"
		L"    PAGE_EXECUTE_READWRITE = 0x%x", PAGE_EXECUTE_READWRITE);
	wprintf(L"\n"
		L"    PAGE_EXECUTE_WRITECOPY = 0x%x", PAGE_EXECUTE_WRITECOPY);
	wprintf(L"\n"
		L"    SEC_IMAGE              = 0x%x", SEC_IMAGE);
	wprintf(L"\n"
		L"    SEC_LARGE_LAGES        = 0x%x", SEC_LARGE_PAGES);
	wprintf(L"\n"
		L"    SEC_COMMIT             = 0x%x", SEC_COMMIT);
	wprintf(L"\n");
	if(!GetValue(L"%i", &dwMapProt, TRUE)) goto CLEANUP;

	SIZE_T MapSize;
	wprintf(L"\nMap size: ");
	if (!GetValue(L"%I64i", &MapSize, FALSE)) goto CLEANUP;

	wcscpy_s(wszMappingName, sizeof wszMappingName / sizeof wszMappingName[0], L"map");
	wprintf(L"\nmapping name [%s]:", wszMappingName);
	if (!GetValue(L"%s", wszMappingName, TRUE)) goto CLEANUP;
	wszMappingName[sizeof wszMappingName / sizeof wszMappingName[0] - 1] = L'\0';

	DWORD dwViewAcc = FILE_MAP_READ | FILE_MAP_WRITE;
	wprintf(L"\nView Access [0x%x]:", dwViewAcc);
	wprintf(L"\n"
		L"    FILE_MAP_ALL_ACCESS = 0x%x", FILE_MAP_ALL_ACCESS);
	wprintf(L"\n"
		L"    FILE_MAP_COPY       = 0x%x", FILE_MAP_COPY);
	wprintf(L"\n"
		L"    FILE_MAP_EXECUTE    = 0x%x", FILE_MAP_EXECUTE);
	wprintf(L"\n"
		L"    FILE_MAP_READ       = 0x%x", FILE_MAP_READ);
	wprintf(L"\n"
		L"    FILE_MAP_WRITE      = 0x%x", FILE_MAP_WRITE);
	wprintf(L"\n");
	if(!GetValue(L"%i", &dwViewAcc, TRUE)) goto CLEANUP;

	LONGLONG llValue = 0;
	DWORD dwOffHigh, dwOffLow;
	wprintf(L"\noffset [0x%I64x]:", llValue);
	if (!GetValue(L"%I64i", &llValue, TRUE)) goto CLEANUP;
	dwOffHigh = (DWORD) (llValue >> 32);
	dwOffLow = (DWORD) llValue;

	SIZE_T Size = 0;
	wprintf(L"\nview size [0x%I64x]:", Size);
	if (!GetValue(L"%I64i", &Size, TRUE)) goto CLEANUP;

	BOOL bExplicitNumaNode = FALSE;
	DWORD dwNumaNode = 0;
	wprintf(L"\n");
	wchCharVal = L'n';
	if (!GetKey(&wchCharVal, L"specify NUMA node", TRUE, L"?", L"yn")) goto CLEANUP;
	switch (wchCharVal) {
		case L'y':
			bExplicitNumaNode = TRUE;
			wprintf(L"\nNUMA node: ");
			if (!GetValue(L"%d", &dwNumaNode, FALSE)) goto CLEANUP;
			break;
		case L'n':
			bExplicitNumaNode = FALSE;
			break;
	}

	if (!FileMappingTest(
		hFileToMap,
		dwMapProt,
		&MapSize,
		dwViewAcc,
		dwOffLow,
		dwOffHigh,
		&Size,
		bExplicitNumaNode,
		dwNumaNode,
		wszMappingName,
		&lpMappedRegionStart,
		&hFileMapping)) {

		bRet = FALSE;
		dwLastErr = GetLastError();
		goto CLEANUP;

	}
	lpMappedRegionEnd = (PBYTE) lpMappedRegionStart + Size;
	dwLastErr = ERROR_SUCCESS;

CLEANUP:
	SetLastError(dwLastErr);
	return bRet;
}




//++
// Function: FileOpenCreateInterface
//
// 
//--
static BOOL FileOpenCreateInterface()
{
	BOOL	bRet = TRUE;
	DWORD	dwLastErr = ERROR_CANCELLED;

	WCHAR wchCharVal;
	wprintf(L"\n");
	if (!GetKey(
		&wchCharVal,
		L"c - create file, o - open file",
		FALSE,
		L": ",
		L"co")) goto CLEANUP;
	switch (wchCharVal) {
		case L'c':
			if (!FileCreateInterface()) {
				dwLastErr = GetLastError();
				bRet = FALSE;
				goto CLEANUP;
			}
			break;
		case L'o':
			if (!OpenFileInterface()) {
				dwLastErr = GetLastError();
				bRet = FALSE;
				goto CLEANUP;
			}
			break;
	}
	dwLastErr = ERROR_SUCCESS;

CLEANUP:
	SetLastError(dwLastErr);
	return bRet;
}

//++
// Function: FileReadTest
//
// 
//--
static BOOL FileReadTest(
	HANDLE		hFile,
	ULONGLONG	ullOffset,
	DWORD		dwLength)
{

#define BUF_SIZE	0x100000

	BOOL			bRet = TRUE;
	DWORD			dwLastErr = ERROR_SUCCESS;
	LARGE_INTEGER	liDist;
	PVOID			lpBuffer = NULL;

	if (hFile == INVALID_HANDLE_VALUE) {
		wprintf(L"\ninvalid file handle");
		SetLastError(ERROR_NOT_SUPPORTED);
		return FALSE;
	}
	lpBuffer = VirtualAllocEx(
		GetCurrentProcess(),
		NULL,
		BUF_SIZE,
		MEM_RESERVE | MEM_COMMIT,
		PAGE_READWRITE);
	if (lpBuffer == NULL) {
		dwLastErr = GetLastError();
		bRet = FALSE;
		wprintf(L"\nVirtualAllocEx() failed with GetLastError() = %d", dwLastErr);
		goto CLEANUP;
	}
	liDist.QuadPart = ullOffset;
	wprintf(L"\nabout to move the file pointer");
	if (!ConfirmOper()) {
		dwLastErr = ERROR_CANCELLED;
		goto CLEANUP;
	}
	if (!SetFilePointerEx(
		hFile,
		liDist,
		NULL,
		FILE_BEGIN)) {

		dwLastErr = GetLastError();
		bRet = FALSE;
		wprintf(L"\nSetFilePointerEx() failed with GetLastError() = %d", dwLastErr);
		goto CLEANUP;
	}
	DWORD dwBytesRead;
	DWORD dwReadSize;
	DWORD dwRemaining;
	dwRemaining = dwLength;
	wprintf(L"\nabout to read the file");
	if (!ConfirmOper()) {
		dwLastErr = ERROR_CANCELLED;
		goto CLEANUP;
	}
	while (dwRemaining) {
		dwReadSize = (BUF_SIZE < dwRemaining ? BUF_SIZE : dwRemaining);
		if (!ReadFile(
			hFile,
			lpBuffer,
			dwReadSize,
			&dwBytesRead,
			NULL)) {

			dwLastErr = GetLastError();
			bRet = FALSE;
			wprintf(L"\nReadFile() failed with GetLastError() = %d", dwLastErr);
			goto CLEANUP;
		}
		dwRemaining -= dwReadSize;
	}
	wprintf(L"\nfile read completed");

CLEANUP:
	if (lpBuffer != NULL) VirtualFreeEx(
		GetCurrentProcess(),
		lpBuffer,
		BUF_SIZE,
		MEM_RELEASE);
	SetLastError(dwLastErr);
	return bRet;


}


//++
// Function: FileReadTestInterface
//
// 
//--
static BOOL FileReadTestInterface()
{
	BOOL		bRet = TRUE;
	DWORD		dwLastErr = ERROR_CANCELLED;
	DWORD		dwLength;
	ULONGLONG	ullOffset;

	// Open the file if it has not been done yet.
	//
	if (hFileGlob == INVALID_HANDLE_VALUE) {
		if (!OpenFileInterface()) {
			bRet = FALSE;
			dwLastErr = GetLastError();
			goto CLEANUP;
		}
		if (GetLastError() == ERROR_CANCELLED) goto CLEANUP;
	}
	ullOffset = 0;
	wprintf(L"\noffset [0x%I64x] = ", ullOffset);
	if (!GetValue(L"%I64i", &ullOffset, TRUE)) goto CLEANUP;
	wprintf(L"\nlength = ");
	if (!GetValue(L"%i", &dwLength, FALSE)) goto CLEANUP;
	if (!FileReadTest(hFileGlob, ullOffset, dwLength)) {
		dwLastErr = GetLastError();
		bRet = FALSE;
		goto CLEANUP;
	}
	dwLastErr = ERROR_SUCCESS;

CLEANUP:
	SetLastError(dwLastErr);
	return bRet;
}


//++
// Function: FileWriteTest
//
// 
//--
static BOOL FileWriteTest(
	HANDLE		hFile,
	ULONGLONG	ullOffset,
	ULONGLONG	ullByteCount)
{
	DWORD	dwLastErr;

	LARGE_INTEGER liDist;
	liDist.QuadPart = ullOffset;
	wprintf(L"\nabout to move the file pointer");
	if (!ConfirmOper()) {
		SetLastError(ERROR_CANCELLED);
		return TRUE;
	}
	if (!SetFilePointerEx(
		hFile,
		liDist,
		NULL,
		FILE_BEGIN)) {

		dwLastErr = GetLastError();
		wprintf(L"\nSetFilePointerEx() failed with GetLastError() = %d", dwLastErr);
		SetLastError(dwLastErr);
		return FALSE;
	}
	wprintf(L"\nabout to write into the file");
	if (!ConfirmOper()) {
		SetLastError(ERROR_CANCELLED);
		return TRUE;
	}
	BYTE j = 0;
	for (ULONGLONG i = 0; i < ullByteCount; i++, j++) {
		if (!WriteFileWr(
			hFile,
			&j,
			sizeof j)) {
			
			return FALSE;
		}
	}
	wprintf(L"\nfile write completed");
	return TRUE;
}



//++
// Function: FileWriteTestInterface
//
// 
//--
static BOOL FileWriteTestInterface()
{
	BOOL		bRet = TRUE;
	DWORD		dwLastErr = ERROR_CANCELLED;

	// Open the file if it has not been done yet.
	//
	if (hFileGlob == INVALID_HANDLE_VALUE) {
		if (!FileOpenCreateInterface()) {
			bRet = FALSE;
			dwLastErr = GetLastError();
			goto CLEANUP;
		}
		if (GetLastError() == ERROR_CANCELLED) goto CLEANUP;
	}

	ULONGLONG ullOffset = 0;
	wprintf(L"\noffset [0x%I64x] = ", ullOffset);
	if (!GetValue(L"%I64i", &ullOffset, TRUE)) goto CLEANUP;

	ULONGLONG ullByteCount;
	wprintf(L"\nbyte count = ");
	if (!GetValue(L"%I64i", &ullByteCount, FALSE)) goto CLEANUP;
	if (!FileWriteTest(
		hFileGlob,
		ullOffset,
		ullByteCount)) {

		dwLastErr = GetLastError();
		bRet = FALSE;
		goto CLEANUP;
	}
	dwLastErr = ERROR_SUCCESS;

CLEANUP:
	SetLastError(dwLastErr);
	return bRet;
}


//++
// Function: GetKey
//
//--
static BOOL GetKey(
	PWCHAR		lpwchKey,
	PWSTR		lpwszMsg,
	BOOL		bDefault,
	PWSTR		lpwszSeparator,
	PWSTR		lpwszValidChars)
{
	BOOL bLoop = TRUE;
	WCHAR wchKey;
	do {
		if (lpwszMsg != NULL) wprintf(lpwszMsg);
		if (lpwszValidChars != NULL) {
			wprintf(L" (");
			PWCHAR lpwchCurrent = lpwszValidChars;
			while (*lpwchCurrent != L'\0') {
				wprintf(L"%c", *lpwchCurrent);
				lpwchCurrent++;
				if (*lpwchCurrent != L'\0') wprintf(L"/");
			}
			wprintf(L")");
		}
		if (bDefault) {
			wprintf(L" [%c]", *lpwchKey);
		}
		if (lpwszSeparator != NULL) {
			wprintf(lpwszSeparator);
		}
		wchKey = _getwch();
		switch (wchKey) {
			case 27:
				return FALSE;
			case L'\r':
				if (bDefault) {
					wchKey = *lpwchKey;
					bLoop = FALSE;
				}
				break;
			default:
				if (lpwszValidChars != NULL) {
					PWCHAR lpwchCurrent = lpwszValidChars;
					while (*lpwchCurrent != L'\0') {
						if (wchKey == *lpwchCurrent) break;
						lpwchCurrent++;
					}
					if (*lpwchCurrent != L'\0') {
						bLoop = FALSE;
					} else {
						wprintf(L"\ninvalid key: %c", wchKey);
					}
				} else {
					bLoop = FALSE;
				}
		}
		if (bLoop) wprintf(L"\n");
	} while (bLoop);
	wprintf(L"%c", wchKey);
	*lpwchKey = wchKey;
	return TRUE;
}


//++
// Function: GetValue
//
//--
// We want to use wscanf without getting warning C4996
//
#pragma warning(push)
#pragma warning(disable : 4996)
static BOOL GetValue(
	PWSTR		lpwszFormat,
	PVOID		lpValue,
	BOOL		bDefault)
{
	HANDLE hStdIn;
	INPUT_RECORD ConInp;
	DWORD dwNumberRead;
	hStdIn = GetStdHandle(STD_INPUT_HANDLE);
	for (;;) {
		WaitForSingleObject(hStdIn, INFINITE);
		PeekConsoleInput(
			hStdIn,
			&ConInp,
			1,
			&dwNumberRead);
		if ((ConInp.EventType) != KEY_EVENT || !ConInp.Event.KeyEvent.bKeyDown) {
			FlushConsoleInputBuffer(hStdIn);
			continue;
		}
		WCHAR wchBuf = ConInp.Event.KeyEvent.uChar.UnicodeChar;
		switch (wchBuf) {
			case 0:
				FlushConsoleInputBuffer(hStdIn);
				continue;
				break;
			case 13:
				FlushConsoleInputBuffer(hStdIn);
				if (bDefault) {
					return TRUE;
				} else {
					continue;
				}
				break;
			case 27:
				FlushConsoleInputBuffer(hStdIn);
				return FALSE;
				break;
			default:
				if (!wscanf(lpwszFormat, lpValue)) {
					wprintf(L"\nInvalid value, reenter: ");
					WCHAR wchBuf2;
					do {
						wscanf(L"%c", &wchBuf2);
					} while (wchBuf2 != L'\n');
					continue;
				}
				return TRUE;
		}
	}
}
#pragma warning(pop)



//++
// Function: InitStatus
//
// 
//--
static VOID InitStatus()
{
	lpMappedRegionStart = NULL;
	lpMappedRegionEnd = NULL;
	lpPrivateRegionStart = NULL;
	lpPrivateRegionEnd = NULL;
	hFileMapping = INVALID_HANDLE_VALUE;
	hFileGlob = INVALID_HANDLE_VALUE;
	gl_pMdl = NULL;
	gl_AllMapIn.Size = 0;
	gl_AllMapIn.Address = NULL;
	gl_bMdlLocked = FALSE;
	gl_lpMappedSystemRegion = NULL;
	gl_lpResMappedRegion = NULL;
}


//++
// Function: IoAllocateMdlTest
//
// 
//--
static BOOL IoAllocateMdlTest()
{
	BOOL		bRet = FALSE;
	DWORD		dwLastErr = ERROR_SUCCESS;
	HANDLE		hDevice = INVALID_HANDLE_VALUE;

	hDevice = OpenSysRegDev();
	if (hDevice == INVALID_HANDLE_VALUE) {
		dwLastErr = GetLastError();
		goto CLEANUP;
	}

	PVOID pVirtAddr;
	wprintf(L"\nVirtualAddress ");
	if (!GetValue(L"%I64i", &pVirtAddr, FALSE)) {
		bRet = TRUE;
		goto CLEANUP;
	}

	ULONG uLength;
	wprintf(L"\nLength ");
	if (!GetValue(L"%i", &uLength, FALSE)) {
		bRet = TRUE;
		goto CLEANUP;
	}
	KADRV_ALLOCMDL_INPUT AllocMdlIn;
	AllocMdlIn.VirtualAddress = pVirtAddr;
	AllocMdlIn.Length = uLength;
	wprintf(L"\nAbout to call the driver");
	if (!ConfirmOper()) {
		bRet = TRUE;
		dwLastErr = ERROR_SUCCESS;
		goto CLEANUP;
	}
	if (!SendIoCtl(
		hDevice,
		IOCTL_MEMTEST_ALLOCATEMDL,
		&AllocMdlIn,
		sizeof AllocMdlIn,
		&gl_pMdl,
		sizeof gl_pMdl)) {

		dwLastErr = GetLastError();
		goto CLEANUP;
	}
	bRet = TRUE;
	dwLastErr = ERROR_SUCCESS;
CLEANUP:
	if (hDevice != INVALID_HANDLE_VALUE) CloseHandle(hDevice);
	SetLastError(dwLastErr);
	return bRet;
}


//++
// Function: IoFreeMdlTest
//--
static BOOL IoFreeMdlTest()
{
	BOOL		bRet = FALSE;
	DWORD		dwLastErr = ERROR_SUCCESS;
	HANDLE		hDevice = INVALID_HANDLE_VALUE;

	hDevice = OpenSysRegDev();
	if (hDevice == INVALID_HANDLE_VALUE) {
		dwLastErr = GetLastError();
		goto CLEANUP;
	}

	PVOID pMdl = gl_pMdl;
	wprintf(L"\nMdl address [%#p] ", pMdl);
	if (!GetValue(L"%I64i", &pMdl, TRUE)) {
		bRet = TRUE;
		goto CLEANUP;
	}

	wprintf(L"\nAbout to call the driver");
	if (!ConfirmOper()) {
		bRet = TRUE;
		dwLastErr = ERROR_SUCCESS;
		goto CLEANUP;
	}
	if (!SendIoCtl(
		hDevice,
		IOCTL_MEMTEST_FREEMDL,
		&pMdl,
		sizeof pMdl,
		NULL,
		0)) {

		dwLastErr = GetLastError();
		goto CLEANUP;
	}
	if (pMdl == gl_pMdl) gl_pMdl = 0;
	bRet = TRUE;
	dwLastErr = ERROR_SUCCESS;
CLEANUP:
	if (hDevice != INVALID_HANDLE_VALUE) CloseHandle(hDevice);
	SetLastError(dwLastErr);
	return bRet;
}


//++
// Function: KMemTouchTest
//
// 
//--
static BOOL KMemTouchTest()
{
	BOOL		bRet = FALSE;
	DWORD		dwLastErr = STATUS_SUCCESS;
	HANDLE		hDevice = INVALID_HANDLE_VALUE;
	KADRV_KMEMTOUCH_INPUT KmemTouchIn;

	hDevice = OpenSysRegDev();
	if (hDevice == INVALID_HANDLE_VALUE) {
		dwLastErr = GetLastError();
		goto CLEANUP;
	}
	KmemTouchIn.lpStart = gl_lpMappedSystemRegion;
	wprintf(L"\nStart address [0x%16p]", KmemTouchIn.lpStart);
	if (!GetValue(L"%I64i", &KmemTouchIn.lpStart, TRUE)) {
		bRet = TRUE;
		goto CLEANUP;
	}

	KmemTouchIn.cbLength = 0x1000;
	wprintf(L"\nLength [0x%I64x]", KmemTouchIn.cbLength);
	if (!GetValue(L"%I64i", &KmemTouchIn.cbLength, TRUE)) {
		bRet = TRUE;
		goto CLEANUP;
	}

	ULONG Operation = (ULONG) ATRead;
	wprintf(L"\nAccess type");
	wprintf(L"\n    %d - Read", (ULONG) ATRead);
	wprintf(L"\n    %d - Write", (ULONG) ATWrite);
	wprintf(L"\nEnter value [%d] ", Operation);
	if (!GetValue(L"%i", &Operation, TRUE)) {
		bRet = TRUE;
		goto CLEANUP;
	}
	KmemTouchIn.AccessType = (KADRV_ACCESS_TYPE) Operation;

	wprintf(L"\nAbout to call the driver");
	if (!ConfirmOper()) {
		bRet = TRUE;
		goto CLEANUP;
	}
	if (!SendIoCtl(
		hDevice,
		IOCTL_MEMTEST_KMEMTOUCH,
		&KmemTouchIn,
		sizeof KmemTouchIn,
		NULL,
		0)) {

		dwLastErr = GetLastError();
		goto CLEANUP;
	}
CLEANUP:
	if (hDevice != INVALID_HANDLE_VALUE) CloseHandle(hDevice);
	SetLastError(dwLastErr);
	return bRet;
}

//++
// Function: LoadSysRegDrv 
//
// This function is based on the code of w2k_lib.dll written by
// Sven Schreiber and published on the companion CD to
// Undocumented Windows 2000 Secrets.
// 
//--
static BOOL LoadSysRegDrv()
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
		DRV_IMAGE,
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
// Function: LockPageableDrvTest
//
// 
//--
static BOOL LockPageableDrvTest()
{
	BOOL		bRet = FALSE;
	DWORD		dwLastErr = STATUS_SUCCESS;
	HANDLE		hDevice = INVALID_HANDLE_VALUE;

	hDevice = OpenSysRegDev();
	if (hDevice == INVALID_HANDLE_VALUE) {
		dwLastErr = GetLastError();
		goto CLEANUP;
	}
	if (!SendIoCtl(
		hDevice,
		IOCTL_MEMTEST_LOCKPAGEABLE,
		NULL,
		0,
		NULL,
		0)) {

		dwLastErr = GetLastError();
		goto CLEANUP;
	}
	bRet = TRUE;
	dwLastErr = ERROR_SUCCESS;

CLEANUP:
	if (hDevice != INVALID_HANDLE_VALUE) CloseHandle(hDevice);
	SetLastError(dwLastErr);
	return bRet;
}


//++
// Function: MmAllocateMappingAddressTest
//
// 
//--
static BOOL MmAllocateMappingAddressTest()
{
	BOOL		bRet = FALSE;
	DWORD		dwLastErr = STATUS_SUCCESS;
	HANDLE		hDevice = INVALID_HANDLE_VALUE;

	wprintf(L"\nSize ");
	if (!GetValue(L"%I64i", &gl_AllMapIn.Size, FALSE)) {
		bRet = TRUE;
		goto CLEANUP;
	}

	gl_AllMapIn.Address = 0;
	hDevice = OpenSysRegDev();
	if (hDevice == INVALID_HANDLE_VALUE) {
		dwLastErr = GetLastError();
		goto CLEANUP;
	}
	wprintf(L"\nAbout to call the driver");
	if (!ConfirmOper()) {
		bRet = TRUE;
		goto CLEANUP;
	}
	if (!SendIoCtl(
		hDevice,
		IOCTL_MEMTEST_ALLOCMAPADDR,
		&gl_AllMapIn,
		sizeof gl_AllMapIn,
		&gl_AllMapIn,
		sizeof gl_AllMapIn)) {

		dwLastErr = GetLastError();
		goto CLEANUP;
	}
CLEANUP:
	if (!gl_AllMapIn.Address) gl_AllMapIn.Size = 0;
	if (hDevice != INVALID_HANDLE_VALUE) CloseHandle(hDevice);
	SetLastError(dwLastErr);
	return bRet;
}


//++
// Function: MmAllocatePagesForMdlExTest
//--
static BOOL MmAllocatePagesForMdlExTest()
{
	BOOL		bRet = FALSE;
	DWORD		dwLastErr = STATUS_SUCCESS;
	HANDLE		hDevice = INVALID_HANDLE_VALUE;

	hDevice = OpenSysRegDev();
	if (hDevice == INVALID_HANDLE_VALUE) {
		dwLastErr = GetLastError();
		goto CLEANUP;
	}

	KADRV_ALLPAGESFORMDL_INPUT AllPagesMdlIn;

	wprintf(L"\nLow address ");
	if (!GetValue(L"%I64i", &AllPagesMdlIn.LowAddress, FALSE)) {
		bRet = TRUE;
		goto CLEANUP;
	}

	wprintf(L"\nHigh address ");
	if (!GetValue(L"%I64i", &AllPagesMdlIn.HighAddress, FALSE)) {
		bRet = TRUE;
		goto CLEANUP;
	}

	AllPagesMdlIn.SkipBytes = 0x1000;
	wprintf(L"\nSkip bytes [%I64x]", AllPagesMdlIn.SkipBytes);
	if (!GetValue(L"%I64i", &AllPagesMdlIn.SkipBytes, TRUE)) {
		bRet = TRUE;
		goto CLEANUP;
	}

	ULONGLONG TotalBytes;
	wprintf(L"\nTotal bytes ");
	if (!GetValue(L"%I64i", &TotalBytes, FALSE)) {
		bRet = TRUE;
		goto CLEANUP;
	}
	AllPagesMdlIn.TotalBytes = (SIZE_T) TotalBytes;

	AllPagesMdlIn.CacheType = CTCached;
	wprintf(L"\nCache type:");
	wprintf(L"\n    %d - Not cached", CTNonCached);
	wprintf(L"\n    %d - Cached", CTCached);
	wprintf(L"\n    %d - Write combined", CTWriteCombined);
	wprintf(L"\nEnter value: [%d]", AllPagesMdlIn.CacheType);
	if (!GetValue(L"%i", &AllPagesMdlIn.CacheType, TRUE)) {
		bRet = TRUE;
		goto CLEANUP;
	}

	AllPagesMdlIn.Flags = 0;
	wprintf(L"\nFlags [%d]", AllPagesMdlIn.Flags);
	if (!GetValue(L"%i", &AllPagesMdlIn.Flags, TRUE)) {
		bRet = TRUE;
		goto CLEANUP;
	}

	wprintf(L"\nAbout to call the driver");
	if (!ConfirmOper()) {
		bRet = TRUE;
		goto CLEANUP;
	}
	if (!SendIoCtl(
		hDevice,
		IOCTL_MEMTEST_ALLOCPAGESMDL,
		&AllPagesMdlIn,
		sizeof AllPagesMdlIn,
		&gl_pMdl,
		sizeof gl_pMdl)) {

		dwLastErr = GetLastError();
		gl_pMdl = NULL;
		goto CLEANUP;
	}
	dwLastErr = ERROR_SUCCESS;
	bRet = TRUE;
CLEANUP:
	if (hDevice != INVALID_HANDLE_VALUE) CloseHandle(hDevice);
	SetLastError(dwLastErr);
	return bRet;
}


//++
// Function: MmFreeMappingAddressTest
//--
static BOOL MmFreeMappingAddressTest()
{
	BOOL		bRet = FALSE;
	DWORD		dwLastErr = ERROR_SUCCESS;
	HANDLE		hDevice = INVALID_HANDLE_VALUE;

	PVOID pRegion = gl_AllMapIn.Address;
	wprintf(L"\nBase address [%#p] ", pRegion);
	if (!GetValue(L"%I64i", &pRegion, TRUE)) {
		bRet = TRUE;
		goto CLEANUP;
	}

	hDevice = OpenSysRegDev();
	if (hDevice == INVALID_HANDLE_VALUE) {
		dwLastErr = GetLastError();
		goto CLEANUP;
	}

	wprintf(L"\nAbout to call the driver");
	if (!ConfirmOper()) {
		bRet = TRUE;
		dwLastErr = ERROR_SUCCESS;
		goto CLEANUP;
	}
	if (!SendIoCtl(
		hDevice,
		IOCTL_MEMTEST_FREEMAPADDR,
		&pRegion,
		sizeof pRegion,
		NULL,
		0)) {

		dwLastErr = GetLastError();
		goto CLEANUP;
	}
	if (pRegion == gl_AllMapIn.Address) {
		gl_AllMapIn.Address = NULL;
		gl_AllMapIn.Size = 0;
	}
	bRet = TRUE;
	dwLastErr = ERROR_SUCCESS;
CLEANUP:
	if (hDevice != INVALID_HANDLE_VALUE) CloseHandle(hDevice);
	SetLastError(dwLastErr);
	return bRet;
}


//++
// Function: MmFreePagesFromMdlTest
//
// 
//--
static BOOL MmFreePagesFromMdlTest()
{
	BOOL		bRet = FALSE;
	DWORD		dwLastErr = STATUS_SUCCESS;
	HANDLE		hDevice = INVALID_HANDLE_VALUE;

	hDevice = OpenSysRegDev();
	if (hDevice == INVALID_HANDLE_VALUE) {
		dwLastErr = GetLastError();
		goto CLEANUP;
	}

	PVOID lpMdl = gl_pMdl;
	wprintf(L"\nMDL address [0x%16p]", lpMdl);
	if (!GetValue(L"%I64i", &lpMdl, TRUE)) {
		bRet = TRUE;
		goto CLEANUP;
	}

	wprintf(L"\nAbout to call the driver");
	if (!ConfirmOper()) {
		bRet = TRUE;
		goto CLEANUP;
	}
	if (!SendIoCtl(
		hDevice,
		IOCTL_MEMTEST_FREEPAGESMDL,
		&lpMdl,
		sizeof lpMdl,
		NULL,
		0)) {

		dwLastErr = GetLastError();
		goto CLEANUP;
	}
	if (lpMdl == gl_pMdl) {
		gl_pMdl = NULL;
	}
	dwLastErr = ERROR_SUCCESS;
	bRet = TRUE;
CLEANUP:
	if (hDevice != INVALID_HANDLE_VALUE) CloseHandle(hDevice);
	SetLastError(dwLastErr);
	return bRet;
}


//++
// Function: MmAllocateMappingAddressTest
//
// 
//--
static BOOL MmMapLockedPagesSpecifyCacheTest()
{
	BOOL		bRet = FALSE;
	DWORD		dwLastErr = STATUS_SUCCESS;
	HANDLE		hDevice = INVALID_HANDLE_VALUE;

	hDevice = OpenSysRegDev();
	if (hDevice == INVALID_HANDLE_VALUE) {
		dwLastErr = GetLastError();
		goto CLEANUP;
	}

	KADRV_MAPLOCKPAGES_INPUT MapLockPgIn;

	MapLockPgIn.pMdl = gl_pMdl;
	wprintf(L"\nMDL address [%p]", MapLockPgIn.pMdl);
	if (!GetValue(L"%I64i", &MapLockPgIn.pMdl, TRUE)) {
		bRet = TRUE;
		goto CLEANUP;
	}

	MapLockPgIn.AccessMode = AMKernel;
	wprintf(
		L"\nAccess mode (%d = KernelMode, %d = UserMode) [%d]", 
		AMKernel,
		AMUser,
		MapLockPgIn.AccessMode);
	if (!GetValue(L"%i", &MapLockPgIn.AccessMode, TRUE)) {
		bRet = TRUE;
		goto CLEANUP;
	}

	MapLockPgIn.CacheType = CTCached;
	wprintf(
		L"\nCache type (%d = MmNonCached, %d = MmCached, %d = MmWriteCombined) [%d]", 
		CTNonCached,
		CTCached,
		CTWriteCombined,
		MapLockPgIn.CacheType);
	if (!GetValue(L"%i", &MapLockPgIn.CacheType, TRUE)) {
		bRet = TRUE;
		goto CLEANUP;
	}

	MapLockPgIn.pBaseAddress = 0;
	wprintf(L"\nBase address [%p]", MapLockPgIn.pBaseAddress);
	if (!GetValue(L"%I64i", &MapLockPgIn.pBaseAddress, TRUE)) {
		bRet = TRUE;
		goto CLEANUP;
	}

	wprintf(L"\nAbout to call the driver");
	if (!ConfirmOper()) {
		bRet = TRUE;
		goto CLEANUP;
	}
	if (!SendIoCtl(
		hDevice,
		IOCTL_MEMTEST_MAPLOCKPAGES,
		&MapLockPgIn,
		sizeof MapLockPgIn,
		&gl_lpMappedSystemRegion,
		sizeof gl_lpMappedSystemRegion)) {

		dwLastErr = GetLastError();
		gl_lpMappedSystemRegion = 0;
		goto CLEANUP;
	}
CLEANUP:
	if (hDevice != INVALID_HANDLE_VALUE) CloseHandle(hDevice);
	SetLastError(dwLastErr);
	return bRet;
}


//++
// Function: MmMapLockedPagesWithReservedMappingTest
//
// 
//--
static BOOL MmMapLockedPagesWithReservedMappingTest()
{
	BOOL		bRet = FALSE;
	DWORD		dwLastErr = STATUS_SUCCESS;
	HANDLE		hDevice = INVALID_HANDLE_VALUE;

	hDevice = OpenSysRegDev();
	if (hDevice == INVALID_HANDLE_VALUE) {
		dwLastErr = GetLastError();
		goto CLEANUP;
	}

	KADRV_MAPLPAGESRESMAP_INPUT MapLPagesIn;

	MapLPagesIn.MappingAddress = gl_AllMapIn.Address;
	wprintf(L"\nMapping address [0x%16p] ", MapLPagesIn.MappingAddress);
	if (!GetValue(L"%I64i", &MapLPagesIn.MappingAddress, TRUE)) {
		bRet = TRUE;
		goto CLEANUP;
	}

	MapLPagesIn.pMdl = gl_pMdl;
	wprintf(L"\nMDL address [0x%16p] ", MapLPagesIn.pMdl);
	if (!GetValue(L"%I64i", &MapLPagesIn.pMdl, TRUE)) {
		bRet = TRUE;
		goto CLEANUP;
	}

	MapLPagesIn.CacheType = CTCached;
	wprintf(L"\nCache type:");
	wprintf(L"\n    %d - Not cached", CTNonCached);
	wprintf(L"\n    %d - Cached", CTCached);
	wprintf(L"\n    %d - Write combined", CTWriteCombined);
	wprintf(L"\nEnter value: [%d]", MapLPagesIn.CacheType);
	if (!GetValue(L"%i", &MapLPagesIn.CacheType, TRUE)) {
		bRet = TRUE;
		goto CLEANUP;
	}

	wprintf(L"\nAbout to call the driver");
	if (!ConfirmOper()) {
		bRet = TRUE;
		goto CLEANUP;
	}
	if (!SendIoCtl(
		hDevice,
		IOCTL_MEMTEST_MAPLPAGESRESMAP,
		&MapLPagesIn,
		sizeof MapLPagesIn,
		&gl_lpResMappedRegion,
		sizeof gl_lpResMappedRegion)) {

		dwLastErr = GetLastError();
		gl_lpResMappedRegion = NULL;
		goto CLEANUP;
	}
	dwLastErr = ERROR_SUCCESS;
	bRet = TRUE;
CLEANUP:
	if (hDevice != INVALID_HANDLE_VALUE) CloseHandle(hDevice);
	SetLastError(dwLastErr);
	return bRet;
}


//++
// Function: MmProbeAndLockPagesTest
//
// 
//--
static BOOL MmProbeAndLockPagesTest()
{
	BOOL		bRet = FALSE;
	DWORD		dwLastErr = STATUS_SUCCESS;
	HANDLE		hDevice = INVALID_HANDLE_VALUE;

	KADRV_PROBEANDLOCK_INPUT ProbeAndLockIn;
	ProbeAndLockIn.pMdl = gl_pMdl;
	wprintf(L"\nMdl address [%#p] ", ProbeAndLockIn.pMdl);
	if (!GetValue(L"%I64i", &ProbeAndLockIn.pMdl, TRUE)) {
		bRet = TRUE;
		goto CLEANUP;
	}

	ULONG AccessMode;
	wprintf(L"\nAccess mode ");
	wprintf(L"\n    %d - Kernel", (ULONG) AMKernel);
	wprintf(L"\n    %d - User", (ULONG) AMUser);
	wprintf(L"\nEnter value ");
	if (!GetValue(L"%i", &AccessMode, FALSE)) {
		bRet = TRUE;
		goto CLEANUP;
	}
	ProbeAndLockIn.AccessMode = (KADRV_ACCESS_MODE) AccessMode;

	ULONG Operation = (ULONG) ATWrite;
	wprintf(L"\nOperation");
	wprintf(L"\n    %d - Read", (ULONG) ATRead);
	wprintf(L"\n    %d - Write", (ULONG) ATWrite);
	wprintf(L"\nEnter value [%d] ", Operation);
	if (!GetValue(L"%i", &Operation, TRUE)) {
		bRet = TRUE;
		goto CLEANUP;
	}
	ProbeAndLockIn.Operation = (KADRV_ACCESS_TYPE) Operation;

	hDevice = OpenSysRegDev();
	if (hDevice == INVALID_HANDLE_VALUE) {
		dwLastErr = GetLastError();
		goto CLEANUP;
	}
	wprintf(L"\nAbout to call the driver");
	if (!ConfirmOper()) {
		bRet = TRUE;
		goto CLEANUP;
	}
	if (!SendIoCtl(
		hDevice,
		IOCTL_MEMTEST_PROBEANDLOCK,
		&ProbeAndLockIn,
		sizeof ProbeAndLockIn,
		NULL,
		0)) {

		dwLastErr = GetLastError();
		goto CLEANUP;
	}
	if (ProbeAndLockIn.pMdl == gl_pMdl) gl_bMdlLocked = TRUE;
	bRet = TRUE;
CLEANUP:
	if (hDevice != INVALID_HANDLE_VALUE) CloseHandle(hDevice);
	SetLastError(dwLastErr);
	return bRet;
}


//++
// Function: MmUnlockPagesTest
//
// 
//--
static BOOL MmUnlockPagesTest()
{
	BOOL		bRet = FALSE;
	DWORD		dwLastErr = STATUS_SUCCESS;
	HANDLE		hDevice = INVALID_HANDLE_VALUE;

	PVOID pMdl = gl_pMdl;
	wprintf(L"\nMdl address [0x%16p] ", pMdl);
	if (!GetValue(L"%I64i", &pMdl, TRUE)) {
		bRet = TRUE;
		goto CLEANUP;
	}

	hDevice = OpenSysRegDev();
	if (hDevice == INVALID_HANDLE_VALUE) {
		dwLastErr = GetLastError();
		goto CLEANUP;
	}
	wprintf(L"\nAbout to call the driver");
	if (!ConfirmOper()) {
		bRet = TRUE;
		goto CLEANUP;
	}
	if (!SendIoCtl(
		hDevice,
		IOCTL_MEMTEST_UNLOCKPAGES,
		&pMdl,
		sizeof pMdl,
		NULL,
		0)) {

		dwLastErr = GetLastError();
		goto CLEANUP;
	}
	if (pMdl == gl_pMdl) gl_bMdlLocked = FALSE;
	bRet = TRUE;
CLEANUP:
	if (hDevice != INVALID_HANDLE_VALUE) CloseHandle(hDevice);
	SetLastError(dwLastErr);
	return bRet;
}


//++
// Function: MmUnmapReservedMappingTest
//
// 
//--
static BOOL MmUnmapLockedPagesTest()
{
	BOOL		bRet = FALSE;
	DWORD		dwLastErr = STATUS_SUCCESS;
	HANDLE		hDevice = INVALID_HANDLE_VALUE;

	hDevice = OpenSysRegDev();
	if (hDevice == INVALID_HANDLE_VALUE) {
		dwLastErr = GetLastError();
		goto CLEANUP;
	}

	KADRV_UNMAPLOCKPAG_INPUT UnmapLockPagIn;

	UnmapLockPagIn.BaseAddress = gl_lpMappedSystemRegion;
	wprintf(L"\nBase address [0x%16p] ", UnmapLockPagIn.BaseAddress);
	if (!GetValue(L"%I64i", &UnmapLockPagIn.BaseAddress, TRUE)) {
		bRet = TRUE;
		goto CLEANUP;
	}

	UnmapLockPagIn.pMdl = gl_pMdl;
	wprintf(L"\nMDL address [0x%16p] ", UnmapLockPagIn.pMdl);
	if (!GetValue(L"%I64i", &UnmapLockPagIn.pMdl, TRUE)) {
		bRet = TRUE;
		goto CLEANUP;
	}

	wprintf(L"\nAbout to call the driver");
	if (!ConfirmOper()) {
		bRet = TRUE;
		goto CLEANUP;
	}
	if (!SendIoCtl(
		hDevice,
		IOCTL_MEMTEST_UNMAPLOCKPAG,
		&UnmapLockPagIn,
		sizeof UnmapLockPagIn,
		NULL,
		0)) {

		dwLastErr = GetLastError();
		goto CLEANUP;
	}

	// If the address which has been unmapped is the one stored in the static,
	// set the latter to NULL.
	//
	if(UnmapLockPagIn.BaseAddress == gl_lpMappedSystemRegion) gl_lpMappedSystemRegion = NULL;
	dwLastErr = ERROR_SUCCESS;
	bRet = TRUE;
CLEANUP:
	if (hDevice != INVALID_HANDLE_VALUE) CloseHandle(hDevice);
	SetLastError(dwLastErr);
	return bRet;
}


//++
// Function: MmUnmapReservedMappingTest
//
// 
//--
static BOOL MmUnmapReservedMappingTest()
{
	BOOL		bRet = FALSE;
	DWORD		dwLastErr = STATUS_SUCCESS;
	HANDLE		hDevice = INVALID_HANDLE_VALUE;

	hDevice = OpenSysRegDev();
	if (hDevice == INVALID_HANDLE_VALUE) {
		dwLastErr = GetLastError();
		goto CLEANUP;
	}

	KADRV_UNMAPRESMAP_INPUT UnmapResMapIn;

	UnmapResMapIn.BaseAddress = gl_AllMapIn.Address;
	wprintf(L"\nBase address [0x%16p] ", UnmapResMapIn.BaseAddress);
	if (!GetValue(L"%I64i", &UnmapResMapIn.BaseAddress, TRUE)) {
		bRet = TRUE;
		goto CLEANUP;
	}

	UnmapResMapIn.pMdl = gl_pMdl;
	wprintf(L"\nMDL address [0x%16p] ", UnmapResMapIn.pMdl);
	if (!GetValue(L"%I64i", &UnmapResMapIn.pMdl, TRUE)) {
		bRet = TRUE;
		goto CLEANUP;
	}

	wprintf(L"\nAbout to call the driver");
	if (!ConfirmOper()) {
		bRet = TRUE;
		goto CLEANUP;
	}
	if (!SendIoCtl(
		hDevice,
		IOCTL_MEMTEST_UNMAPRESMAP,
		&UnmapResMapIn,
		sizeof UnmapResMapIn,
		NULL,
		0)) {

		dwLastErr = GetLastError();
		goto CLEANUP;
	}

	// If the range which has been unmapped is the one described
	// by gl_AllMapIn, gl_lpResMappedRegion must be set to
	// NULL, because it stores the address at which a mapping
	// has previously been made in the range described by gl_AllMapIn.
	//
	if (UnmapResMapIn.BaseAddress == gl_AllMapIn.Address) gl_lpResMappedRegion = NULL;
	dwLastErr = ERROR_SUCCESS;
	bRet = TRUE;
CLEANUP:
	if (hDevice != INVALID_HANDLE_VALUE) CloseHandle(hDevice);
	SetLastError(dwLastErr);
	return bRet;
}



//++
// Function: MyOpenFile
//
// 
//--
static HANDLE MyOpenFile(
	PWSTR		lpwszFileName,
	DWORD		dwAccess)
{
	wprintf(L"\nabout to open file %s", lpwszFileName);
	if (!ConfirmOper()) {
		SetLastError(ERROR_CANCELLED);
		return INVALID_HANDLE_VALUE;
	}
	HANDLE hRet = CreateFileWr(lpwszFileName, dwAccess, 0, OPEN_EXISTING);
	if (hRet == INVALID_HANDLE_VALUE) return INVALID_HANDLE_VALUE;
	wprintf(L"\nfile %s opened", lpwszFileName);
	return hRet;
}


//++
// Function: OpenFileInterface
//
// 
//--
static BOOL OpenFileInterface()
{
	BOOL		bRet = TRUE;
	DWORD		dwLastErr = ERROR_CANCELLED;

	wcscpy_s(wszFileNameGlob, sizeof wszFileNameGlob / sizeof wszFileNameGlob[0],
		L"memtests.tmp");
	wprintf(L"\nfile name [%s]: ", wszFileNameGlob);
	if (!GetValue(L"%s", wszFileNameGlob, TRUE)) goto CLEANUP;
	wszFileNameGlob[sizeof wszFileNameGlob / sizeof wszFileNameGlob[0] - 1] = L'\0';

	DWORD dwDesiredAccess = GENERIC_READ | GENERIC_WRITE;
	wprintf(L"\ndwDesiredAccess [0x%x]:", dwDesiredAccess);
	wprintf(L"\n    0x%x - GENERIC_READ", GENERIC_READ);
	wprintf(L"\n    0x%x - GENERIC_WRITE", GENERIC_WRITE);
	wprintf(L"\n    0x%x - GENERIC_EXECUTE", GENERIC_EXECUTE);
	wprintf(L"\n");
	if (!GetValue(L"%i", &dwDesiredAccess, TRUE)) goto CLEANUP;
	hFileGlob = MyOpenFile(wszFileNameGlob, dwDesiredAccess);
	if (hFileGlob == INVALID_HANDLE_VALUE) {

		dwLastErr = GetLastError();

		// If cancelled, no error.
		//
		bRet = (GetLastError() == ERROR_CANCELLED);
		goto CLEANUP;
	}
	dwLastErr = ERROR_SUCCESS;

CLEANUP:
	SetLastError(dwLastErr);
	return bRet;
}


//++
// Function: OpenSysRegDev
//
//--
static HANDLE OpenSysRegDev()
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
// Function: PrintMenu
//
// 
//--
static VOID PrintMenu()
{
	wprintf(L"\n\nMemory Allocation\n");
	wprintf(L"\n    l - VirtualAllocEx() test");
	wprintf(L"\n    m - Memory section test");
	wprintf(L"\n    o - Open existing file mapping");
	wprintf(L"\n    v - VirtualProtectEx() test");
	wprintf(L"\n    s - Shrink WS");

	wprintf(L"\n\nMemory Access\n");
	wprintf(L"\n    a - Access region");

	wprintf(L"\n\nTest File Management\n");
	wprintf(L"\n    e - Create test file");
	wprintf(L"\n    c - Close test file");
	wprintf(L"\n    p - Open existing test file");

	wprintf(L"\n\nTest File Access\n");
	wprintf(L"\n    f - File read test");
	wprintf(L"\n    w - File write test");

	wprintf(L"\n\nResource Deallocation\n");
	wprintf(L"\n    r - Release private region");
	wprintf(L"\n    u - Release file mapping");
	wprintf(L"\n    R - Release all");

	wprintf(L"\n\nAccount Privileges");
	wprintf(L"\n    d - Add %s privilege", SE_LOCK_MEMORY_NAME);
	wprintf(L"\n    n - Enable %s privilege", SE_LOCK_MEMORY_NAME);

	wprintf(L"\n");
	wprintf(L"\n    y - System range tests");
	wprintf(L"\n    t - Print status");

	wprintf(L"\n\n    q - Exit\n");
}


//++
// Function: PrintPagStructAddrs 
//
// Print the paging structures addresses for the range
// 
//--
static void PrintPagStructAddrs(
	PBYTE		lpbStart,
	SIZE_T		dwSize )
{
	DWORD_PTR		lpStart, lpLastPage;
	DWORD_PTR		lpFirstPs, lpLastPs;

	lpStart = (DWORD_PTR) lpbStart;
	lpLastPage = lpStart + dwSize - 0x1000;

	// PDPT

	lpFirstPs = VA_TO_PS_ADDR(lpStart, 27, PDPTE_RANGE_START);
	lpLastPs = VA_TO_PS_ADDR(lpLastPage, 27, PDPTE_RANGE_START);
	wprintf(L"\nPDPTE - first: %#p, last: %#p", lpFirstPs, lpLastPs);

	// PD

	lpFirstPs = VA_TO_PS_ADDR(lpStart, 18, PDE_RANGE_START);
	lpLastPs = VA_TO_PS_ADDR(lpLastPage, 18, PDE_RANGE_START);
	wprintf(L"\nPDE   - first: %#p, last: %#p", lpFirstPs, lpLastPs);

	// PT

	lpFirstPs = VA_TO_PS_ADDR(lpStart, 9, PTE_RANGE_START);
	lpLastPs = VA_TO_PS_ADDR(lpLastPage, 9, PTE_RANGE_START);
	wprintf(L"\nPTE   - first: %#p, last: %#p", lpFirstPs, lpLastPs);
}


//++
// Function: PrintStatus
//
// 
//--
static VOID PrintStatus()
{
	wprintf(L"\nMapped region  : 0x%16p - 0x%16p", lpMappedRegionStart, lpMappedRegionEnd);
	wprintf(L"\nPrivate region : 0x%16p - 0x%16p", lpPrivateRegionStart, lpPrivateRegionEnd);
	if ((hFileMapping != INVALID_HANDLE_VALUE) && (hFileMapping != NULL)) {
		wprintf(L"\nFile mapping is open; name: %s", wszMappingName);
	}
	if ((hFileGlob != INVALID_HANDLE_VALUE) && (hFileGlob != NULL)) {
		wprintf(L"\nFile is open; name: %s", wszFileNameGlob);
	}
	wprintf(L"\n");
	wprintf(L"\nMDL                            : 0x%16p - ", gl_pMdl);
	wprintf(L"%slocked", (gl_bMdlLocked ? L"" : L"not "));
	wprintf(L"\nReserved sys region            : 0x%16p - 0x%16p",
		gl_AllMapIn.Address,
		(PBYTE) gl_AllMapIn.Address + gl_AllMapIn.Size);
	wprintf(L"\nMapped addr in reserved region : 0x%16p", gl_lpResMappedRegion);
	wprintf(L"\nMapped sys addr                : 0x%16p", gl_lpMappedSystemRegion);

}


//++
// Function: ProcessOption
//
// 
//--
static BOOL ProcessOption()
{
	switch (wchOption) {
		case L'a':
			return AccessRegionInterface();
			break;
		case L'c':
			return CloseFile(&hFileGlob, TRUE);
			break;
		case L'd':
			return AddPrivilege(SE_LOCK_MEMORY_NAME);
			break;
		case L'f':
			return FileReadTestInterface();
			break;
		case L'e':
			return FileCreateInterface();
			break;
		case L'l':
			return VirtAllocTestInterface();
			break;
		case L'm':
			return FileMappingTestInterface();
			break;
		case L'n':
			return EnablePrivilege(SE_LOCK_MEMORY_NAME);
			break;
		case L'o':
			return FileMappingOpenTestInterface();
			break;
		case L'p':
			return OpenFileInterface();
			break;
		case L'q':
			bExit = TRUE;
			return TRUE;
		case L'r':
			return ReleasePrivateRegion(TRUE);
			break;
		case L'R':
			return ReleaseAll();
			break;
		case L's':
			return ShrinkWs();
			break;
		case L't':
			PrintStatus();
			return TRUE;
			break;
		case L'u':
			return ReleaseFileMapping(TRUE);
			break;
		case L'v':
			return VirtProtTestInterface();
			break;
		case L'w':
			return FileWriteTestInterface();
			break;
		case L'y':
			return SystemRangeSubmenu();
			break;
		default:
			wprintf(L"\ninvalid option: %c", wchOption);
			SetLastError(ERROR_INVALID_PARAMETER);
			return FALSE;
	}
}


//++
// Function: ReleaseAll
//
// 
//--
static BOOL ReleaseAll()
{
	BOOL		bRet;
	DWORD		dwFirstErr = ERROR_SUCCESS;

	bRet = CloseFile(&hFileGlob, FALSE);
	if (!bRet && (dwFirstErr == ERROR_SUCCESS)) {
		dwFirstErr = GetLastError();
	}
	bRet = ReleaseFileMapping(FALSE);
	if (!bRet && (dwFirstErr == ERROR_SUCCESS)) {
		dwFirstErr = GetLastError();
	}
	bRet = ReleasePrivateRegion(FALSE);
	if (!bRet && (dwFirstErr == ERROR_SUCCESS)) {
		dwFirstErr = GetLastError();
	}
	SetLastError(dwFirstErr);
	return bRet;

}


//++
// Function: ReleaseFileMapping
//
// 
//--
static BOOL ReleaseFileMapping(
	BOOL	bInteractive)
{
	DWORD		dwLastErr;
	if (lpMappedRegionStart != NULL) {
		if (bInteractive) {
			wprintf(L"\nabout to call UnmapViewOfFile()");
			if (!ConfirmOper()) {
				SetLastError(ERROR_CANCELLED);
				return TRUE;
			}
		}
		PVOID lpRegionStartCopy = lpMappedRegionStart;
		lpMappedRegionStart = NULL;
		lpMappedRegionEnd = NULL;
		if (!UnmapViewOfFile(lpRegionStartCopy)) {
			dwLastErr = GetLastError();
			wprintf(L"\nUnmapViewOfFile() failed with GetLastError() = %d",
				dwLastErr);
			SetLastError(dwLastErr);
			return FALSE;
		}
	}
	if ((hFileMapping != NULL) && (hFileMapping != INVALID_HANDLE_VALUE)) {
		if (bInteractive) {
			wprintf(L"\nabout to close the mapping handle");
			if (!ConfirmOper()) {
				SetLastError(ERROR_CANCELLED);
				return TRUE;
			}
		}
		HANDLE hMapHndCopy = hFileMapping;
		wszMappingName[0] = L'\0';
		hFileMapping = INVALID_HANDLE_VALUE;
		if (!CloseHandle(hMapHndCopy)) {
			dwLastErr = GetLastError();
			wprintf(L"\nCloseHandle() failed with GetLastError() = %d",
				dwLastErr);
			return FALSE;
		}
	}
	return TRUE;
}


//++
// Function: ReleasePrivateRegion
//
// 
//--
static BOOL ReleasePrivateRegion(
	BOOL		bInteractive)
{
	DWORD		dwLastErr;

	if (lpPrivateRegionStart != NULL) {
		if (bInteractive) {
			wprintf(L"\nabout to release private region");
			if (!ConfirmOper()) {
				SetLastError(ERROR_CANCELLED);
				return TRUE;
			}
		}
		PVOID lpRegionStartCopy = lpPrivateRegionStart;
		lpPrivateRegionStart = NULL;
		lpPrivateRegionEnd = NULL;
		if (!VirtualFreeEx(
			GetCurrentProcess(),
			lpRegionStartCopy,
			0,
			MEM_RELEASE)) {

			dwLastErr = GetLastError();
			wprintf(L"\nVirtualFreeEx() failed, GetLastError() = %d",
				dwLastErr);
			SetLastError(dwLastErr);
			return FALSE;
		}
	}
	return TRUE;
}


//++
// Function: SendIoCtl
//
// 
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
// Function: ShrinkWs
//
// 
//--
static BOOL ShrinkWs()
{
	BOOL	bRet = TRUE;
	DWORD	dwLastErr = ERROR_CANCELLED;

	if (!ConfirmOper()) goto CLEANUP;

	bRet = SetProcessWorkingSetSize(
		GetCurrentProcess(), 
		(SIZE_T) -1, 
		(SIZE_T) -1 );
	if (!bRet) {
		dwLastErr = GetLastError();
		wprintf(L"\nSetProcessWorkingSetSize failed with GetLastError() = %d",
			dwLastErr);
		goto CLEANUP;
	}
	wprintf(L"\nworking set shrunk");
	dwLastErr = ERROR_SUCCESS;
CLEANUP:
	SetLastError(dwLastErr);
	return bRet;
}


//++
// Function: SRSChoice
//
// 
//--
static BOOL SRSChoice(
	PBOOL		bQuit)
{
	*bQuit = FALSE;
	WCHAR wchChoice = _getwch();
	switch (wchChoice) {
		case L'a':
			return MmAllocateMappingAddressTest();
			break;
		case L'b':
			return MmMapLockedPagesSpecifyCacheTest();
			break;
		case L'c':
			return MmAllocatePagesForMdlExTest();
			break;
		case L'd':
			return LockPageableDrvTest();
			break;
		case L'e':
			return MmFreePagesFromMdlTest();
			break;
		case L'f':
			return IoFreeMdlTest();
			break;
		case L'g':
			return CallPageableFunTest();
			break;
		case L'h':
			return MmUnmapLockedPagesTest();
			break;
		case L'i':
			return UnlockPageableDrvTest();
			break;
		case L'k':
			return MmProbeAndLockPagesTest();
			break;
		case L'l':
			return LoadSysRegDrv();
			break;
		case L'm':
			return IoAllocateMdlTest();
			break;
		case L'n':
			return MmUnmapReservedMappingTest();
			break;
		case L'o':
			return MmUnlockPagesTest();
			break;
		case L'p':
			return MmMapLockedPagesWithReservedMappingTest();
			break;
		case L'q':
			*bQuit = TRUE;
			return TRUE;
			break;
		case L'r':
			return MmFreeMappingAddressTest();
			break;
		case L't':
			return KMemTouchTest();
			break;
		case L'u':
			return UnloadSysRegDrv();
			break;
		default:
			wprintf(L"\n\nInvalid key: %c", wchChoice);
			return TRUE;
	}

}


//++
// Function: SystemRangeSubmenu
//
// 
//--
static BOOL SystemRangeSubmenu()
{
	BOOL	bQuit = FALSE;
	do {
		wprintf(L"\n\n\nSystem Range Tests\n\n");
		PrintStatus();
		wprintf(L"\n\nDriver control\n");
		wprintf(L"\n    l - Load kernel allocations driver");
		wprintf(L"\n    u - Unload kernel allocations driver");

		wprintf(L"\n\nTests\n");
		wprintf(L"\n    m - IoAllocateMdl() test");
		wprintf(L"\n    f - IoFreeMdl() test");
		wprintf(L"\n    a - MmAllocateMappingAddress() test");
		wprintf(L"\n    r - MmFreeMappingAddress() test");
		wprintf(L"\n    k - MmProbeAndLockPages() test");
		wprintf(L"\n    o - MmUnLockPages() test");
		wprintf(L"\n    p - MmMapLockedPagesWithReservedMapping() test");
		wprintf(L"\n    n - MmUnmapReservedMapping() test");
		wprintf(L"\n    b - MmMapLockedPagesSpecifyCache() test");
		wprintf(L"\n    h - MmUnmapLockedPages() test");
		wprintf(L"\n    c - MmAllocatePagesForMdlEx() test");
		wprintf(L"\n    e - MmFreePagesFromMdl() test");
		wprintf(L"\n    t - Memory touch test");
		wprintf(L"\n    g - Call pageable function test");
		wprintf(L"\n    d - Lock pageable driver test");
		wprintf(L"\n    i - Unlock pageable driver test");

		wprintf(L"\n\n    q - Quit\n\n");
		SRSChoice(&bQuit);
		if (!bQuit) {
			wprintf (L"\nany key to return to system tests menu...");
			_getwch();
		}
	} while (!bQuit);
	return TRUE;
}


//++
// Function: UnloadSysRegDrv
//
// 
//--
static BOOL UnloadSysRegDrv()
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


//++
// Function: UnlockPageableDrvTest
//
// 
//--
static BOOL UnlockPageableDrvTest()
{
	BOOL		bRet = FALSE;
	DWORD		dwLastErr = STATUS_SUCCESS;
	HANDLE		hDevice = INVALID_HANDLE_VALUE;

	hDevice = OpenSysRegDev();
	if (hDevice == INVALID_HANDLE_VALUE) {
		dwLastErr = GetLastError();
		goto CLEANUP;
	}
	if (!SendIoCtl(
		hDevice,
		IOCTL_MEMTEST_UNLOCKPAGEABLE,
		NULL,
		0,
		NULL,
		0)) {

		dwLastErr = GetLastError();
		goto CLEANUP;
	}
	bRet = TRUE;
	dwLastErr = ERROR_SUCCESS;

CLEANUP:
	if (hDevice != INVALID_HANDLE_VALUE) CloseHandle(hDevice);
	SetLastError(dwLastErr);
	return bRet;
}



//++
// Function: VirtAllocTest
//
// 
//--
static BOOL VirtAllocTest(
	PVOID		lpAddress,
	SIZE_T		Size,
	DWORD		flAllocationType,
	DWORD		flProtect,
	BOOL		bExplicitNumaNode,
	DWORD		dwNumaNode,
	PVOID*		lplpStart,
	PVOID*		lplpEnd)
{
	DWORD		dwLastErr;

	HANDLE hProcess = GetCurrentProcess();

	wprintf(
		L"\nlpAddress        = %#p", lpAddress);
	wprintf(
		L"\ndwSize           = 0x%I64x", Size);
	wprintf(
		L"\nflAllocationType = 0x%x", flAllocationType);
	wprintf(
		L"\nflProtect        = 0x%x", flProtect);
	wprintf(
		L"\nbExplicitNumaNode = %s",
		(bExplicitNumaNode ? L"TRUE" : L"FALSE"));
	if (bExplicitNumaNode) {
		wprintf(
		L"\nnndPreferred      = %d", dwNumaNode);
	}
	if (bExplicitNumaNode) {
		wprintf(L"\n\nabout to call VirtualAllocExNuma()");
	} else {
		wprintf(L"\n\nabout to call VirtualAllocEx()");
	}
	if (!ConfirmOper()) {
		SetLastError(ERROR_CANCELLED);
		return TRUE;
	}


	PVOID lpMem;
	if (bExplicitNumaNode) {
		lpMem = (PBYTE) VirtualAllocExNuma(
			hProcess,
			lpAddress,
			Size,
			flAllocationType,
			flProtect,
			dwNumaNode);
	} else {
		lpMem = (PBYTE) VirtualAllocEx(
			hProcess,
			lpAddress,
			Size,
			flAllocationType,
			flProtect);
	}
	if (lpMem == NULL) {
		dwLastErr = GetLastError();
		wprintf(L"\nVirtualAllocEx() failed with GetLastError() = %d", dwLastErr);
		SetLastError(dwLastErr);
		return FALSE;
	}
	wprintf(L"\n");
	PrintPagStructAddrs((PBYTE) lpMem, dwSize);
	*lplpStart = lpMem;
	*lplpEnd = (PBYTE) lpMem + Size;
	wprintf(L"\n\nstarting address = %#p", *lplpStart);
	wprintf(L"\nending address   = %#p", *lplpEnd);
	SetLastError(ERROR_SUCCESS);
	return TRUE;
}


//++
// Function: VirtAllocTestInterface
//
// 
//--
static BOOL VirtAllocTestInterface()
{
	BOOL		bRet = TRUE;
	DWORD		dwLastErr = ERROR_SUCCESS;
	WCHAR		wchCharVal;

	PVOID lpAddress = 0;
	wprintf(L"\n\nlpAddress [0x%p] = ", lpAddress);
	if (!GetValue(L"%I64i", &lpAddress, TRUE)) goto CLEANUP;

	SIZE_T Size;
	wprintf(L"\ndwSize = ");
	if (!GetValue(L"%I64i", &Size, FALSE)) goto CLEANUP;

	DWORD flAllocationType = MEM_COMMIT | MEM_RESERVE;
	wprintf(L"\nflAllocationType [0x%x]:", flAllocationType);
	wprintf(L"\n    MEM_COMMIT      = 0x%x", MEM_COMMIT);
	wprintf(L"\n    MEM_RESERVE     = 0x%x", MEM_RESERVE);
	wprintf(L"\n    MEM_RESET       = 0x%x", MEM_RESET);
	wprintf(L"\n    MEM_LARGE_PAGES = 0x%x", MEM_LARGE_PAGES);
	wprintf(L"\n    MEM_PHYSICAL    = 0x%x", MEM_PHYSICAL);
	wprintf(L"\n    MEM_TOP_DOWN    = 0x%x", MEM_TOP_DOWN);
	wprintf(L"\n\n");
	if (!GetValue(L"%i", &flAllocationType, TRUE)) goto CLEANUP;

	DWORD flProtect = PAGE_READWRITE;
	wprintf(L"\nflProtect [0x%x]:", flProtect);
	wprintf(L"\n"
		L"    PAGE_READONLY          = 0x%x", PAGE_READONLY);
	wprintf(L"\n"
		L"    PAGE_READWRITE         = 0x%x", PAGE_READWRITE);
	wprintf(L"\n"
		L"    PAGE_WRITECOPY         = 0x%x", PAGE_WRITECOPY);
	wprintf(L"\n"
		L"    PAGE_EXECUTE_READ      = 0x%x", PAGE_EXECUTE_READ);
	wprintf(L"\n"
		L"    PAGE_EXECUTE_READWRITE = 0x%x", PAGE_EXECUTE_READWRITE);
	wprintf(L"\n"
		L"    PAGE_EXECUTE_WRITECOPY = 0x%x", PAGE_EXECUTE_WRITECOPY);
	wprintf(L"\n"
		L"    PAGE_EXECUTE           = 0x%x", PAGE_EXECUTE);
	wprintf(L"\n"
		L"    PAGE_NOACCESS          = 0x%x", PAGE_NOACCESS);
	wprintf(L"\n\n");
	if (!GetValue(L"%i", &flProtect, TRUE)) goto CLEANUP;

	BOOL bExplicitNumaNode = FALSE;
	DWORD dwNumaNode = 0;
	wchCharVal = 'n';
	wprintf(L"\n");
	if (!GetKey(&wchCharVal, L"specify NUMA node", TRUE, L"?", L"yn")) goto CLEANUP;
	switch (wchCharVal) {
		case L'y':
			bExplicitNumaNode = TRUE;
			wprintf(L"\nnndPreferred: ");
			if (!GetValue(L"%d", &dwNumaNode, FALSE)) goto CLEANUP;
			break;
		case L'n':
			bExplicitNumaNode = FALSE;
			break;
	}
	if (!VirtAllocTest(
		lpAddress,
		Size,
		flAllocationType,
		flProtect,
		bExplicitNumaNode,
		dwNumaNode,
		&lpPrivateRegionStart,
		&lpPrivateRegionEnd
		)) {
			bRet = FALSE;
			dwLastErr = GetLastError();
	}
	dwLastErr = STATUS_SUCCESS;

CLEANUP:
	SetLastError(dwLastErr);
	return bRet;

}


//++
// Function: VirtProtTestInterface
//
// 
//--
static BOOL VirtProtTestInterface()
{
	BOOL	bRet = TRUE;
	DWORD	dwLastErr = ERROR_CANCELLED;

	PVOID	lpAddress;
	wprintf(L"\naddress: ");
	if (!GetValue(L"%I64i", &lpAddress, FALSE)) goto CLEANUP;

	SIZE_T	Size;
	wprintf(L"\nsize: ");
	if (!GetValue(L"%I64i", &Size, FALSE)) goto CLEANUP;

	DWORD flNewProtect;
	wprintf(L"\nflNewProtect: ");
	if(!GetValue(L"%I64i", &flNewProtect, FALSE)) goto CLEANUP;

	wprintf(L"\nsubregion      : %#p - %#p", lpAddress, (PBYTE) lpAddress + Size);
	wprintf(L"\nnew protection : %x", flNewProtect);
	wprintf(L"\nabout to call VirtualProtectEx()...");
	if (!ConfirmOper()) {
		goto CLEANUP;
	}
	DWORD flOldProtect;
	if (!VirtualProtectEx(
		GetCurrentProcess(),
		lpAddress,
		Size,
		flNewProtect,
		&flOldProtect)) {

		dwLastErr = GetLastError();
		bRet = FALSE;
		wprintf(L"\nVirtualProtectEx() failed with GetLastError() = %d",
			dwLastErr);
		goto CLEANUP;
	}
	wprintf(L"\nold protection : %x", flOldProtect);
	ConfirmOper();
	dwLastErr = ERROR_SUCCESS;
CLEANUP:
	SetLastError(dwLastErr);
	return bRet;
}


//++
// Function: WriteFileWr
//
// 
//--
static BOOL WriteFileWr(
	HANDLE		hFile,
	LPVOID		lpBuffer,
	DWORD		cbBCount)
{
	DWORD		dwLastErr;

	DWORD dwWrBytes;
	if (!WriteFile(
		hFile,
		lpBuffer,
		cbBCount,
		&dwWrBytes,
		NULL)) {

		dwLastErr = GetLastError();
		wprintf(L"\nWriteFile failed with GetLastError() = %d", dwLastErr);
		SetLastError(dwLastErr);
		return FALSE;
	}
	if (dwWrBytes != cbBCount) {
		wprintf(L"\nWriteFile failed to write %d bytes; written bytes count: %d",
			cbBCount,
			dwWrBytes);
		SetLastError(ERROR_WRITE_FAULT);
		return FALSE;
	}
	return TRUE;
}


