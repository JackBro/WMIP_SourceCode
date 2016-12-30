/*


=======================================================================

MemColls
========

Companion test program to What Makes It Page?

Copyright (c), 2012 by Enrico Martignetti - All rights reserved.

Program to test in-paging collisions.

=======================================================================

*/
#include <windows.h>


#include <stdio.h>
#include <wchar.h>
#include <conio.h>



#define PGM_NAME			L"MemColls"
#define VER_MAJ				L"1"
#define VER_MIN				L"0"


// Commands
//
#define CMD_ACCESS_RANGE	L'd'
#define CMD_CHANGE_RANGE_PROT	L'h'
#define CMD_CLEAR_BRK		L'c'
#define CMD_DECOMMIT		L'o'
#define CMD_FREE			L'f'
#define CMD_FREE_SYNC		L'y'
#define CMD_QUIT			L'q'
#define CMD_READ			L'r'
#define CMD_REALLOC			L'a'
#define CMD_SET_BRK			L't'
#define CMD_SHRINK			L's'
#define CMD_WRITE			L'w'


// Access codes for StartAccess()
//
#define ACC_READ			1
#define ACC_WRITE			2

#define ERR_MSG_SIZE		501

typedef struct _MEM_ACCESS_PARAMS {
	HANDLE	hHeap;
	INT		AccessCode;
	PVOID	lpStart;
	SIZE_T	Size;
} MEM_ACCESS_PARAMS, *PMEM_ACCESS_PARAMS;

typedef struct _MEM_DECOMMIT_PARAMS {
	HANDLE	hHeap;
	PVOID	lpStart;
	SIZE_T	Size;
} MEM_DECOMMIT_PARAMS, *PMEM_DECOMMIT_PARAMS;

typedef struct _MEM_PCHANGE_PARAMS {
	HANDLE	hHeap;
	PVOID	lpStart;
	SIZE_T	Size;
	DWORD	dwNewProt;
} MEM_PCHANGE_PARAMS, *PMEM_PCHANGE_PARAMS;

BOOL			bBrk = FALSE;
BYTE			DummyByte;
DWORD			dwInitialProt;
PVOID			lpMem;
DWORD64			Size64;

static DWORD WINAPI AccessMemory(
	  LPVOID		AccessCode );

static DWORD WINAPI ChangeProtection(
	LPVOID		lpParam);

static BOOL CreateThrWr(
	LPTHREAD_START_ROUTINE	lpStartAddress,
	LPVOID					lpParameter);

static DWORD WINAPI DecommitMemory(
	  LPVOID		lpParam );

static DWORD WINAPI FreeMemory(
   LPVOID		lpParam );

static VOID PrintCmdList();

static VOID PrintHelp();

static BOOL ProcessCommandLoop();

static BOOL ProcessCommand(
	WCHAR		Cmd,
	PBOOL		lpbEndLoop);

static PVOID PrvAlloc(
	DWORD64		Size64, 
	DWORD		dwProtection);

static BOOL StartAccess(
	INT		AccessCode,
	PVOID	lpStart,
	SIZE_T	Size);

static BOOL StartDecommit(
	PVOID		lpStart,
	SIZE_T		Length);

static BOOL StartFree();

static BOOL StartPchange(
	PVOID		lpStart,
	SIZE_T		Length,
	DWORD		dwNewProt);

static BOOL StartPrChange(
	DWORD		dwProtect);

static BOOL StartRangeAccess();

static BOOL StartRangeDecommit();

static BOOL StartRangePchange();

static BOOL StartShrink();

static BOOL XtractParams(
	INT			ArgC,
	LPWSTR		lpwszArgV[]);


int wmain(int ArgC, wchar_t *lpwszArgV[])
{
	if (!XtractParams(ArgC, lpwszArgV)) return GetLastError();
	lpMem = PrvAlloc(Size64, dwInitialProt);
	if (lpMem == NULL) return GetLastError();
	if (!ProcessCommandLoop()) return GetLastError();
	return ERROR_SUCCESS;
}


//++
// Function: AccessMemory
//
// Memory access function.
//
// Before returning, frees the parameters instance.
//--
static DWORD WINAPI AccessMemory(
	  LPVOID		lpParam )
{
	DWORD				dwLastErr;
	DWORD				dwThrId = GetCurrentThreadId();
	PMEM_ACCESS_PARAMS	lpAccParams = (PMEM_ACCESS_PARAMS) lpParam;
	PBYTE				lpPage;


	// Uncomment the following lines to experiment with I/O priority, e.g.
	// to cause asynchronous handling of collided page faults.

	//if (!SetThreadPriority(
	//	GetCurrentThread(),
	//	THREAD_MODE_BACKGROUND_BEGIN))
	//{
	//	dwLastErr = GetLastError();
	//	wprintf(L"\nThread %d - Failed to set background mode with GetLastError() = %d",
	//		dwThrId,
	//		dwLastErr);
	//} else {
	//	wprintf(L"\nThread %d - Background mode set",
	//		dwThrId );
	//}


	PBYTE lpEnd = (PBYTE) lpAccParams->lpStart + lpAccParams->Size;
	if (lpAccParams->AccessCode == ACC_READ) {
		wprintf(L"\nThread %d - Reading memory from %#p to %#p...", 
			dwThrId,
			lpAccParams->lpStart,
			lpEnd);
	} else {
		wprintf(L"\nThread %d - Writing memory from %#p to %#p...", 
			dwThrId,
			lpAccParams->lpStart,
			lpEnd);
	}
	if (bBrk) {
		DebugBreak();
	}
	for(lpPage = (PBYTE) lpAccParams->lpStart; lpPage < lpEnd; lpPage += 0x1000) {
		if (lpAccParams->AccessCode == ACC_READ) {
			DummyByte = *lpPage;
		} else {
			*((DWORDLONG *) lpPage) = (DWORDLONG) lpPage;
		}
	}
	HeapFree(lpAccParams->hHeap, 0, lpAccParams);
	wprintf(L"\nThread %d - Finished accessing memory", dwThrId);

	return ERROR_SUCCESS;
}


//++
// Function: ChangeProtection
//
// Changes the region protection
//
// 
//--
static DWORD WINAPI ChangeProtection(
	LPVOID		lpParam)
{
	DWORD		dwLastErr;
	DWORD		dwOldProtect;
	DWORD		dwThrId = GetCurrentThreadId();


	PMEM_PCHANGE_PARAMS lpPchgParams = (PMEM_PCHANGE_PARAMS) lpParam;
	PBYTE lpEnd = (PBYTE) lpPchgParams->lpStart + lpPchgParams->Size;
	wprintf(L"\nThread %d - Setting protection to 0x%x from %#p to %#p...", 
			dwThrId,
			lpPchgParams->dwNewProt,
			lpPchgParams->lpStart,
			lpEnd);
	if (bBrk) {
		DebugBreak();
	}
	if (!VirtualProtectEx(
		GetCurrentProcess(),
		lpPchgParams->lpStart,
		lpPchgParams->Size,
		lpPchgParams->dwNewProt,
		&dwOldProtect)) {

		dwLastErr = GetLastError();
		wprintf(L"\nThread %d - VirtualProtectEx() failed with GetLastError() = %d",
			dwThrId,
			dwLastErr );
		return dwLastErr;
	}
	wprintf(L"\nThread %d - Memory protection set to %d", dwThrId, lpPchgParams->dwNewProt);

	return ERROR_SUCCESS;
}


//++
// Function: CreateThrWr
//
// Wrapper for CreateThread
//
// 
//--
static BOOL CreateThrWr(
	LPTHREAD_START_ROUTINE	lpStartAddress,
	LPVOID					lpParameter)
{
	DWORD		dwLastErr;
	HANDLE		hThread;

	hThread = CreateThread(
		NULL,
		0,
		lpStartAddress,
		lpParameter,
		0,
		NULL);
	if (hThread == NULL) {
		dwLastErr = GetLastError();
		wprintf(
			L"\nCreateThread failed with GetLastError() = %d",
			dwLastErr);
		SetLastError(dwLastErr);
		return FALSE;
	}

	CloseHandle(hThread);
	return TRUE;

}


//++
// Function: DecommitMemory
//
// Memory decommit function.
//
// Before returning, frees the parameters instance.
//--
static DWORD WINAPI DecommitMemory(
	  LPVOID		lpParam )
{
	DWORD					dwLastErr;
	DWORD					dwThrId = GetCurrentThreadId();
	PMEM_DECOMMIT_PARAMS	lpDecParams = (PMEM_DECOMMIT_PARAMS) lpParam;

	PBYTE lpEnd = (PBYTE) lpDecParams->lpStart + lpDecParams->Size;
	wprintf(L"\nThread %d - Decommitting memory from %#p to %#p...", 
			dwThrId,
			lpDecParams->lpStart,
			lpEnd);
	if (bBrk) {
		DebugBreak();
	}
	if (!VirtualFreeEx(
		GetCurrentProcess(),
		lpDecParams->lpStart,
		lpDecParams->Size,
		MEM_DECOMMIT)) {
		dwLastErr = GetLastError();
		wprintf(L"\nThread %d - VirtualFreeEx failed with GetLastError() = %d",
			dwThrId,
			dwLastErr);
	}
	HeapFree(lpDecParams->hHeap, 0, lpDecParams);
	wprintf(L"\nThread %d - Finished decomitting memory", dwThrId);

	return ERROR_SUCCESS;
}



//++
// Function: FreeMemory
//
// Frees the memory region.
//--
static DWORD WINAPI FreeMemory(
   LPVOID		lpParam )
{
	DWORD		dwLastErr = ERROR_SUCCESS;
	DWORD		dwThrId = GetCurrentThreadId();

	if (bBrk) {
		DebugBreak();
	}
	if (!VirtualFreeEx(
		GetCurrentProcess(),
		lpParam,
		0,
		MEM_RELEASE)) {
		dwLastErr = GetLastError();
		wprintf(L"\n Thread %d - VirtualFreeEx failed with GetLAstError() = %d",
			dwThrId,
			dwLastErr);
		return dwLastErr;
	}
	wprintf(L"\n Thread %d - Memory freed", dwThrId);
	return ERROR_SUCCESS;
}


//++
// Function: PrintCmdList
//
// 
//--
static VOID PrintCmdList()
{
	wprintf(L"\n\n");
	wprintf(L"\n%c - Read entire region", CMD_READ);
	wprintf(L"\n%c - Write entire region", CMD_WRITE);
	wprintf(L"\n%c - Access subrange", CMD_ACCESS_RANGE);
	wprintf(L"\n%c - Change subrange protection", CMD_CHANGE_RANGE_PROT);
	wprintf(L"\n%c - Free memory", CMD_FREE);
	wprintf(L"\n%c - Decommit memory", CMD_DECOMMIT);
	wprintf(L"\n%c - Synchronous free memory", CMD_FREE_SYNC);
	wprintf(L"\n%c - Shrink working set", CMD_SHRINK);
	wprintf(L"\n%c - Reallocate memory", CMD_REALLOC);
	wprintf(L"\n%c - Activate breaking mode", CMD_SET_BRK);
	wprintf(L"\n%c - Deactivate breaking mode", CMD_CLEAR_BRK);
	wprintf(L"\n%c - Quit", CMD_QUIT);
	wprintf(L"\n\n");
	wprintf(L"\nRegion   : 0x%16p - 0x%16p", lpMem, ((PBYTE) lpMem) + Size64);
	wprintf(L"\nSize     : 0x%I64x (%I64d)", Size64, Size64);
	wprintf(L"\nBreaking : %s", bBrk ? L"active" : L"not active");
	wprintf(L"\n\n");

	return;
}
	


//++
// Function: 
//
// 
//--
static VOID PrintHelp()
{
	wprintf(L"\n\n");
	wprintf(L"Usage:");
	wprintf(L"\n\n");
	wprintf(L"    " PGM_NAME L" alloc_size alloc_protection");
	wprintf(L"\n\n");
	wprintf(L"    alloc_size       : allocation size in bytes");
	wprintf(L"\n\n");
	wprintf(L"    alloc_protection : protection, e.g.:");
	wprintf(L"\n");
	wprintf(L"        PAGE_READWRITE = 0x%x", PAGE_READWRITE);
	wprintf(L"\n");
	wprintf(L"        PAGE_READONLY  = 0x%x", PAGE_READONLY);
	wprintf(L"\n");
	wprintf(L"        See also flProtect of VirtualAllocEx()");
	wprintf(L"\n");
	return;
}


//++
// Function: ProcessCommand
//
// Executes a command.
//
// Sets *lpbEndLoop if the command causes the command loop to end.
//
// Returns FALSE on errors.
//
// 
//--
static BOOL	ProcessCommand(
	WCHAR		Cmd,
	PBOOL		lpbEndLoop)
{
	switch(Cmd) {
		case CMD_READ:
			return StartAccess(ACC_READ, lpMem, Size64);
			break;
		case CMD_ACCESS_RANGE:
			return StartRangeAccess();
			break;
		case CMD_WRITE:
			return StartAccess(ACC_WRITE, lpMem, Size64);
			break;
		case CMD_CHANGE_RANGE_PROT:
			return StartRangePchange();
			break;
		case CMD_FREE:
			return StartFree();
			break;
		case CMD_DECOMMIT:
			return StartRangeDecommit();
			break;
		case CMD_FREE_SYNC:
			FreeMemory(lpMem);

			// Let the command loop go on regadless of any errors
			return TRUE;
		case CMD_SHRINK:
			return StartShrink();
			break;
		case CMD_REALLOC:
			lpMem = PrvAlloc(Size64, dwInitialProt);
			if (lpMem == NULL) return FALSE;
			break;
		case CMD_SET_BRK:
			bBrk = TRUE;
			break;
		case CMD_CLEAR_BRK:
			bBrk = FALSE;
			break;
		case CMD_QUIT:
			*lpbEndLoop = TRUE;
			break;
		default:
			wprintf(L"\nInvalid command: %c", Cmd);
	}
	return TRUE;
}


//++
// Function: ProcessCommand
//
// Executes the loop which reads the command character from
// the keyboard and executes it in a separate thread.
//--
static BOOL ProcessCommandLoop()
{
	BOOL bEndLoop = FALSE;
	do {
		PrintCmdList();
		WCHAR Cmd = _getwch();
		if (!ProcessCommand(Cmd, &bEndLoop)) {
			return FALSE;
		}
	}
	while (!bEndLoop);
	return TRUE;
}


//++
// Function: PrvAlloc
//
// Reserves and commits the memory range.
//--
static PVOID PrvAlloc(
	DWORD64		Size64, 
	DWORD		dwProtection)
{
	DWORD		dwLastErr;

	wprintf(L"\nAllocating 0x%I64x (%I64d) bytes with protection 0x%x...", Size64, Size64, dwProtection);

	PBYTE lpRegion = (PBYTE) VirtualAllocEx(
		GetCurrentProcess(),
		NULL,
		Size64,
		MEM_COMMIT | MEM_RESERVE,
		dwProtection);
	if (lpRegion == NULL) {
		dwLastErr = GetLastError();
		wprintf(
			L"\nVirtualAlloc() failed w. GetLastError() = %d",
			dwLastErr);
		SetLastError(dwLastErr);
		return NULL;
	}
	PBYTE lpEnd = lpRegion + Size64;
	wprintf(L"\nAllocated region: 0x%16p - 0x%16p", lpRegion, lpEnd);
	return lpRegion;
}


//++
// Function: ShrinkWs
//
// Shrinks the working set
// 
//--
static DWORD WINAPI ShrinkWs(
	LPVOID		lpParam)
{
	DWORD		dwLastErr;
	DWORD		dwThrId = GetCurrentThreadId();
	
	// Dummy assignment, to avoid warning C4100
	//
	lpParam = 0;
	if (!SetProcessWorkingSetSizeEx(
		GetCurrentProcess(),
		(SIZE_T) -1,
		(SIZE_T) -1,
		0)) {
		dwLastErr = GetLastError();
		wprintf(L"\nThread %d - SetProcessWorkingSetSizeEx() failed with GetLastError() = %d",
			dwThrId,
			dwLastErr);
		return dwLastErr;
	}
	wprintf(L"\nThread %d - Working set shrinked", dwThrId);
	return ERROR_SUCCESS;
}


//++
// Function: StartAccess
//
// Starts a thread executing a loop which touches the pages of the memory region,
// reading or writing, according to AccessCode.
// 
//--
static BOOL StartAccess(
	INT		AccessCode,
	PVOID	lpStart,
	SIZE_T	Size)
{
	DWORD dwLastErr;
	HANDLE hHeap = GetProcessHeap();
	if (hHeap == NULL){
		dwLastErr = GetLastError();
		wprintf(L"\nGetProcessHeap failed with GetLastError() = %d", dwLastErr);
		SetLastError(dwLastErr);
		return FALSE;
	}
	PMEM_ACCESS_PARAMS lpAccParams = (PMEM_ACCESS_PARAMS) HeapAlloc(hHeap, 0, sizeof MEM_ACCESS_PARAMS);
	if (lpAccParams == NULL){
		dwLastErr = GetLastError();
		wprintf(L"\nHeapAlloc failed with GetLastError() = %d", dwLastErr);
		SetLastError(dwLastErr);
		return FALSE;
	}
	lpAccParams->hHeap = hHeap;	// Heap handle passed to the new thread which will free the memory.
	lpAccParams->AccessCode = AccessCode;
	lpAccParams->lpStart = lpStart;
	lpAccParams->Size = Size;
	BOOL bRetVal;
	if (!CreateThrWr(AccessMemory, lpAccParams)) {
		dwLastErr = GetLastError();
		wprintf(L"\nFailed to start thread for memory access with AccessCode = %d", AccessCode);
		if (lpAccParams != NULL) HeapFree(hHeap, 0, lpAccParams);
		bRetVal = FALSE;
		SetLastError(dwLastErr);
		goto CLEANUP;
	}
	bRetVal = TRUE;
CLEANUP:
	return bRetVal;
	
}


//++
// Function: StartDecommit
//
// Starts a thread wich decommits the memory region specified
// by the input parameters
// 
//--
static BOOL StartDecommit(
	PVOID		lpStart,
	SIZE_T		Length)
{
	DWORD dwLastErr;
	HANDLE hHeap = GetProcessHeap();
	if (hHeap == NULL){
		dwLastErr = GetLastError();
		wprintf(L"\nGetProcessHeap failed with GetLastError() = %d", dwLastErr);
		SetLastError(dwLastErr);
		return FALSE;
	}
	PMEM_DECOMMIT_PARAMS lpDecParams = (PMEM_DECOMMIT_PARAMS) HeapAlloc(hHeap, 0, sizeof MEM_DECOMMIT_PARAMS);
	if (lpDecParams == NULL){
		dwLastErr = GetLastError();
		wprintf(L"\nHeapAlloc failed with GetLastError() = %d", dwLastErr);
		SetLastError(dwLastErr);
		return FALSE;
	}
	lpDecParams->hHeap = hHeap;	// Heap handle passed to the new thread which will free the memory.
	lpDecParams->lpStart = lpStart;
	lpDecParams->Size = Length;
	BOOL bRetVal;
	if (!CreateThrWr(DecommitMemory, lpDecParams)) {
		dwLastErr = GetLastError();
		wprintf(L"\nFailed to start thread for memory decommit");
		if (lpDecParams != NULL) HeapFree(hHeap, 0, lpDecParams);
		bRetVal = FALSE;
		SetLastError(dwLastErr);
		return FALSE;
	}
	return TRUE;
	
}


//++
// Function: StartFree
//
// Starts a thread wich frees the memory region
// 
//--
static BOOL StartFree()
{
	DWORD dwLastErr;
	if (!CreateThrWr(FreeMemory, lpMem)) {
		dwLastErr = GetLastError();
		wprintf(L"\nFailed to start thread for memory freeing");
		SetLastError(dwLastErr);
		return FALSE;
	}
	return TRUE;
}


//++
// Function: StartPchange
//
// Starts a thread wich changes the protection of a memory region
// as specified by the input params.
// 
//--
static BOOL StartPchange(
	PVOID		lpStart,
	SIZE_T		Length,
	DWORD		dwNewProt)
{
	DWORD dwLastErr;
	HANDLE hHeap = GetProcessHeap();
	if (hHeap == NULL){
		dwLastErr = GetLastError();
		wprintf(L"\nGetProcessHeap failed with GetLastError() = %d", dwLastErr);
		SetLastError(dwLastErr);
		return FALSE;
	}
	PMEM_PCHANGE_PARAMS lpPchgParams = (PMEM_PCHANGE_PARAMS) HeapAlloc(hHeap, 0, sizeof MEM_PCHANGE_PARAMS);
	if (lpPchgParams == NULL){
		dwLastErr = GetLastError();
		wprintf(L"\nHeapAlloc failed with GetLastError() = %d", dwLastErr);
		SetLastError(dwLastErr);
		return FALSE;
	}
	lpPchgParams->hHeap = hHeap;	// Heap handle passed to the new thread which will free the memory.
	lpPchgParams->lpStart = lpStart;
	lpPchgParams->Size = Length;
	lpPchgParams->dwNewProt = dwNewProt;
	if (!CreateThrWr(ChangeProtection, lpPchgParams)) {
		dwLastErr = GetLastError();
		wprintf(L"\nFailed to start thread for memory protection change");
		if (lpPchgParams != NULL) HeapFree(hHeap, 0, lpPchgParams);
		SetLastError(dwLastErr);
		return FALSE;
	}
	return TRUE;
	
}


//++
// Function: StartRangeAccess
//
// Starts a thread which accesses a range of the memory region.
// 
//--
static BOOL StartRangeAccess()
{
	INT			AccessCode;
	PVOID		lpStart;
	SIZE_T		Length;

	wprintf(L"\n");
	wprintf(L"\nstart address: ");
	if (!wscanf_s(L"%I64i", (PLONGLONG) &lpStart)) {
		lpStart = 0;

		// drain stdin
		while(getwc(stdin) != L'\n'){}
	}
	if (!lpStart) {
		wprintf(L"\ninvalid address");

		// return TRUE because we don't want to end the command loop
		return TRUE;
	}
	wprintf(L"\nlength: ");
	if (!wscanf_s(L"%I64i", &Length)) {
		Length = 0;

		// drain stdin
		while(getwc(stdin) != L'\n'){}
	}
	if (!Length) {
		wprintf(L"\ninvalid length");
		return TRUE;
	}
	wprintf(L"\naccess type (%d = read, %d = write): ", ACC_READ, ACC_WRITE);
	if (!wscanf_s(L"%i", &AccessCode)) {
		AccessCode = 0;

		// drain stdin
		while(getwc(stdin) != L'\n'){}
	}
	if (!AccessCode) {
		wprintf(L"\ninvalid access code");
		return TRUE;
	}
	return StartAccess(AccessCode, lpStart, Length);


}


//++
// Function: StartRangeDecommit
//
// Prompts for the parameters to decommit a memory range and
// starts a thread wich performs the operation.
// 
//--
static BOOL StartRangeDecommit()
{
	SIZE_T		Length;
	PVOID		lpStart;


	wprintf(L"\n");
	wprintf(L"\nstart address: ");
	if (!wscanf_s(L"%I64i", (PLONGLONG) &lpStart)) {
		lpStart = 0;

		// drain stdin
		while(getwc(stdin) != L'\n'){}
	}
	if (!lpStart) {
		wprintf(L"\ninvalid address");

		// return TRUE because we don't want to end the command loop
		return TRUE;
	}
	wprintf(L"\nlength: ");
	if (!wscanf_s(L"%I64i", &Length)) {
		Length = 0;

		// drain stdin
		while(getwc(stdin) != L'\n'){}
	}
	if (!Length) {
		wprintf(L"\ninvalid length");
		return TRUE;
	}
	return StartDecommit(lpStart, Length);

}


//++
// Function: StartRangePchange
//
// Prompts for parameters to change protection of a memory
// range and starts a thread which performs the change.
// 
//--
static BOOL StartRangePchange()
{
	DWORD		dwProt;
	SIZE_T		Length;
	PVOID		lpStart;


	wprintf(L"\n");
	wprintf(L"\nstart address: ");
	if (!wscanf_s(L"%I64i", (PLONGLONG) &lpStart)) {
		lpStart = 0;

		// drain stdin
		while(getwc(stdin) != L'\n'){}
	}
	if (!lpStart) {
		wprintf(L"\ninvalid address");

		// return TRUE because we don't want to end the command loop
		return TRUE;
	}
	wprintf(L"\nlength: ");
	if (!wscanf_s(L"%I64i", &Length)) {
		Length = 0;

		// drain stdin
		while(getwc(stdin) != L'\n'){}
	}
	if (!Length) {
		wprintf(L"\ninvalid length");
		return TRUE;
	}
	wprintf(L"\nprotection: ");
	if (!wscanf_s(L"%i", &dwProt)) {
		while(getwc(stdin) != L'\n'){}
		wprintf(L"\ninvalid protection");
		return TRUE;
	}
	return StartPchange(lpStart, Length, dwProt);

}


//++
// Function: StartShrink
//
// Starts a thread which shrinks the workingset
// 
//--
static BOOL StartShrink()
{
	DWORD dwLastErr;
	if (!CreateThrWr(ShrinkWs, NULL)) {
		dwLastErr = GetLastError();
		wprintf(L"\nFailed to start thread for working set shrinking");
		SetLastError(dwLastErr);
		return FALSE;
	}
	return TRUE;
}

//++
// Function: 
//
// 
//--
static BOOL XtractParams(
	INT			ArgC,
	LPWSTR		lpwszArgV[])
{
	INT		Converted;
	if (ArgC < 2) {
		PrintHelp();
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	if (*lpwszArgV[1] == L'?') {
		PrintHelp();
		SetLastError(ERROR_SUCCESS);
		return FALSE;
	}
	if (wcslen(lpwszArgV[1]) == 2) {
		if (*(lpwszArgV[1] + 1) == L'?') {
			PrintHelp();
			SetLastError(ERROR_SUCCESS);
			return FALSE;
		}
	}
	if (ArgC < 3) {
		wprintf(L"\n\nError, too few parameters. " PGM_NAME L" /? for help.\n\n");
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	Converted = swscanf_s(lpwszArgV[1], L"%I64i", &Size64);
	if (!Converted || !Size64) {
		wprintf(L"\n\nError, invalid size: %s. " PGM_NAME L" /? for help.\n\n", lpwszArgV[1]);
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	Converted = swscanf_s(lpwszArgV[2], L"%i", &dwInitialProt);
	if (!Converted) {
		wprintf(L"\n\nError, invalid protection: %s. " PGM_NAME L" /? for help.\n\n", lpwszArgV[2]);
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	return TRUE;

}
