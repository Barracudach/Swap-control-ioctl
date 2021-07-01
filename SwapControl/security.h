#include <ntdef.h>
#include <ntifs.h>
#include <ntddk.h>
#include <WinDef.h>

#include "ntapi.h"
#include "common.h"


void clearCache(UNICODE_STRING DriverName, ULONG timeDateStamp);

NTSTATUS ClearUnloadedDriver(_In_ PUNICODE_STRING DriverName, _In_ BOOLEAN AccquireResource);
NTSTATUS FindMmDriverData(VOID);

NTSTATUS clearTableEntry(PDRIVER_OBJECT driver, wchar_t* driverName);



BOOLEAN bDataCompare(const BYTE* pData, const BYTE* bMask, const char* szMask);
UINT64 FindPattern(UINT64 dwAddress, UINT64 dwLen, BYTE* bMask, char* szMask);

void EraseHeader();