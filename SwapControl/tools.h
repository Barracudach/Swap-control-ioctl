#pragma once


#include "ntstructs.h"
#include "ntapi.h"
#include "common.h"

ULONGLONG get_module_handle(ULONG pid, LPCWSTR module_name);
NTSTATUS copy_memory(PEPROCESS src_proc, PEPROCESS target_proc, PVOID src, PVOID dst, SIZE_T size);
NTSTATUS SwapControl_f(UNICODE_STRING driver_name, PVOID hook_func, PVOID* original, BOOL write_trampoline);