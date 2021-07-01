#pragma once

#include "ntstructs.h"

extern "C"
NTKERNELAPI
NTSTATUS 
ObReferenceObjectByName(IN PUNICODE_STRING ObjectName,
	IN ULONG Attributes,
	IN PACCESS_STATE PassedAccessState, 
	IN ACCESS_MASK DesiredAccess, 
	IN POBJECT_TYPE ObjectType, 
	IN KPROCESSOR_MODE AccessMode,
	IN OUT PVOID ParseContext,
	OUT PVOID* Object);

extern "C"
NTKERNELAPI
PVOID
NTAPI
RtlFindExportedRoutineByName(
	PVOID ImageBase,
	PCCH RoutineName
);

extern "C"
NTKERNELAPI
NTSTATUS
ZwQuerySystemInformation(
	ULONG InfoClass,
	PVOID Buffer,
	ULONG Length,
	PULONG ReturnLength
);

extern "C"
NTKERNELAPI
PVOID
NTAPI
PsGetProcessWow64Process(_In_ PEPROCESS Process);

extern "C"
NTKERNELAPI
NTSTATUS
NTAPI
MmCopyVirtualMemory(
	_In_ PEPROCESS FromProcess,
	_In_ PVOID FromAddress,
	_In_ PEPROCESS ToProcess,
	_Out_ PVOID ToAddress,
	_In_ SIZE_T BufferSize,
	_In_ KPROCESSOR_MODE PreviousMode,
	_Out_ PSIZE_T NumberOfBytesCopied
);

extern "C"
NTKERNELAPI
PPEB
PsGetProcessPeb(
	IN PEPROCESS Process
);


extern "C"
NTSYSAPI
NTSTATUS
NTAPI
ZwProtectVirtualMemory(
	__in HANDLE ProcessHandle,
	__inout PVOID* BaseAddress,
	__inout PSIZE_T RegionSize,
	__in ULONG NewProtect,
	__out PULONG OldProtect
);


EXTERN_C NTSYSAPI
PIMAGE_NT_HEADERS
NTAPI
RtlImageNtHeader(IN PVOID   ModuleAddress);

NTKERNELAPI
PVOID
PsGetProcessSectionBaseAddress(
	__in PEPROCESS Process
);