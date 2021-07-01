#pragma once

#include "tools.h"

ULONGLONG get_module_handle(ULONG pid, LPCWSTR module_name) {
	PEPROCESS target_proc;
	ULONGLONG base = 0;
	if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pid, &target_proc)))
		return 0;

	KeAttachProcess((PKPROCESS)target_proc);

	PPEB peb = PsGetProcessPeb(target_proc);
	if (!peb)goto end;

	if (!peb->Ldr || !peb->Ldr->Initialized)goto end;

	UNICODE_STRING module_name_unicode;
	RtlInitUnicodeString(&module_name_unicode, module_name);
	for (PLIST_ENTRY list = peb->Ldr->InLoadOrderModuleList.Flink;
		list != &peb->Ldr->InLoadOrderModuleList;
		list = list->Flink) {
		PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(list, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		if (RtlCompareUnicodeString(&entry->BaseDllName, &module_name_unicode, TRUE) == 0) {
			base = (ULONGLONG)entry->DllBase;
			goto end;
		}
	}

end:
	KeDetachProcess();
	ObDereferenceObject(target_proc);
	return base;
}

NTSTATUS copy_memory(PEPROCESS src_proc, PEPROCESS target_proc, PVOID src, PVOID dst, SIZE_T size) {
	SIZE_T bytes;
	return MmCopyVirtualMemory(src_proc, src, target_proc, dst, size, UserMode, &bytes);
}



const UCHAR HkpDetour[] = {
		0x90, 0x90, 0xff, 0x25, 0x00, 0x00, 0x00, 0x00
};
#define INTERLOCKED_EXCHANGE_SIZE	(16ul)
_IRQL_requires_max_(APC_LEVEL)
static NTSTATUS HkpReplaceCode16Bytes(
	_In_ PVOID	Address,
	_In_ PUCHAR	Replacement
)
{
	//
	// ѕроверьте правильность выравнивани€. cmpxchg16b работает только с 16-байтовыми выровненными адресами.
	//
	if ((ULONG64)Address != ((ULONG64)Address & ~0xf))
	{
		return STATUS_DATATYPE_MISALIGNMENT;
	}

	//
	// —оздайте список дескрипторов пам€ти дл€ отображени€ пам€ти только дл€ чтени€ (или RX) как дл€ чтени€-записи.
	//
	PMDL Mdl = IoAllocateMdl(Address, INTERLOCKED_EXCHANGE_SIZE, FALSE, FALSE, NULL);
	if (Mdl == NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	//
	// —делайте страницы пам€ти посто€нными в ќ«” и убедитесь, что они не выгружаютс€.
	//
	__try
	{
		MmProbeAndLockPages(Mdl, KernelMode, IoReadAccess);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		IoFreeMdl(Mdl);

		return STATUS_INVALID_ADDRESS;
	}

	//
	// —оздайте новое отображение дл€ посто€нной пам€ти.
	//
	PLONG64 RwMapping = (PLONG64)MmMapLockedPagesSpecifyCache(
		Mdl,
		KernelMode,
		MmNonCached,
		NULL,
		FALSE,
		NormalPagePriority
	);

	if (RwMapping == NULL)
	{
		MmUnlockPages(Mdl);
		IoFreeMdl(Mdl);

		return STATUS_INTERNAL_ERROR;
	}

	//
	// ”становите новую защиту страницы сопоставлени€ на чтение и запись, чтобы изменить ее.
	//
	NTSTATUS Status = MmProtectMdlSystemAddress(Mdl, PAGE_READWRITE);
	if (!NT_SUCCESS(Status))
	{
		MmUnmapLockedPages(RwMapping, Mdl);
		MmUnlockPages(Mdl);
		IoFreeMdl(Mdl);

		return Status;
	}

	LONG64 PreviousContent[2];
	PreviousContent[0] = RwMapping[0];
	PreviousContent[1] = RwMapping[1];

	//
	// «амените 16 байтов кода, использу€ созданное отображение чтени€-записи.
	// Ѕлокированное сравнение и обмен (cmpxchg16b) используетс€, чтобы избежать проблем с параллелизмом.
	//
	InterlockedCompareExchange128(
		RwMapping,
		((PLONG64)Replacement)[1],
		((PLONG64)Replacement)[0],
		PreviousContent
	);

	//
	// Unlock and unmap pages, free MDL. 
	//
	MmUnmapLockedPages(RwMapping, Mdl);
	MmUnlockPages(Mdl);
	IoFreeMdl(Mdl);

	return STATUS_SUCCESS;
}


PVOID locate_shellcode(PDRIVER_OBJECT object, PVOID jmp_func)
{ 
	PVOID trampoline = (PVOID)object->MajorFunction[IRP_MJ_DEVICE_CONTROL];
	while (memcmp(trampoline, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 10))
	{
		(*(PBYTE*)&trampoline)++;
	}


    UCHAR DetourBytes[INTERLOCKED_EXCHANGE_SIZE];
	RtlCopyMemory(DetourBytes, HkpDetour, sizeof(HkpDetour));
	RtlCopyMemory(DetourBytes + sizeof(HkpDetour), &jmp_func, sizeof(PVOID));

	if (HkpReplaceCode16Bytes(trampoline, DetourBytes) == STATUS_SUCCESS)
	{
		return trampoline;
	}
	else return NULL;


}

extern "C" POBJECT_TYPE* IoDriverObjectType;
NTSTATUS SwapControl_f(UNICODE_STRING driver_name, PVOID hook_func, PVOID* original, BOOL write_trampoline)
{
	PVOID hook = hook_func;
	PDRIVER_OBJECT object = NULL;
	
	NTSTATUS _status = ObReferenceObjectByName(&driver_name, OBJ_CASE_INSENSITIVE, 0, 0, *IoDriverObjectType, KernelMode, 0, (PVOID*)&object);

	if (NT_SUCCESS(_status))
	{
		if (write_trampoline)
		{
			if (!(hook = locate_shellcode(object, hook)))
			{
				DBG("locate_shellcode error\n");
				return STATUS_UNSUCCESSFUL;
			}
		}
		PVOID old = object->MajorFunction[IRP_MJ_DEVICE_CONTROL];
		if (hook_func != *original)*original = old;


		InterlockedExchangePointer((PVOID*)&object->MajorFunction[IRP_MJ_DEVICE_CONTROL], (PVOID)hook);

		DBG("%wZ swapped(0x%I64x to 0x%I64x)\n", driver_name, old, hook);
		ObDereferenceObject(object);
		return STATUS_SUCCESS;
	}
	else
	{
		DBG("failed to get %wZ: %p !\n", &driver_name, _status);
		return STATUS_UNSUCCESSFUL;
	}
}