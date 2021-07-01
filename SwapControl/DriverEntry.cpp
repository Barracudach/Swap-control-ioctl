#include "ntapi.h"
#include "ioctl.h"
#include <stdarg.h>
#include "Wdf.h"
#include "common.h"
#include <time.h>

#include "tools.h"
NTSTATUS Sleep(LONGLONG ms_duration);


#define complete_request(irp,type,status)\
irp->IoStatus.Status = status;\
irp->IoStatus.Information = sizeof(type);\
IoCompleteRequest(irp, IO_NO_INCREMENT);\
return status;

PDRIVER_DISPATCH SpeedFanControlOriginal = 0;
NTSTATUS SpeedFanControl(PDEVICE_OBJECT device, PIRP irp)
{
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);

	switch (stack->Parameters.DeviceIoControl.IoControlCode) {

	case ioctl_copy_memory: {
		DBG("ioctl_copy_memory\n");
		pk_rw_request in = (pk_rw_request)irp->AssociatedIrp.SystemBuffer;
		PEPROCESS src_proc;
		PEPROCESS dst_proc;
		NTSTATUS status;
		status = PsLookupProcessByProcessId((HANDLE)in->src_pid, &src_proc);
		status |= PsLookupProcessByProcessId((HANDLE)in->dst_pid, &dst_proc);
		if (NT_SUCCESS(status)) {
			status = copy_memory(src_proc, dst_proc, (PVOID)in->src_addr, (PVOID)in->dst_addr, in->size);
			ObfDereferenceObject(dst_proc);
			ObfDereferenceObject(src_proc);
			//	if (!NT_SUCCESS(status))DbgPrint("[DRIVER] copy_memory error");
		}
		complete_request(irp,k_rw_request, status);
	} break;

	case ioctl_allocate_virtual_memory: {
		DBG("ioctl_allocate_virtual_memory\n");
		//	DbgPrint("[DRIVER] ioctl_allocate_virtual_memory");
		pk_alloc_mem_request in = (pk_alloc_mem_request)irp->AssociatedIrp.SystemBuffer;
		PEPROCESS target_proc;
		NTSTATUS status;
		status = PsLookupProcessByProcessId((HANDLE)in->pid, &target_proc);
		if (NT_SUCCESS(status)) {
			KAPC_STATE apc;
			KeStackAttachProcess(target_proc, &apc);
			status = ZwAllocateVirtualMemory(ZwCurrentProcess(), (PVOID*)&in->addr, 0, &in->size,
				in->allocation_type, in->protect);
			KeUnstackDetachProcess(&apc);
			ObfDereferenceObject(target_proc);
		}
		complete_request(irp, k_alloc_mem_request, status);
	} break;

	case ioctl_protect_virutal_memory: {
		DBG("ioctl_protect_virutal_memory\n");
		pk_protect_mem_request in = (pk_protect_mem_request)irp->AssociatedIrp.SystemBuffer;
		PEPROCESS target_proc;
		NTSTATUS status;
		status = PsLookupProcessByProcessId((HANDLE)in->pid, &target_proc);
		if (NT_SUCCESS(status)) {
			KAPC_STATE apc;
			ULONG old_protection;
			KeStackAttachProcess(target_proc, &apc);
			status = ZwProtectVirtualMemory(ZwCurrentProcess(), (PVOID*)&in->addr, &in->size, in->protect, &old_protection);
			KeUnstackDetachProcess(&apc);
			in->protect = old_protection;
			ObfDereferenceObject(target_proc);
		}
		complete_request(irp, k_protect_mem_request, status);
	} break;
	case ioctl_get_module_base: {
		DBG("ioctl_get_module_base\n");
		pk_get_base_module_request in = (pk_get_base_module_request)irp->AssociatedIrp.SystemBuffer;
		ULONGLONG handle = get_module_handle(in->pid, in->name);
		in->handle = handle;
		complete_request(irp, k_get_base_module_request, STATUS_SUCCESS);
	} break;

	case ioctl_repair: {
		SwapControl_f(RTL_CONSTANT_STRING(L"\\Driver\\SpeedFan"), (PVOID)SpeedFanControlOriginal, (PVOID*)&SpeedFanControlOriginal, FALSE);
	} break;
	}


	return SpeedFanControlOriginal(device, irp);
}


NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path)
{

	UNREFERENCED_PARAMETER(driver_object);
	UNREFERENCED_PARAMETER(registry_path);

	SwapControl_f(RTL_CONSTANT_STRING(L"\\Driver\\SpeedFan"), (PVOID)SpeedFanControl, (PVOID*)&SpeedFanControlOriginal, TRUE);

	return STATUS_SUCCESS;
}



NTSTATUS Sleep(LONGLONG ms_duration)
{
	LARGE_INTEGER delay;
	delay.QuadPart = -1 * (10000 * ms_duration);
	return KeDelayExecutionThread(KernelMode, FALSE, &delay);
}