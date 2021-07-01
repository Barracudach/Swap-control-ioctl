#pragma once

#include "ntstructs.h"
#include "ntapi.h"


#define ioctl_copy_memory CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1001, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define ioctl_allocate_virtual_memory CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1002, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define ioctl_get_module_base CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1003, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define ioctl_protect_virutal_memory CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1004, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define ioctl_repair CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1005, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)



typedef unsigned int       uint32_t;
typedef unsigned long long uint64_t;

typedef struct _k_get_base_module_request {
	ULONG pid;
	ULONGLONG handle;
	WCHAR name[260];
} k_get_base_module_request, * pk_get_base_module_request;

typedef struct _k_alloc_mem_request {
	ULONG pid, allocation_type, protect;
	ULONGLONG addr;
	SIZE_T size;
} k_alloc_mem_request, * pk_alloc_mem_request;


typedef struct _k_rw_request {
	uint32_t src_pid;
	uint32_t dst_pid;
	uint64_t src_addr;
	uint64_t dst_addr;
	uint32_t size;
} k_rw_request, * pk_rw_request;

typedef struct _k_protect_mem_request {
	ULONG pid, protect;
	ULONGLONG addr;
	SIZE_T size;
} k_protect_mem_request, * pk_protect_mem_request;