#pragma once
#include <ntifs.h>
#include <stdint.h>

#define kprintf(...) \
    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, __VA_ARGS__))

void driver_unload(PDRIVER_OBJECT driver_object);
void handle_permission_lower_test(void);
void thread_test(void* context);

extern "C" uint8_t *PsGetProcessImageFileName(PEPROCESS);

typedef struct _HANDLE_TABLE_ENTRY
{
    UINT64 reverse1;
    UINT32 granted_access_bits;
    UINT32 reverse2;
} HANDLE_TABLE_ENTRY, *PHANDLE_TABLE_ENTRY;