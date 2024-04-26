#include "header.h"

VOID DriveUnload(PDRIVER_OBJECT pDriver)
{
    kprintf("Unload");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING pRegPath)
{
    PEPROCESS eprocess = NULL;
    NTSTATUS  status   = PsLookupProcessByProcessId((HANDLE)0x1470, &eprocess);
    if (!NT_SUCCESS(status)) {
        kprintf("Open process  unsuccessfully!\r\n");
        return STATUS_UNSUCCESSFUL;
    }
    ObDereferenceObject(eprocess);
    ProtectProcessHandleByEprocess(eprocess);

    pDriver->DriverUnload = DriveUnload;

    return STATUS_SUCCESS;
}