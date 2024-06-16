#include "header.h"
#include "TableCode.h"
#include "CycleProcess.h"
#include "HandleTableEntry.h"

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object, PUNICODE_STRING register_path)
{
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(register_path);

    handle_permission_lower_test();

    driver_object->DriverUnload = driver_unload;

    return status;
}

void driver_unload(PDRIVER_OBJECT driver_object)
{
    UNREFERENCED_PARAMETER(driver_object);
    kprintf("[+] Handle Permission: Driver unload\n");
}

void handle_permission_lower_test(void)
{
    CycleProcess cycle_process;

    // 需要保护的进程id
    uint64_t object_pid = 6988;
    PEPROCESS eprocess = nullptr;
    uint64_t object_table = 0, _table_code = 0;
    const uint8_t table_code_offset = 0x8;
    PHANDLE_TABLE_ENTRY handle_table_entry = nullptr;
    HandleTableEntry handle_table_entry_instance;
    uint8_t *image_name = nullptr;
    HANDLE pid = nullptr;

    DbgBreakPoint();

    while (!cycle_process.cycle_end())
    {
        eprocess = cycle_process.next();

        image_name = PsGetProcessImageFileName(eprocess);
        kprintf("[+] Handle Permission: cycle to %s; eprocess %p\n", image_name, eprocess);

        pid = PsGetProcessId(eprocess);
        if (!pid){
            kprintf("[!] Handle Permission: process %s pid is nullptr\n", image_name);
            continue;
        }

        object_table = cycle_process.get_object_table();
        if (!object_table)
        {
            kprintf("[!] Handle Permission: process %s object table is nullptr\n", image_name);
            continue;
        }

        _table_code = *reinterpret_cast<uint64_t *>(object_table + table_code_offset);
        TableCode table_code(_table_code);

        __try
        {
            if (table_code.find_process_by_pid(object_pid, &handle_table_entry))
            {
                kprintf("[+] Handle Permission: Find the process id %llx handle\n", object_pid);

                handle_table_entry_instance.set_handle_table_entry(handle_table_entry);

                /**
                 * 取消句柄的内存读写权限
                 * TODO:
                 * - [ ]: 修改数据时需要加锁，或者提升中断级别
                 */
                handle_table_entry_instance.lower_read_permission();
                handle_table_entry_instance.lower_write_permission();
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            kprintf(
                "[+] Get the EXCEPTION_EXECUTE_HANDLER\n"
                "    table_code ==> %llx\n"
                "    object_table ==> %llx\n",
                _table_code,
                object_table
            );

            DbgBreakPoint();
            continue;
        }
    }
}