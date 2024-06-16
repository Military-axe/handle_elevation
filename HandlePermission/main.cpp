#include "header.h"
#include "TableCode.h"
#include "CycleProcess.h"
#include "HandleTableEntry.h"

// 全局变量
HANDLE g_thread_handle = nullptr;
bool g_terminate_flag = false;
KSPIN_LOCK g_spin_lock;

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object, PUNICODE_STRING register_path)
{
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(register_path);
    driver_object->DriverUnload = driver_unload;

    // 初始化锁
    KeInitializeSpinLock(&g_spin_lock);

    status = PsCreateSystemThread(&g_thread_handle, DELETE, nullptr, nullptr, nullptr, thread_test, nullptr);
    if (!NT_SUCCESS(status))
    {
        kprintf("[!] Handle Permission: Create System Thread failed.\n");
        status = STATUS_UNSUCCESSFUL;
    }

    return status;
}

void driver_unload(PDRIVER_OBJECT driver_object)
{
    KIRQL irql;

    UNREFERENCED_PARAMETER(driver_object);

    // 设置标志位跳出死循环

    KeAcquireSpinLock(&g_spin_lock, &irql);
    g_terminate_flag = true;
    KeReleaseSpinLock(&g_spin_lock, irql);

    // 等待线程结束, 减少线程对象计数

    KeAcquireSpinLock(&g_spin_lock, &irql);
    KeWaitForSingleObject(g_thread_handle, Executive, KernelMode, false, nullptr);
    ObDereferenceObject(g_thread_handle);
    KeReleaseSpinLock(&g_spin_lock, irql);

    kprintf("[+] Handle Permission: Driver unload\n");
}

void thread_test(void *context)
{
    LARGE_INTEGER delay;
    KIRQL irql;

    UNREFERENCED_PARAMETER(context);
    // 设置延迟时间为5秒
    delay.QuadPart = -3 * 1000 * 1000 * 10; // -5秒，单位为100ns

    while (true)
    {
        // 当全局标志位被设置成true, 跳出死循环
        KeAcquireSpinLock(&g_spin_lock, &irql);
        if (g_terminate_flag)
        {
            break;
        }
        KeReleaseSpinLock(&g_spin_lock, irql);

        handle_permission_lower_test();

        // 暂停线程
        KeDelayExecutionThread(KernelMode, false, &delay);
    }

    // 终止线程
    PsTerminateSystemThread(STATUS_SUCCESS);
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
        if (!pid)
        {
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
    }
}