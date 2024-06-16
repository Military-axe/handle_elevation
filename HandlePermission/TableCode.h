#pragma once

#include "header.h"
#include "HandleTableEntry.h"
#include "ObjectHeader.h"

class TableCode
{
private:
    uint64_t table_code;

private:
    bool find_process_by_pid_level1(uint32_t pid, PHANDLE_TABLE_ENTRY *handle_table_entry);
    bool find_process_by_pid_level2(uint32_t pid, PHANDLE_TABLE_ENTRY *handle_table_entry);

public:
    TableCode(uint64_t _table_code);

    bool find_process_by_pid(uint32_t pid, PHANDLE_TABLE_ENTRY *handle_table_entry);
};

TableCode::TableCode(uint64_t _table_code)
{
    this->table_code = _table_code;
}

bool TableCode::find_process_by_pid_level1(uint32_t pid, PHANDLE_TABLE_ENTRY *handle_table_entry)
{
    uint64_t object_header, id;
    HandleTableEntry node;
    const uint16_t page_handle_max = 256;
    PHANDLE_TABLE_ENTRY handle_table_entry_array = reinterpret_cast<PHANDLE_TABLE_ENTRY>(this->table_code);

    for (uint16_t i = 0; i < page_handle_max; i++)
    {
        node.set_handle_table_entry(&handle_table_entry_array[i]);
        if (node.is_invalid())
        {
            continue;
        }

        object_header = node.to_object_header();
        if (!ObjectHeader::is_process(object_header))
        {
            continue;
        }

        id = ObjectHeader::get_process_id(object_header);
        if (!id)
        {
            // 获取失败
            continue;
        }

        if (id != pid)
        {
            continue;
        }

        *handle_table_entry = node.out();

        return true;
    }

    return false;
}

bool TableCode::find_process_by_pid_level2(uint32_t pid, PHANDLE_TABLE_ENTRY *handle_table_entry)
{
    const uint64_t table_code_mask = 0xFFFFFFFFFFFFFFF8;
    uint64_t *tables = reinterpret_cast<uint64_t *>(this->table_code & table_code_mask);

    for (uint16_t i = 0; tables[i] != 0; i++)
    {
        // 切换单层遍历，需要重新设置table_code
        this->table_code = tables[i];
        
        if (find_process_by_pid_level1(pid, handle_table_entry))
        {
            kprintf("[+] Handle Permission: found it\n");
            return true;
        }
    }

    return false;
}

/// @brief 
/// 查找tablecode对应的句柄表中，是否有pid对应的进程句柄, 
/// 如果有则将对应句柄的handle_table_entry地址通过参数handle_table_entry指针传出函数，
/// 并且返回true, 否则返回false
/// @param pid 
/// @param handle_table_entry 
/// @return 成功返回true，失败返回false
bool TableCode::find_process_by_pid(uint32_t pid, PHANDLE_TABLE_ENTRY *handle_table_entry)
{
    const uint8_t table_code_level_mask = 3;
    const uint8_t level1 = 0;
    const uint8_t level2 = 1;

    switch (this->table_code & table_code_level_mask)
    {
    case level1:
        return find_process_by_pid_level1(pid, handle_table_entry);
    case level2:
        return find_process_by_pid_level2(pid, handle_table_entry);
    default:
        return false;
    }
}