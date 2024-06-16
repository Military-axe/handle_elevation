#pragma once

#include "header.h"

class HandleTableEntry
{
private:
    PHANDLE_TABLE_ENTRY data;

public:
    HandleTableEntry(void);

    void set_handle_table_entry(PHANDLE_TABLE_ENTRY data);
    uint64_t to_object_header(void);
    void lower_read_permission(void);
    void lower_write_permission(void);
    bool is_invalid(void);
    PHANDLE_TABLE_ENTRY out(void);
};

/// @brief HandleTableEntry类构造函数, 将data字段置空
/// @param  
HandleTableEntry::HandleTableEntry(void)
{
    this->data = nullptr;
}

void HandleTableEntry::set_handle_table_entry(PHANDLE_TABLE_ENTRY data)
{
    this->data = data;
}

uint64_t HandleTableEntry::to_object_header(void)
{
    return ((data->reverse1 >> 0x10) & 0xFFFFFFFFFFFFFFF0) + 0xFFFF000000000000;
}

void HandleTableEntry::lower_read_permission()
{
    const uint32_t read_permission = 0x10;
    data->granted_access_bits &= ~read_permission;
}

void HandleTableEntry::lower_write_permission()
{
    const uint32_t write_permission = 0x20;
    data->granted_access_bits &= ~write_permission;
}

bool HandleTableEntry::is_invalid()
{
    if (!data->reverse1)
    {
        return true;
    }

    return false;
}

PHANDLE_TABLE_ENTRY HandleTableEntry::out(void)
{
    return this->data;
}