#pragma once
#include "header.h"

class ObjectHeader
{
public:
    static bool is_process(uint64_t addr);
    static uint32_t get_process_id(uint64_t header);
};

/// @brief 判断这个object对象是否是进程对象
/// @param addr obejct_header地址
/// @return 如果是则返回true,否则返回false
bool ObjectHeader::is_process(uint64_t addr)
{
    const uint8_t process_type = 7;
    const uint8_t move_left_8bit = 8;
    const uint8_t last_byte_mask = 0xff;
    const uint8_t type_index_offset = 0x18;
    const uint64_t addr_limit = 0xffffff0000000000;

    // TODO: 不同系统版本需要修改
    const uint8_t header_cookie = 0x21;
    uint8_t type_index = 0, addr_byte = 0;

    // TODO: 使用MmGetSystemRoutineAddress获取nt!ObHeaderCookie

    if (addr >= 0xffffff0000000000) {
        return false;
    }

    addr_byte = (addr >> move_left_8bit) & last_byte_mask;
    type_index = *reinterpret_cast<uint8_t *>(addr + type_index_offset);
    type_index = type_index ^ addr_byte ^ header_cookie;

    if (type_index == process_type)
    {
        return true;
    }

    return false;
}

/// @brief 获取进程对象的id
/// @param header obejct_header地址
/// @return 如果获取成功则返回进程pid，否则返回0
uint32_t ObjectHeader::get_process_id(uint64_t header)
{
    const uint8_t object_body_offset = 0x30;
    PEPROCESS eprocess = nullptr;
    HANDLE pid;

    eprocess = reinterpret_cast<PEPROCESS>(header + object_body_offset);
    pid = PsGetProcessId(eprocess);

    if (pid != nullptr)
    {
        return reinterpret_cast<uint32_t>(pid);
    }

    return 0;
}