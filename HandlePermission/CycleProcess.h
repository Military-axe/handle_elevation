#pragma once

#include "header.h"

class CycleProcess
{
private:
    bool is_begin;
    PEPROCESS begin_eprocess;
    PEPROCESS now_eprocess;

public:
    CycleProcess(void);
    PEPROCESS next(void);

    uint64_t get_object_table(void);
    bool cycle_end(void);
};

/// @todo 给peprocess添加引用计数
CycleProcess::CycleProcess(void)
{
    is_begin = true;
    begin_eprocess = PsGetCurrentProcess();
    now_eprocess = begin_eprocess;
}

/// @brief 获取进程链表中下一个进程的eprocess地址
/// @return 返回一个eprocess地址
/// @todo 需要给新的eprocess的引用计数+1，老的eprocess引用计数-1
PEPROCESS CycleProcess::next(void)
{
    const uint64_t active_process_link_offset = 0x448;
    uint64_t new_eprocess = 0;
    PLIST_ENTRY next_active_process = nullptr;

    next_active_process = reinterpret_cast<PLIST_ENTRY>(reinterpret_cast<uint64_t>(this->now_eprocess) + active_process_link_offset);
    new_eprocess = reinterpret_cast<uint64_t>(next_active_process->Flink) - active_process_link_offset;

    // TODO: 检查new_eprocess是否合法

    this->now_eprocess = reinterpret_cast<PEPROCESS>(new_eprocess);

    // 是否完成一个循环，完成则设置标记位

    if (this->begin_eprocess == this->now_eprocess)
    {
        this->is_begin = false;
    }
    else
    {
        this->is_begin = true;
    }

    return this->now_eprocess;
}

uint64_t CycleProcess::get_object_table(void)
{
    const uint64_t object_table_offset = 0x570;
    uint64_t object_table_addr = 0, object_table = 0;

    object_table_addr = reinterpret_cast<uint64_t>(this->now_eprocess) + object_table_offset;
    object_table = *reinterpret_cast<uint64_t *>(object_table_addr);

    return object_table;
}

/// @brief 判断是否完成一次完整的循环
/// @param
/// @return 是则返回true，否则返回false
bool CycleProcess::cycle_end(void)
{
    if (this->begin_eprocess == this->now_eprocess && this->is_begin == false)
    {
        return true;
    }

    return false;
}