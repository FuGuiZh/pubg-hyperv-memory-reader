#include "platform/windows/process_lookup.hpp"
#include "hypervisor/hypercall.hpp"
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <algorithm>
#include <iostream>
#include <string>
#include <vector>
#include <unordered_set>
#include <sstream>

namespace {
template<class T>
bool ReadExact(T& value, uint64_t address, uint64_t cr3) {
    T complete{};
    if (hypercall::read_guest_virtual_memory(&complete, address, cr3, sizeof(complete)) != sizeof(complete))
        return false;
    value = complete;
    return true;
}

bool ReadExact(void* buffer, uint64_t address, uint64_t cr3, size_t bytes) {
    return hypercall::read_guest_virtual_memory(buffer, address, cr3, bytes) == bytes;
}

}

uint64_t GetProcessCr3(uint64_t target_pid, uint64_t head, Cr3LookupDiagnostics* diagnostics) {
    Cr3LookupDiagnostics local{};
    auto& d = diagnostics ? *diagnostics : local;
    d = {};
    d.target_pid = target_pid; d.head = head;
    d.stage = "CR3_INPUT";
    if (!target_pid || !head) return 0;
    d.stage = "CR3_CALLER_ROOT";
    d.caller_cr3 = hypercall::read_guest_cr3();
    if (!(d.caller_cr3 & 0x000FFFFFFFFFF000ULL)) return 0;
    const auto read = [&](uint64_t& value, uint64_t address, const char* stage) {
        d.stage = stage; d.address = address; d.requested = sizeof(value); ++d.reads;
        uint64_t complete = 0;
        d.received = hypercall::read_guest_virtual_memory(&complete, address, d.caller_cr3, sizeof(complete));
        if (d.received != sizeof(complete)) return false;
        value = complete;
        return true;
    };
    std::unordered_set<uint64_t> visited;
    d.current_entry = head;
    for (unsigned i = 0; i < 50000; ++i) {
        d.next_entry = 0;
        if (!read(d.next_entry, d.current_entry, i == 0 ? "CR3_HEAD_READ" : "CR3_LINK_READ")) return 0;
        if (d.next_entry == head) { d.stage = "CR3_PID_NOT_FOUND"; return 0; }
        if (d.next_entry < Offsets::ActiveProcessLinks || (d.next_entry & 7)) {
            d.stage = "CR3_INVALID_LINK"; return 0;
        }
        if (!visited.insert(d.next_entry).second) { d.stage = "CR3_LIST_CYCLE"; return 0; }
        d.eprocess = d.next_entry - Offsets::ActiveProcessLinks;
        d.observed_pid = 0;
        if (!read(d.observed_pid, d.eprocess + Offsets::UniqueProcessId, "CR3_PID_READ")) return 0;
        ++d.nodes;
        if (d.observed_pid == target_pid) {
            if (!read(d.target_cr3, d.eprocess + Offsets::DirectoryTableBase, "CR3_TARGET_READ")) return 0;
            if (!(d.target_cr3 & 0x000FFFFFFFFFF000ULL)) { d.stage = "CR3_TARGET_ZERO"; return 0; }
            d.stage = "CR3_FOUND";
            return d.target_cr3;
        }
        d.current_entry = d.next_entry;
    }
    d.stage = "CR3_NODE_LIMIT";
    return 0;
}

std::string DescribeCr3Lookup(const Cr3LookupDiagnostics& d) {
    std::ostringstream out;
    out << "stage=" << d.stage << " pid=" << d.target_pid << " nodes=" << d.nodes << " reads=" << d.reads
        << " requested=" << d.requested << " received=" << d.received
        << " observed_pid=" << d.observed_pid << std::hex
        << " caller_cr3=0x" << d.caller_cr3 << " head=0x" << d.head << " address=0x" << d.address
        << " current_entry=0x" << d.current_entry << " next_entry=0x" << d.next_entry
        << " eprocess=0x" << d.eprocess << " target_cr3=0x" << d.target_cr3
        << " offsets(pid/links/cr3)=0x" << Offsets::UniqueProcessId << "/0x" << Offsets::ActiveProcessLinks
        << "/0x" << Offsets::DirectoryTableBase;
    return out.str();
}


uint64_t ProbeProcessCr3(uint64_t target_pid, uint64_t head,
    const std::atomic_bool* stop, std::chrono::steady_clock::time_point deadline) {
    const auto expired = [&] {
        return (stop && stop->load(std::memory_order_relaxed))
            || std::chrono::steady_clock::now() >= deadline;
    };
    if (!target_pid || !head || expired()) return 0;
    const uint64_t system_cr3 = hypercall::read_guest_cr3();
    if (!system_cr3) return 0;
    std::unordered_set<uint64_t> visited;
    uint64_t current = head;
    for (unsigned i = 0; i < 50000 && !expired(); ++i) {
        uint64_t next = 0, pid = 0;
        if (!ReadExact(next, current, system_cr3) || expired() || next == head
            || next < Offsets::ActiveProcessLinks || (next & 7) || !visited.insert(next).second) return 0;
        const uint64_t process = next - Offsets::ActiveProcessLinks;
        if (!ReadExact(pid, process + Offsets::UniqueProcessId, system_cr3) || expired()) return 0;
        if (pid == target_pid) {
            uint64_t first = 0, second = 0, pid_after = 0;
            if (!ReadExact(first, process + Offsets::DirectoryTableBase, system_cr3) || expired()
                || !ReadExact(pid_after, process + Offsets::UniqueProcessId, system_cr3) || expired()
                || !ReadExact(second, process + Offsets::DirectoryTableBase, system_cr3) || expired()) return 0;
            constexpr uint64_t mask = 0x000FFFFFFFFFF000ULL;
            if (pid_after != target_pid || !(first & mask) || (first & mask) != (second & mask)) return 0;
            return second;
        }
        current = next;
    }
    return 0;
}

uint64_t GetModuleBase_Raw(uint64_t target_cr3, uint64_t peb_address, const char* wanted_name) {
    if (!wanted_name) return 0;
    std::wstring wide;
    for (const unsigned char* c = reinterpret_cast<const unsigned char*>(wanted_name); *c; ++c) {
        if (*c > 0x7f) return 0; // Legacy entry accepts ASCII, never a lossy Unicode conversion.
        wide.push_back(*c);
    }
    return GetModuleBase_Raw(target_cr3, peb_address, wide.c_str());
}

uint64_t GetModuleBase_Raw(uint64_t target_cr3, uint64_t peb_address, const wchar_t* wanted_name) {
	if (!peb_address || !wanted_name || !*wanted_name) return 0;
    const std::wstring_view wanted(wanted_name);
    if (wanted.size() > 32767) return 0; // UNICODE_STRING's 16-bit byte length.

	// 读取 PEB -> Ldr
	uint64_t ldr_address = 0;
	if (!ReadExact(ldr_address, peb_address + Offsets::Ldr, target_cr3) || !ldr_address) return 0;

	//获取 InLoadOrderModuleList 头节点
	// 头节点本身不包含 DLL 信息，它的 Flink 指向第一个模块
	uint64_t head_node = ldr_address + Offsets::InLoadOrderLinks;

	uint64_t current_node = 0;
	if (!ReadExact(current_node, head_node, target_cr3)) return 0;

	int safety_check = 200;

	while (current_node != head_node && current_node != 0 && safety_check-- > 0) {
		//在 InLoadOrder 中，LDR_DATA_TABLE_ENTRY 的基址就是 current_node
		uint64_t entry_address = current_node;

		//读取 BaseDllName (UNICODE_STRING)
		UNICODE_STRING_RAW uStr = { 0 };
		const bool have_name = ReadExact(uStr, entry_address + Offsets::BaseDllName, target_cr3);

		if (have_name && uStr.Length > 0 && uStr.Length <= uStr.MaximumLength
            && uStr.Length == wanted.size() * sizeof(wchar_t) && uStr.Buffer != 0) {
			// Read only a complete name of the expected length; preserve Unicode.
			const size_t read_len = uStr.Length;
			std::vector<wchar_t> name_buf(read_len / 2 + 1);

			if (ReadExact(name_buf.data(), uStr.Buffer, target_cr3, read_len)) {
				name_buf[read_len / 2] = 0; // 确保 0 结尾

				const bool name_matches = CompareStringOrdinal(name_buf.data(), static_cast<int>(wanted.size()),
                    wanted.data(), static_cast<int>(wanted.size()), TRUE) == CSTR_EQUAL;

				// 5. 比较名字
				if (name_matches) {
					// 匹配成功！读取 DllBase
					uint64_t dll_base = 0;
					return ReadExact(dll_base, entry_address + Offsets::DllBase, target_cr3) ? dll_base : 0;
				}
			}
		}

		// 6. 移动到下一个节点
		uint64_t next_node = 0;
		if (!ReadExact(next_node, current_node, target_cr3)) return 0;
		current_node = next_node;
	}

	return 0;
}

uint64_t FindPebByCr3_Raw(uint64_t target_cr3, uint64_t ps_active_process_head_addr) {
	// 1. 自动获取 System CR3 (内核上下文)
	const uint64_t system_cr3 = hypercall::read_guest_cr3();

	std::cout << "\n--- CR3 反查 PEB 开始 ---" << std::endl;
	std::cout << "目标 CR3: 0x" << std::hex << target_cr3 << std::endl;
	std::cout << "链表头 (PsActiveProcessHead): 0x" << ps_active_process_head_addr << std::endl;
	std::cout << "当前 System CR3: 0x" << system_cr3 << std::endl;

	if (ps_active_process_head_addr == 0) {
		std::cout << "ERROR: 链表头地址无效" << std::endl;
		return 0;
	}

	// 2. 初始化遍历
	// ps_active_process_head_addr 本身是一个 LIST_ENTRY 结构
	// 我们从它指向的下一个节点开始遍历
	uint64_t current_list_entry = ps_active_process_head_addr;

	// 简单的死循环保护
	for (int i = 0; i < 50000; i++) {
		// 读取当前节点的 Flink (Next)
		uint64_t next_entry = 0;
		if (!ReadExact(next_entry, current_list_entry, system_cr3)) {
			std::cout << "  ERROR: 读取链表节点失败: 0x" << current_list_entry << std::endl;
			break;
		}

		// 检查是否回到起点或断链
		if (next_entry == 0 || next_entry == ps_active_process_head_addr) {
			std::cout << "遍历结束" << std::endl;
			break;
		}

		// 计算 EPROCESS 基址
		// ActiveProcessLinks 位于 EPROCESS 内部，所以要减去偏移
		uint64_t eprocess_base = next_entry - Offsets::ActiveProcessLinks;

		// 读取当前进程的 DirectoryTableBase (CR3)
		uint64_t current_dirbase = 0;
		if (!ReadExact(current_dirbase, eprocess_base + Offsets::DirectoryTableBase, system_cr3)) {
			// 读取失败通常意味着页面未映射，跳过
			current_list_entry = next_entry;
			continue;
		}

		// 关键比对：检查 CR3 是否匹配
		constexpr uint64_t PFN_MASK = ~0xFFFull;

		if ((current_dirbase & PFN_MASK) == (target_cr3 & PFN_MASK)) {
			std::cout << "     发现目标进程!" << std::endl;
			std::cout << "     EPROCESS: 0x" << eprocess_base << std::endl;
			std::cout << "     Found CR3: 0x" << current_dirbase << std::endl;

			// 6. 匹配成功，读取 PEB
			uint64_t target_peb = 0;
			if (ReadExact(target_peb, eprocess_base + Offsets::Peb, system_cr3)) {
				std::cout << "     PEB 地址: 0x" << target_peb << std::endl;
				return target_peb;
			}
			else {
				std::cout << "      ERROR: 无法读取 PEB" << std::endl;
				return 0;
			}
		}

		// 移动到下一个节点
		current_list_entry = next_entry;
	}

	std::cout << "--- 未找到匹配该 CR3 的进程 ---" << std::endl;
	return 0;
}
