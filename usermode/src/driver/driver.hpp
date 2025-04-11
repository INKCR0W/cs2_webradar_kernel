#pragma once

#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>

namespace driver {
	namespace codes {
		// 用于设置驱动 / Used to setup the driver
		constexpr ULONG attach =
			CTL_CODE(FILE_DEVICE_UNKNOWN, 0x114514, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

		// 读取进程内存 / Read process memory
		constexpr ULONG read =
			CTL_CODE(FILE_DEVICE_UNKNOWN, 0x114515, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

		// 写入进程内存 / Write process memory
		constexpr ULONG write =
			CTL_CODE(FILE_DEVICE_UNKNOWN, 0x114516, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

		// 获取模块信息 / Get module information
		constexpr ULONG get_module =
			CTL_CODE(FILE_DEVICE_UNKNOWN, 0x114517, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
	}  // namespace codes

	// 用户模式与内核模式共享 / Shared between user mode & kernel mode
	struct Request {
		PVOID target;       // 目标地址 / Target address
		PVOID buffer;       // 缓冲区 / Buffer

		SIZE_T size;        // 数据大小 / Data size
		SIZE_T return_size; // 返回大小 / Return size
	};

	namespace error_codes {
		// 没有错误 / Access
		static const int ACCESS = 0x00;
		// 获取驱动错误 / Get driver error
		static const int GET_DRIVER_ERROR = 0x01;
		// 获取进程ID错误 / Get process ID error
		static const int GET_PROCESSID_ERROR = 0x02;
	}  // namespace error_codes


	class Driver {
	private:
		// 驱动句柄 / Driver handle
		HANDLE driver_handle;
		// 目标进程的PID / Target process PID
		uint64_t pid;
		// 是否已经附加到目标进程 / Whether attached to target process
		bool attached;
		// 错误信息 / Error code
		int error_code;

	public:
		// 构造函数 / Constructors
		Driver();
		Driver(const wchar_t* driver_path);

		virtual ~Driver();  // 析构函数 / Destructor

		// 设置驱动 / Set driver handle
		bool setDriver(const wchar_t* driver_path);
		// 附加到目标进程 / Attach to target process
		bool attach();

		// 获取驱动句柄 / Get driver handle
		const HANDLE _driver() const;
		// 获取附加的进程ID / Get attached process PID
		const DWORD _pid() const;
		// 检查是否已附加 / Check if attached
		const bool isAttached() const;
		// 获取错误代码（参见driver::error_codes） / Get last error code (see driver::error_codes)
		const int getError() const;

		// 获取模块基地址 / Get module base address
		const std::uintptr_t get_module_base(const wchar_t* module_name) const;

		// 内存读取模板 / Memory read template
		template <typename T>
		T read_memory(const std::uintptr_t addr) {
			T temp = {};

			Request r = {
				reinterpret_cast<PVOID>(addr),
				&temp,
				sizeof(T),
				0
			};

			DeviceIoControl(this->driver_handle, codes::read, &r, sizeof(r), &r, sizeof(r), nullptr, nullptr);

			return temp;
		}

		// 内存写入模板 / Memory write template
		template <typename T>
		void write_memory(const std::uintptr_t addr, const T& value) {
			Request r = {
				reinterpret_cast<PVOID>(addr),
				(PVOID)&value,
				sizeof(T),
				0
			};

			DeviceIoControl(this->driver_handle, codes::write, &r, sizeof(r), &r, sizeof(r), nullptr, nullptr);
		}

		// 指定大小的内存读取 / Memory read with specified size
		template <typename T>
		void read_memory_size(const std::uintptr_t addr, const T* value, size_t size) {
			Request r = {
				reinterpret_cast<PVOID>(addr),
				(PVOID)value,
				size,
				0
			};

			DeviceIoControl(this->driver_handle, codes::read, &r, sizeof(r), &r, sizeof(r), nullptr, nullptr);
		}
	};
}  // namespace driver