#include <comdef.h>
#include <Wbemidl.h>
#include <string>

#include "driver.hpp"

#pragma comment(lib, "wbemuuid.lib")


namespace driver {
	DWORD Driver::get_process_id(const wchar_t* process_name) {
		DWORD process_id = 0;

		const HANDLE snap_shot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
		if (snap_shot == INVALID_HANDLE_VALUE)
			return process_id;

		PROCESSENTRY32W entry = {};
		entry.dwSize = sizeof(decltype(entry));

		if (Process32FirstW(snap_shot, &entry)) {
			do {
				if (_wcsicmp(process_name, entry.szExeFile) == 0) {
					process_id = entry.th32ProcessID;
					break;
				}
			} while (Process32NextW(snap_shot, &entry));
		}

		CloseHandle(snap_shot);

#ifdef DEBUG
		std::cout << "process_id got\n";
#endif // DEBUG

		return process_id;
	}

	Driver::Driver() : driver_handle(nullptr), pid(0), attached(false), error_code(0) {}

	Driver::Driver(const wchar_t* driver_path) : Driver(driver_path, static_cast<DWORD>(0)) {}

	Driver::Driver(const wchar_t* driver_path, const wchar_t* process_name) : Driver(driver_path, get_process_id(process_name)) {}

	Driver::Driver(const wchar_t* driver_path, const DWORD pid) : pid(pid), attached(false), error_code(0) {
		this->driver_handle = CreateFileW(driver_path, GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);


		if (this->driver_handle == INVALID_HANDLE_VALUE) {
			this->error_code = error_codes::GET_DRIVER_ERROR;
			return;
		}

#ifdef DEBUG
		std::cout << "driver_handle got\n";
#endif // DEBUG

		if (pid == 0) {
			this->error_code = error_codes::GET_PROCESSID_ERROR;
			return;
		}

		this->attach(pid);
	}

	Driver::~Driver() {
		CloseHandle(driver_handle);
	}

	bool Driver::setDriver(const wchar_t* driver_path) {
		this->driver_handle = CreateFileW(driver_path, GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

		return (this->driver_handle != INVALID_HANDLE_VALUE);
	}

	bool Driver::attach(const wchar_t* process_name) {
		const DWORD pid = this->get_process_id(process_name);

		if (pid == 0)
			return false;

		return Driver::attach(pid);
	}

	bool Driver::attach(const DWORD pid) {
		Request r = {
			reinterpret_cast<HANDLE>(pid),
			nullptr,
			nullptr,
			0,
			0
		};

		this->attached = DeviceIoControl(this->driver_handle, codes::attach, &r, sizeof(r), &r, sizeof(r), nullptr, nullptr);

		return this->attached;
	}

	const HANDLE Driver::_driver() const {
		return this->driver_handle;
	}

	const DWORD Driver::_pid() const {
		return this->pid;
	}

	const bool Driver::isAttached() const {
		return this->attached;
	}

	const int Driver::getError() const {
		return this->error_code;
	}


	const std::uintptr_t Driver::get_module_base(const wchar_t* module_name) const {


		std::uintptr_t module_base = 0;

		Request r = {
			0,
			0,
			&module_base,
			0,
			0
		};

		bool status = DeviceIoControl(this->driver_handle, codes::get_module, &r, sizeof(r), &r, sizeof(r), nullptr, nullptr);

		return module_base;
	}
}  // namespace driver