#include <comdef.h>
#include <Wbemidl.h>
#include <string>

#include "driver.hpp"

#pragma comment(lib, "wbemuuid.lib")


namespace driver {
	Driver::Driver() : driver_handle(nullptr), pid(0), attached(false), error_code(0) {}

	Driver::Driver(const wchar_t* driver_path) : pid(0), attached(false), error_code(0) {
		this->driver_handle = CreateFileW(driver_path, GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

		if (this->driver_handle == INVALID_HANDLE_VALUE) {
			this->error_code = error_codes::GET_DRIVER_ERROR;
			return;
		}

		this->attach();
	}

	Driver::~Driver() {
		CloseHandle(driver_handle);
	}

	bool Driver::setDriver(const wchar_t* driver_path) {
		this->driver_handle = CreateFileW(driver_path, GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

		return (this->driver_handle != INVALID_HANDLE_VALUE);
	}

	bool Driver::attach() {
		Request r = {
			0,
			&pid,
			0,
			0
		};

		this->attached = DeviceIoControl(this->driver_handle, codes::attach, &r, sizeof(r), &r, sizeof(r), nullptr, nullptr);

		if (!this->attached) {
			error_code = error_codes::GET_PROCESSID_ERROR;
		}

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
			&module_base,
			0,
			0
		};

		bool status = DeviceIoControl(this->driver_handle, codes::get_module, &r, sizeof(r), &r, sizeof(r), nullptr, nullptr);

		return module_base;
	}
}  // namespace driver