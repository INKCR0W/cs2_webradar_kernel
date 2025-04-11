#include <ntifs.h>
#include <wdm.h>
#include <stdio.h>

#include "defines.hpp"


void debug_print(PCSTR text) {
#ifndef _DEBUG
	UNREFERENCED_PARAMETER(text);
#endif // !DEBUG

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, text));
}

namespace driver {
	namespace codes {
		// Used to setup the driver.
		constexpr ULONG attach =
			CTL_CODE(FILE_DEVICE_UNKNOWN, 0x114514, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

		// Read process memory.
		constexpr ULONG read =
			CTL_CODE(FILE_DEVICE_UNKNOWN, 0x114515, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

		// Write process memory.
		constexpr ULONG write =
			CTL_CODE(FILE_DEVICE_UNKNOWN, 0x114516, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

		constexpr ULONG get_module_info =
			CTL_CODE(FILE_DEVICE_UNKNOWN, 0x114517, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
	}  // namespace codes

	// Shared between user mode & kernel mode.
	struct Request {
		PVOID target;
		PVOID buffer;

		SIZE_T size;
		SIZE_T return_size;
	};

	struct ModuleInfo {
		uintptr_t base_addr;
		uintptr_t size;
	};

	NTSTATUS GetModuleInfox64(PEPROCESS proc, const wchar_t* module_name, ModuleInfo* buffer) {
		if (!proc || !buffer || !module_name) {
			return STATUS_INVALID_PARAMETER;
		}

		const SIZE_T max_name_length = 260 * sizeof(wchar_t);

		wchar_t* kernel_module_name = (wchar_t*)ExAllocatePool2(POOL_FLAG_NON_PAGED, max_name_length + sizeof(wchar_t), 'NmeT');
		if (!kernel_module_name) {
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		RtlZeroMemory(kernel_module_name, max_name_length + sizeof(wchar_t));

		__try {
			ProbeForRead((PVOID)module_name, sizeof(wchar_t), sizeof(WCHAR));

			SIZE_T i = 0;
			while (i < max_name_length / sizeof(wchar_t)) {
				wchar_t ch;
				ProbeForRead((PVOID)(module_name + i), sizeof(wchar_t), sizeof(WCHAR));
				ch = module_name[i];

				kernel_module_name[i] = ch;

				if (ch == L'\0') {
					break;
				}

				i++;
			}

			kernel_module_name[max_name_length / sizeof(wchar_t)] = L'\0';
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			ExFreePoolWithTag(kernel_module_name, 'NmeT');
			return GetExceptionCode();
		}

		if (kernel_module_name[0] == L'\0') {
			ExFreePoolWithTag(kernel_module_name, 'NmeT');
			return STATUS_INVALID_PARAMETER;
		}

		ModuleInfo kernelBuffer = { 0 };

		PPEB pPeb = (PPEB)PsGetProcessPeb(proc);
		if (!pPeb) {
			return STATUS_UNSUCCESSFUL;
		}

		KAPC_STATE state;
		KeStackAttachProcess(proc, &state);

		PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)pPeb->Ldr;
		if (!pLdr) {
			KeUnstackDetachProcess(&state);
			ExFreePoolWithTag(kernel_module_name, 'NmeT');
			return STATUS_UNSUCCESSFUL;
		}



		UNICODE_STRING uniStr = {};

		RtlInitUnicodeString(&uniStr, kernel_module_name);

		for (
			PLIST_ENTRY list = (PLIST_ENTRY)pLdr->InLoadOrderModuleList.Flink;
			list != &pLdr->InLoadOrderModuleList;
			list = (PLIST_ENTRY)list->Flink
			) {
			PLDR_DATA_TABLE_ENTRY pEntry =
				CONTAINING_RECORD(list, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

			if (RtlCompareUnicodeString(&pEntry->BaseDllName, &uniStr, TRUE) == 0) {
				kernelBuffer.base_addr = (ULONG64)pEntry->DllBase;
				kernelBuffer.size = (ULONG64)pEntry->SizeOfImage;

				KeUnstackDetachProcess(&state);
				ExFreePoolWithTag(kernel_module_name, 'NmeT');

				__try {
					ProbeForWrite(buffer, sizeof(ModuleInfo), 1);
					*buffer = kernelBuffer;
					return STATUS_SUCCESS;
				}
				__except (EXCEPTION_EXECUTE_HANDLER) {
					return GetExceptionCode();
				}
			}
		}

		KeUnstackDetachProcess(&state);
		ExFreePoolWithTag(kernel_module_name, 'NmeT');

		return STATUS_UNSUCCESSFUL; // 未找到模块
	}
	HANDLE find_process_id_by_name(const wchar_t* process_name) {
		NTSTATUS status;
		PVOID buffer;
		PSYSTEM_PROCESS_INFORMATION spi;
		ULONG bufferSize = 0;
		HANDLE processId = NULL;

		status = ZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &bufferSize);
		if (status != STATUS_INFO_LENGTH_MISMATCH) {
			return NULL;
		}

		buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, bufferSize, 'prct');
		if (buffer == NULL) {
			debug_print("Failed to allocate memory\n");
			return NULL;
		}

		status = ZwQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, NULL);
		if (!NT_SUCCESS(status)) {
			ExFreePoolWithTag(buffer, 'prct');
			return NULL;
		}

		spi = (PSYSTEM_PROCESS_INFORMATION)buffer;
		for (;;) {
			if (spi->ImageName.Length > 0 && spi->ImageName.Buffer != NULL) {
				if (_wcsicmp(spi->ImageName.Buffer, process_name) == 0) {
					processId = spi->UniqueProcessId;
					break;
				}
			}

			if (spi->NextEntryOffset == 0) {
				break;
			}

			spi = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)spi + spi->NextEntryOffset);
		}

		ExFreePoolWithTag(buffer, 'prct');

		return processId;
	}

	NTSTATUS attach(PEPROCESS* target_process, ULONG64* pid_addr) {
		NTSTATUS status = STATUS_UNSUCCESSFUL;

		HANDLE pid = find_process_id_by_name(L"cs2.exe");

		if (pid == NULL) {
			return status;
		}

		*pid_addr = reinterpret_cast<ULONG64>(pid);

		return PsLookupProcessByProcessId(pid, target_process);
	}

	NTSTATUS create(PDEVICE_OBJECT device_object, PIRP irp) {
		UNREFERENCED_PARAMETER(device_object);

		IoCompleteRequest(irp, IO_NO_INCREMENT);

		return irp->IoStatus.Status;
	}

	NTSTATUS close(PDEVICE_OBJECT device_object, PIRP irp) {
		UNREFERENCED_PARAMETER(device_object);

		IoCompleteRequest(irp, IO_NO_INCREMENT);

		return irp->IoStatus.Status;
	}

	NTSTATUS device_control(PDEVICE_OBJECT device_object, PIRP irp) {
		UNREFERENCED_PARAMETER(device_object);

		debug_print("[+] Device control called.");

		NTSTATUS status = STATUS_UNSUCCESSFUL;

		// We need this to determine which code was passed through.
		PIO_STACK_LOCATION stack_irp = IoGetCurrentIrpStackLocation(irp);

		// Access the request object sent from user mode.
		auto request = reinterpret_cast<Request*>(irp->AssociatedIrp.SystemBuffer);

		if (stack_irp == nullptr || request == nullptr) {
			IoCompleteRequest(irp, IO_NO_INCREMENT);
			return status;
		}


		// The target process we want access to.
		static PEPROCESS target_process = nullptr;


		const ULONG control_code = stack_irp->Parameters.DeviceIoControl.IoControlCode;

		switch (control_code) {
		case codes::attach:
			status = attach(&target_process, reinterpret_cast<ULONG64*>(request->buffer));
			break;

		case codes::read:
			if (target_process != nullptr)
				status = MmCopyVirtualMemory(target_process, request->target, PsGetCurrentProcess(), request->buffer, request->size, KernelMode, &request->return_size);
			break;

		case codes::write:
			if (target_process != nullptr)
				status = MmCopyVirtualMemory(PsGetCurrentProcess(), request->buffer, target_process, request->target, request->size, KernelMode, &request->return_size);
			break;

		case codes::get_module_info:
			if (target_process != nullptr)
				status = GetModuleInfox64(target_process, reinterpret_cast<const wchar_t*>(request->target), reinterpret_cast<ModuleInfo*>(request->buffer));
			break;

		default:
			break;
		}

		irp->IoStatus.Status = status;
		irp->IoStatus.Information = sizeof(Request);

		IoCompleteRequest(irp, IO_NO_INCREMENT);

		return status;
	}

}  // namespace driver

// The real entry
NTSTATUS driver_main(PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path) {
	UNREFERENCED_PARAMETER(registry_path);

	UNICODE_STRING device_name = {};
	RtlInitUnicodeString(&device_name, L"\\Device\\HimcDriver");

	// Create driver device object.
	PDEVICE_OBJECT device_object = nullptr;
	NTSTATUS status = IoCreateDevice(driver_object, 0, &device_name, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &device_object);

	if (status != STATUS_SUCCESS) {
		debug_print("[-] Failed to create driver device.\n");
		return status;
	}

	debug_print("[+] Driver device successfully created.\n");

	UNICODE_STRING symbolic_link = {};
	RtlInitUnicodeString(&symbolic_link, L"\\DosDevices\\Global\\HimcDriver");

	status = IoCreateSymbolicLink(&symbolic_link, &device_name);
	if (status != STATUS_SUCCESS) {
		debug_print("[-] Failed to establish symbolic link.\n");
		return status;
	}

	debug_print("[+] Driver symbolic link successfully established.\n");

	// Allow us to send small amounts of data between um/km.
	SetFlag(device_object->Flags, DO_BUFFERED_IO);

	// Set the driver handlers to our functions with our logic.
	driver_object->MajorFunction[IRP_MJ_CREATE] = driver::create;
	driver_object->MajorFunction[IRP_MJ_CLOSE] = driver::close;
	driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = driver::device_control;

	// We have initialized our device.
	ClearFlag(device_object->Flags, DO_DEVICE_INITIALIZING);

	debug_print("[+] Driver initialized successfully.\n");

	return status;
}

NTSTATUS DriverEntry() {
	debug_print("[+] HERE IS SOMEONE WHO IS WILL BLOW UP YOUR KERNEL.\n");

	UNICODE_STRING driver_name = {};
	RtlInitUnicodeString(&driver_name, L"\\Driver\\HimcDriver");

	return IoCreateDriver(&driver_name, driver_main);
}