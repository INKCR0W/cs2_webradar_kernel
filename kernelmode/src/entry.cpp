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

		constexpr ULONG get_module =
			CTL_CODE(FILE_DEVICE_UNKNOWN, 0x114517, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
	}  // namespace codes

	// Shared between user mode & kernel mode.
	struct Request {
		PVOID target;
		PVOID buffer;

		SIZE_T size;
		SIZE_T return_size;
	};


	ULONG64 GetModuleBasex64(PEPROCESS proc, UNICODE_STRING module_name, bool get_size) {
		PPEB pPeb = (PPEB)PsGetProcessPeb(proc);

		if (!pPeb) {
			return 0;
		}

		KAPC_STATE state;

		KeStackAttachProcess(proc, &state);

		PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)pPeb->Ldr;

		if (!pLdr) {
			KeUnstackDetachProcess(&state);
			return 0;
		}

		// loop the linked list
		for (PLIST_ENTRY list = (PLIST_ENTRY)pLdr->InLoadOrderModuleList.Flink;
			list != &pLdr->InLoadOrderModuleList; list = (PLIST_ENTRY)list->Flink)
		{
			PLDR_DATA_TABLE_ENTRY pEntry =
				CONTAINING_RECORD(list, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

			if (RtlCompareUnicodeString(&pEntry->BaseDllName, &module_name, TRUE) ==
				0) {
				ULONG64 baseAddr = (ULONG64)pEntry->DllBase;
				ULONG64 moduleSize = (ULONG64)pEntry->SizeOfImage; // get the size of the module
				KeUnstackDetachProcess(&state);
				if (get_size) {
					return moduleSize; // return the size of the module if get_size is TRUE
				}
				return baseAddr;
			}
		}

		KeUnstackDetachProcess(&state);

		return 0; // failed
	}

	NTSTATUS GetModuleBaseProcess(PEPROCESS proc, ULONG64* buffer) {
		NTSTATUS status = STATUS_UNSUCCESSFUL;

		UNICODE_STRING module_name = {};

		RtlInitUnicodeString(&module_name, L"client.dll");

		ULONG64 addr = GetModuleBasex64(proc, module_name, false);

		if (addr == 0) {
			return status;
		}

		*buffer = addr;

		status = STATUS_SUCCESS;

		return status;
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
			if (target_process == nullptr)
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

		case codes::get_module:
			if (target_process != nullptr)
				status = GetModuleBaseProcess(target_process, reinterpret_cast<ULONG64*>(request->buffer));
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