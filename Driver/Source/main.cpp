#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>

static DWORD get_process_id(const wchar_t* process_name) {
	DWORD process_id = 0;
	HANDLE snaplist = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (snaplist == INVALID_HANDLE_VALUE) {
		return process_id;
	}

	PROCESSENTRY32W entry = {};
	entry.dwSize = sizeof(decltype(entry));
	if ( Process32FirstW(snaplist, &entry) == TRUE ) {
		if (_wcsicmp(process_name, entry.szExeFile) == 0) {
			process_id = entry.th32ProcessID;
		}
		else {
			while (Process32NextW(snaplist, &entry) == TRUE) {
				if (_wcsicmp(process_name, entry.szExeFile) == 0) {
					process_id = entry.th32ProcessID;
					break;
				}
			}
		}
	}
	CloseHandle(snaplist);
	return process_id;
}

static std::uintptr_t get_module_base(const DWORD pid, const wchar_t* module_name) {
	std::uintptr_t module_base = 0;
	// Need to bitwise OR this to get all the modules in the process
	HANDLE snaplist = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
	if (snaplist == INVALID_HANDLE_VALUE) {
		return module_base;
	}
	
	MODULEENTRY32W entry = {};
	if (Module32FirstW(snaplist, &entry) == TRUE) {
		if (wcsstr(module_name, entry.szModule) != nullptr) {
			module_base = reinterpret_cast<std::uintptr_t>(entry.modBaseAddr);
		}
		else {
			while (Module32NextW(snaplist, &entry) == TRUE) {
				if (wcsstr(module_name, entry.szModule) != nullptr) {
					module_base = reinterpret_cast<std::uintptr_t>(entry.modBaseAddr);
					break;
				}
			}
		}

	}
	CloseHandle(snaplist);
	return module_base;
}

namespace driver {
	namespace codes {
		constexpr ULONG attach = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x696, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
		constexpr ULONG read = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x697, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
		constexpr ULONG write = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x698, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

	}
	struct Request
	{
		HANDLE process_id;

		PVOID target;
		PVOID buffer;

		SIZE_T size;
		SIZE_T return_size;
	};

	bool attach_to_process(HANDLE driver_handle, DWORD pid) {
		Request r;
		r.process_id = reinterpret_cast<HANDLE>(pid);
		return DeviceIoControl(driver_handle, codes::attach, &r, sizeof(r), &r, sizeof(r), nullptr, nullptr);
	}

	template <class T>
	T read_memory(HANDLE driver_handle, const std::uintptr_t addr) {
		T temp = {};
		Request r;
		r.target = reinterpret_cast<PVOID>(addr);
		r.buffer = &temp;
		r.size = sizeof(T);
		DeviceIoControl(driver_handle, codes::read, &r, sizeof(r), &r, sizeof(r), nullptr, nullptr);
		return temp;
	}

	template <class T>
	BOOL write_memory(HANDLE driver_handle, const std::uintptr_t addr, const T& value) {
		
		Request r;
		r.target = reinterpret_cast<PVOID>(addr);
		r.buffer = (PVOID)&value;
		r.size = sizeof(T);
		return DeviceIoControl(driver_handle, codes::write, &r, sizeof(r), &r, sizeof(r), nullptr, nullptr);
	}

}

int main(int argc, char* argv[]) {
	DWORD pid = get_process_id( L"notepad.exe");
	if (pid == 0) {
		std::cout << "Failed to find notepad" << std::endl;
		std::cin.get();
		return -1;
	}

	const HANDLE driver_handle = CreateFile(L"\\\\.\\SexyDriver", GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (driver_handle == INVALID_HANDLE_VALUE) {
		std::cout << "Failed to create driver handle" << std::endl;
		std::cin.get();
		return -1;
	}

	if (driver::attach_to_process(driver_handle, pid)) {
		std::cout << "Successfully attached user mode application to the driver..." << std::endl;
		std::cin.get();
	}

	CloseHandle(driver_handle);
	return 0;
}