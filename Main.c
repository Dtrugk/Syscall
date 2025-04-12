// sysWhisper command: python3 syswhispers.py -a x64 -c msvc -m jumper_randomized -f NtAllocateVirtualMemory,NtWriteVirtualMemory,NtProtectVirtualMemory,NtCreateThreadEx,NtQuerySystemInformation,NtQueryInformationProcess -o syscall -v

#include <windows.h>
#include <stdio.h>
#include "payload.h"
#include "syscall.h"

// Structure to store found processes
typedef struct {
    char* name;
    DWORD pid;
} ProcessInfo;

HMODULE getModuleHandle(IN LPCWSTR moduleName) {
	HMODULE hModule = NULL;
	hModule = GetModuleHandleW(moduleName);

	if (hModule == NULL) {
		warn("Failed to get a handle to the module. error: 0x%lx\n", GetLastError());
		return NULL;
	}
	else {
		return hModule;
	}
}

int EnumProcess(char* Proclist[], int listSize, ProcessInfo found[], int* foundCount) {
    *foundCount = 0; // Initialize count of found processes
    NTSTATUS status;

    // Load NTDLL
    HMODULE hNTDLL = getModuleHandle(L"NTDLL.dll");
    if (!hNTDLL) {
        warn("Unable to load NTDLL, error: 0x%lx\n", GetLastError());
        return 0;
    }

    // Get required buffer size
    ULONG size = 0;
    status = Sw3NtQuerySystemInformation(SystemProcessInformation, NULL, 0, &size);
    if (status != 0xC0000004) {
        okay("Unexpected error: 0x%X\n", status);
        FreeLibrary(hNTDLL);
        return 0;
    }

    // Allocate memory
    PVOID buffer = malloc(size);
    if (!buffer) {
        okay("Memory allocation failed\n");
        FreeLibrary(hNTDLL);
        return 0;
    }

    // Get process list
    status = Sw3NtQuerySystemInformation(SystemProcessInformation, buffer, size, &size);
    if (status != 0) {
        okay("NtQuerySystemInformation failed. Status: 0x%X\n", status);
        free(buffer);
        FreeLibrary(hNTDLL);
        return 0;
    }

    // Iterate through process list
    SYSTEM_PROCESS_INFORMATION* spi = (SYSTEM_PROCESS_INFORMATION*)buffer;

    while (spi) {
        if (spi->ImageName.Buffer) {
            char processName[MAX_PATH] = { 0 };
            size_t convertedChars = 0;
            wcstombs_s(&convertedChars, processName, MAX_PATH, spi->ImageName.Buffer, _TRUNCATE);

            // Check if process is in the provided list
            for (int i = 0; i < listSize; i++) {
                if (Proclist[i] && _stricmp(processName, Proclist[i]) == 0) {
                    // Store match
                    found[*foundCount].name = Proclist[i];
                    found[*foundCount].pid = (DWORD)(ULONG_PTR)spi->UniqueProcessId;
                    (*foundCount)++;
                    break; // Move to next process after finding a match
                }
            }
        }

        if (spi->NextEntryOffset == 0) break;
        spi = (SYSTEM_PROCESS_INFORMATION*)((BYTE*)spi + spi->NextEntryOffset);
    }

    free(buffer);
    FreeLibrary(hNTDLL);
    return *foundCount;
}

// hide process 
void HideProcess(DWORD pid) {
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hProcess == NULL) {
		okay("Failed to open process. Error: %lu\n", GetLastError());
		return;
	}
	// Hide the process (implementation depends on the method used)
	// For example, using a driver or other techniques
	CloseHandle(hProcess);
}

int main() {
    // List of process names to search for
    char* processList[] = {
        "notepad.exe",
        "calc.exe",
        "explorer.exe",
        "cmd.exe",
        "powershell.exe",
        "chrome.exe",
        "notepad++.exe",
    };
    int listSize = sizeof(processList) / sizeof(processList[0]); // Correct size

    // Array to store found processes
    ProcessInfo foundProcesses[50]; // Arbitrary limit for matches
    int foundCount = 0;

    // Enumerate processes
    EnumProcess(processList, listSize, foundProcesses, &foundCount);

    // Display results
    if (foundCount > 0) {
        okay("Found %d matching processes:\n", foundCount);
        for (int i = 0; i < foundCount; i++) {
            okay("Process: %s, PID: %lu\n", foundProcesses[i].name, foundProcesses[i].pid);
        }
    }
    else {
        okay("No matching processes found\n");
    }

    return 0;
}