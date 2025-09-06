#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <thread>
#include <chrono>

#define red "\x1b[31m"
#define reset "\x1b[0m"

// find process id by name
DWORD getprocessbyname(const char* name) {
PROCESSENTRY32 entry{};
entry.dwSize = sizeof(entry);

HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
if (snap == INVALID_HANDLE_VALUE)
return -1;

if (Process32First(snap, &entry)) {
do {
char procname[MAX_PATH];
wcstombs_s(nullptr, procname, entry.szExeFile, MAX_PATH);
if (_stricmp(procname, name) == 0) {
CloseHandle(snap);
return entry.th32ProcessID;
}
} while (Process32Next(snap, &entry));
}

CloseHandle(snap);
return 0;
}

int main() {
HANDLE hconsole = GetStdHandle(STD_OUTPUT_HANDLE);
DWORD mode;
if (GetConsoleMode(hconsole, &mode))
SetConsoleMode(hconsole, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);

SetConsoleTitleA("loadlib injector by tars");
std::cout << red << "[injector] " << reset << "waiting for fivem.exe...\n";

DWORD pid = 0;
while (!pid) {
pid = getprocessbyname("FiveM.exe");
if (!pid) {
std::cout << red << "[injector] " << reset << "fivem.exe not found, retrying...\r";
std::cout.flush();
std::this_thread::sleep_for(std::chrono::milliseconds(500));
}
}

std::cout << "\n" << red << "[injector] " << reset << "fivem.exe found! pid: " << pid << "\n";

char dllpath[MAX_PATH];
if (GetFullPathNameA("region.dll", MAX_PATH, dllpath, nullptr) == 0) {
std::cerr << red << "[injector] " << reset << "couldn't find region.dll\n";
return -1;
}

HANDLE hprocess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
if (!hprocess) {
std::cerr << red << "[injector] " << reset << "failed to open process\n";
return -1;
}

LPVOID mem = VirtualAllocEx(hprocess, nullptr, strlen(dllpath) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
if (!mem) {
std::cerr << red << "[injector] " << reset << "failed to allocate memory\n";
CloseHandle(hprocess);
return -1;
}

if (!WriteProcessMemory(hprocess, mem, dllpath, strlen(dllpath) + 1, nullptr)) {
std::cerr << red << "[injector] " << reset << "failed to write dll path\n";
VirtualFreeEx(hprocess, mem, 0, MEM_RELEASE);
CloseHandle(hprocess);
return -1;
}

HMODULE hkernel = GetModuleHandleA("kernel32.dll");
if (!hkernel) {
std::cerr << red << "[injector] " << reset << "failed to get kernel32 handle\n";
VirtualFreeEx(hprocess, mem, 0, MEM_RELEASE);
CloseHandle(hprocess);
return -1;
}

FARPROC loadlib = GetProcAddress(hkernel, "LoadLibraryA");
if (!loadlib) {
std::cerr << red << "[injector] " << reset << "failed to get loadlibrary address\n";
VirtualFreeEx(hprocess, mem, 0, MEM_RELEASE);
CloseHandle(hprocess);
return -1;
}

HANDLE thread = CreateRemoteThread(hprocess, nullptr, 0, (LPTHREAD_START_ROUTINE)loadlib, mem, 0, nullptr);
if (!thread) {
std::cerr << red << "[injector] " << reset << "failed to create remote thread\n";
VirtualFreeEx(hprocess, mem, 0, MEM_RELEASE);
CloseHandle(hprocess);
return -1;
}

std::cout << red << "[injector] " << reset << "region.dll injected into fivem! have fun  \n";
std::cout << red << "[injector] " << reset << "press ctrl + c to exit\n";

WaitForSingleObject(thread, INFINITE);
CloseHandle(thread);
VirtualFreeEx(hprocess, mem, 0, MEM_RELEASE);
CloseHandle(hprocess);

return 0;
}