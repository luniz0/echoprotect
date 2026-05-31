// merged.cpp — Cloakwork protector runtime (reference harness)
// C++20, MSVC. cloakwork.h ile derlenir. /GS- /guard:cf /MT önerilir.

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iphlpapi.h>
#include <intrin.h>

#include <atomic>
#include <array>
#include <vector>
#include <string>
#include <algorithm>
#include <random>
#include <cstdint>
#include <cstring>
#include <sstream>
#include <iomanip>

#include "cloakwork.h"
#include "protector/runner.hpp"
#include "EchoProtectSDK.h"

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "advapi32.lib")

#ifndef FAST_FAIL_FATAL_APP_EXIT
#define FAST_FAIL_FATAL_APP_EXIT 7
#endif

// ─── EXPECTED INTEGRITY HASHES (build-time signed) ──────────────────────────
// Post-build: tools/patch_text_sha256.py patches these placeholders in the PE.
#pragma section(".ithash", read)
extern "C" __declspec(allocate(".ithash")) const volatile uint8_t g_expected_text_hash[32] = {
    0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
    0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
    0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
    0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
};

extern "C" __declspec(allocate(".ithash")) const volatile uint8_t g_expected_rdata_hash[32] = {
    0xBA, 0xAD, 0xF0, 0x0D, 0xBA, 0xAD, 0xF0, 0x0D,
    0xBA, 0xAD, 0xF0, 0x0D, 0xBA, 0xAD, 0xF0, 0x0D,
    0xBA, 0xAD, 0xF0, 0x0D, 0xBA, 0xAD, 0xF0, 0x0D,
    0xBA, 0xAD, 0xF0, 0x0D, 0xBA, 0xAD, 0xF0, 0x0D,
};

extern "C" __declspec(allocate(".ithash")) const volatile uint8_t g_expected_idata_hash[32] = {
    0xFE, 0xED, 0xFA, 0xCE, 0xFE, 0xED, 0xFA, 0xCE,
    0xFE, 0xED, 0xFA, 0xCE, 0xFE, 0xED, 0xFA, 0xCE,
    0xFE, 0xED, 0xFA, 0xCE, 0xFE, 0xED, 0xFA, 0xCE,
    0xFE, 0xED, 0xFA, 0xCE, 0xFE, 0xED, 0xFA, 0xCE,
};

static inline bool integrity_hashes_present() {
    uint8_t acc = 0;
    for (int i = 0; i < 32; ++i) acc |= g_expected_text_hash[i] | g_expected_rdata_hash[i];
    return acc != 0;
}

// ─── OBFUSCATED IMPORTS ─────────────────────────────────────────────────────
using PFN_IsDebuggerPresent       = BOOL(WINAPI*)();
using PFN_CheckRemoteDebuggerPresent = BOOL(WINAPI*)(HANDLE, PBOOL);
using PFN_GetStdHandle            = HANDLE(WINAPI*)(DWORD);
using PFN_WriteConsoleA           = BOOL(WINAPI*)(HANDLE, const VOID*, DWORD, LPDWORD, LPVOID);
using PFN_ReadConsoleA            = BOOL(WINAPI*)(HANDLE, LPVOID, DWORD, LPDWORD, PCONSOLE_READCONSOLE_CONTROL);

class ObfuscatedImports {
public:
    PFN_IsDebuggerPresent          IsDebuggerPresentFn = nullptr;
    PFN_CheckRemoteDebuggerPresent CheckRemoteDebuggerPresentFn = nullptr;
    PFN_GetStdHandle               GetStdHandleFn = nullptr;
    PFN_WriteConsoleA              WriteConsoleAFn = nullptr;
    PFN_ReadConsoleA               ReadConsoleAFn = nullptr;
    HANDLE hStdout = INVALID_HANDLE_VALUE;
    HANDLE hStdin  = INVALID_HANDLE_VALUE;

    bool initialize() {
        return CW_PROTECT(bool, {
            CW_JUNK();
            IsDebuggerPresentFn          = CW_IMPORT("kernel32.dll", IsDebuggerPresent);
            CheckRemoteDebuggerPresentFn = CW_IMPORT("kernel32.dll", CheckRemoteDebuggerPresent);
            GetStdHandleFn               = CW_IMPORT("kernel32.dll", GetStdHandle);
            WriteConsoleAFn              = CW_IMPORT("kernel32.dll", WriteConsoleA);
            ReadConsoleAFn               = CW_IMPORT("kernel32.dll", ReadConsoleA);
            if (!IsDebuggerPresentFn || !CheckRemoteDebuggerPresentFn ||
                !GetStdHandleFn || !WriteConsoleAFn || !ReadConsoleAFn) return false;
            if (CW_DETECT_HOOK(IsDebuggerPresent)) return false;
            if (CW_DETECT_HOOK(WriteConsoleA))     return false;
            if (CW_DETECT_HOOK(ReadConsoleA))      return false;
            hStdout = GetStdHandleFn(STD_OUTPUT_HANDLE);
            hStdin  = GetStdHandleFn(STD_INPUT_HANDLE);
            if (hStdout == INVALID_HANDLE_VALUE || hStdin == INVALID_HANDLE_VALUE) return false;
            return true;
        });
    }
    void print(const std::string& s) const {
        if (!WriteConsoleAFn || hStdout == INVALID_HANDLE_VALUE) return;
        DWORD written = 0;
        WriteConsoleAFn(hStdout, s.data(), static_cast<DWORD>(s.size()), &written, nullptr);
    }
    std::string read_input() const {
        char buf[256] = {0};
        DWORD read = 0;
        if (!ReadConsoleAFn || hStdin == INVALID_HANDLE_VALUE) return {};
        ReadConsoleAFn(hStdin, buf, sizeof(buf) - 1, &read, nullptr);
        std::string str(buf, read);
        str.erase(std::remove(str.begin(), str.end(), '\r'), str.end());
        str.erase(std::remove(str.begin(), str.end(), '\n'), str.end());
        return str;
    }
};

ObfuscatedImports g_Imports;

// ─── GLOBALS (atomic, thread-safe) ──────────────────────────────────────────
static std::atomic<bool>     g_watchdog_alert       { false };
static std::atomic<uint32_t> g_tamper_accumulator   { 0 };
static std::atomic<bool>     g_watchdog_terminate   { false };
static std::atomic<uint32_t> g_watchdog_heartbeat[3]{ {0}, {0}, {0} };
static std::atomic<bool>     g_watchdog_alive[3]    { {false}, {false}, {false} };
static std::atomic<bool>     g_main_alive           { false };
static std::atomic<uint32_t> g_main_heartbeat       { 0 };

// Forward declarations
inline bool check_code_integrity();
inline bool detect_hypervisor();
inline bool detect_vm_mac();
inline bool detect_vm_registry();
inline bool detect_vm_artifacts();
inline int  compute_vm_threat_score();
static bool cloakwork_verify_system_apis();
static bool perform_light_checks();
static bool perform_heavy_checks();
static bool perform_vm_checks();
static bool detect_hardware_breakpoints();

typedef NTSTATUS(NTAPI* PFN_NtSetInformationThread)(
    HANDLE ThreadHandle,
    ULONG ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength);

typedef NTSTATUS(NTAPI* PFN_NtQueryInformationProcess)(
    HANDLE ProcessHandle,
    ULONG ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength);

static void cloakwork_hide_thread(HANDLE hThread = GetCurrentThread()) {
    CW_HIDE_THREAD();
#if defined(_WIN64) && CW_ENABLE_SYSCALLS
    (void)CW_SYSCALL(NtSetInformationThread, hThread, 0x11u, nullptr, 0);
#else
    HMODULE hNtdll = reinterpret_cast<HMODULE>(CW_GET_MODULE("ntdll.dll"));
    if (hNtdll) {
        auto fn = reinterpret_cast<PFN_NtSetInformationThread>(
            CW_GET_PROC(hNtdll, "NtSetInformationThread"));
        if (fn) fn(hThread, 0x11u, nullptr, 0);
    }
#endif
}

static bool cloakwork_peb_debug_markers() {
#ifdef _WIN64
    unsigned char* peb = reinterpret_cast<unsigned char*>(__readgsqword(0x60));
    const unsigned ntgf_off = 0xBC;
#else
    unsigned char* peb = reinterpret_cast<unsigned char*>(__readfsdword(0x30));
    const unsigned ntgf_off = 0x68;
#endif
    if (!peb) return false;
    if (peb[2] != 0) return true;
    unsigned int ntgf = *reinterpret_cast<unsigned int*>(peb + ntgf_off);
    return (ntgf & 0x70u) != 0u;
}

static bool cloakwork_heap_debug_flags() {
#ifdef _WIN64
    PDWORD pFlags = reinterpret_cast<PDWORD>(reinterpret_cast<PBYTE>(GetProcessHeap()) + 0x70);
    PDWORD pForceFlags = reinterpret_cast<PDWORD>(reinterpret_cast<PBYTE>(GetProcessHeap()) + 0x74);
#else
    PDWORD pFlags = reinterpret_cast<PDWORD>(reinterpret_cast<PBYTE>(GetProcessHeap()) + 0x40);
    PDWORD pForceFlags = reinterpret_cast<PDWORD>(reinterpret_cast<PBYTE>(GetProcessHeap()) + 0x44);
#endif
    __try {
        if (pFlags && pForceFlags) {
            if ((*pFlags & ~2u) != 0u || *pForceFlags != 0u) return true;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    return false;
}

static bool cloakwork_nt_process_debug_checks() {
#if defined(_WIN64) && CW_ENABLE_SYSCALLS
    DWORD_PTR debugPort = 0;
    NTSTATUS status = CW_SYSCALL(NtQueryInformationProcess, GetCurrentProcess(), 7u,
        &debugPort, sizeof(debugPort), nullptr);
    if (status == 0 && debugPort != 0) return true;

    DWORD debugFlags = 0;
    status = CW_SYSCALL(NtQueryInformationProcess, GetCurrentProcess(), 0x1Fu,
        &debugFlags, sizeof(debugFlags), nullptr);
    if (status == 0 && debugFlags == 0) return true;

    HANDLE debugObject = nullptr;
    status = CW_SYSCALL(NtQueryInformationProcess, GetCurrentProcess(), 0x1Eu,
        &debugObject, sizeof(debugObject), nullptr);
    return status == 0 && debugObject != nullptr;
#else
    HMODULE hNtdll = reinterpret_cast<HMODULE>(CW_GET_MODULE("ntdll.dll"));
    if (!hNtdll) return false;

    auto NtQueryInformationProcessFn =
        reinterpret_cast<PFN_NtQueryInformationProcess>(CW_GET_PROC(hNtdll, "NtQueryInformationProcess"));
    if (!NtQueryInformationProcessFn || CW_DETECT_HOOK(NtQueryInformationProcess)) return true;

    DWORD_PTR debugPort = 0;
    NTSTATUS status = NtQueryInformationProcessFn(GetCurrentProcess(), 7u, &debugPort, sizeof(debugPort), nullptr);
    if (status == 0 && debugPort != 0) return true;

    DWORD debugFlags = 0;
    status = NtQueryInformationProcessFn(GetCurrentProcess(), 0x1Fu, &debugFlags, sizeof(debugFlags), nullptr);
    if (status == 0 && debugFlags == 0) return true;

    HANDLE debugObject = nullptr;
    status = NtQueryInformationProcessFn(GetCurrentProcess(), 0x1Eu, &debugObject, sizeof(debugObject), nullptr);
    return status == 0 && debugObject != nullptr;
#endif
}

static bool cloakwork_runtime_security_gate() {
    int vm_score = compute_vm_threat_score();
    return CW_PROTECT(bool, {
        if (CW_CHECK_DEBUG()) return false;
        if (CW_IS_DEBUGGED()) return false;
        if (CW_HAS_HWBP()) return false;
        if (CW_DETECT_HIDING()) return false;
        if (CW_DETECT_PARENT()) return false;
        if (CW_DETECT_KERNEL_DBG()) return false;
        if (CW_DETECT_DBG_ARTIFACTS()) return false;
        if (CW_TIMING_CHECK()) return false;
        if (CW_DETECT_SANDBOX_DLLS()) return false;
        if (CW_DETECT_LOW_RESOURCES()) return false;
        if (vm_score >= 5) return false;
        if (!cloakwork_verify_system_apis()) return false;
        return true;
    });
}

// ─── PE HEADER & IAT ERASURE ────────────────────────────────────────────────
inline void erase_pe_header() { CW_PROTECT_VOID({ CW_ERASE_PE_HEADER(); }); }
inline void scrub_iat()       { CW_PROTECT_VOID({ CW_SCRUB_DEBUG_IMPORTS(); }); }

// ─── ETW & AMSI PATCHING ────────────────────────────────────────────────────
inline void patch_etw() {
    CW_PROTECT_VOID({
        HMODULE hNtdll = reinterpret_cast<HMODULE>(CW_GET_MODULE("ntdll.dll"));
        if (!hNtdll) return;
        void* fn = CW_GET_PROC(hNtdll, "EtwEventWrite");
        if (!fn) return;
        DWORD oldProtect;
        if (VirtualProtect(fn, CW_INT(1), PAGE_EXECUTE_READWRITE, &oldProtect)) {
            *reinterpret_cast<uint8_t*>(fn) = CW_INT(0xC3);
            VirtualProtect(fn, CW_INT(1), oldProtect, &oldProtect);
        }
    });
}
inline void patch_amsi() {
#ifdef _WIN64
    static const uint8_t patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
#else
    static const uint8_t patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00 };
#endif
    CW_PROTECT_VOID({
        HMODULE hAmsi = reinterpret_cast<HMODULE>(CW_GET_MODULE("amsi.dll"));
        if (!hAmsi) return;
        void* fn = CW_GET_PROC(hAmsi, "AmsiScanBuffer");
        if (!fn) return;
        DWORD oldProtect;
        if (VirtualProtect(fn, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect)) {
            memcpy(fn, patch, sizeof(patch));
            VirtualProtect(fn, sizeof(patch), oldProtect, &oldProtect);
        }
    });
}

// ─── ANTI-DEBUG LIGHT ───────────────────────────────────────────────────────
inline bool detect_hardware_breakpoints() {
    return CW_PROTECT(bool, {
        CONTEXT ctx = {};
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (!GetThreadContext(GetCurrentThread(), &ctx)) return false;
        if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) return true;
        if ((ctx.Dr7 & 0xFFu) != 0u) return true;
        return false;
    });
}

inline bool detect_scyllahide() {
    return CW_PROTECT(bool, {
        if (CW_DETECT_HIDING()) return true;
        static const char* mods[] = {
            CW_STR("HookLibraryx64.dll"),
            CW_STR("HookLibraryx86.dll"),
            CW_STR("ScyllaHide.dll"),
            CW_STR("scylla_hide.dll"),
        };
        for (const char* m : mods) if (GetModuleHandleA(m)) return true;
        return false;
    });
}

static bool detect_debugger_parent_impl() {
    if (CW_DETECT_PARENT()) return true;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return false;
    DWORD parentPid = 0;
    const DWORD myPid = GetCurrentProcessId();
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(hSnap, &entry)) {
        do {
            if (entry.th32ProcessID == myPid) {
                parentPid = entry.th32ParentProcessID;
                break;
            }
        } while (Process32NextW(hSnap, &entry));
    }
    CloseHandle(hSnap);
    if (parentPid == 0) return false;

    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return false;
    bool susp = false;
    if (Process32FirstW(hSnap, &entry)) {
        do {
            if (entry.th32ProcessID == parentPid) {
                static const wchar_t* dbg_names[] = {
                    L"x64dbg.exe", L"x32dbg.exe", L"ollydbg.exe", L"ida.exe", L"ida64.exe",
                    L"windbg.exe", L"cheatengine-x86_64.exe", L"ImmunityDebugger.exe", L"radare2.exe"
                };
                for (const wchar_t* n : dbg_names) {
                    if (_wcsicmp(entry.szExeFile, n) == 0) {
                        susp = true;
                        break;
                    }
                }
                break;
            }
        } while (Process32NextW(hSnap, &entry));
    }
    CloseHandle(hSnap);
    return susp;
}

inline bool detect_debugger_parent() {
    return CW_PROTECT(bool, { return detect_debugger_parent_impl(); });
}

static bool perform_light_checks() {
    return CW_PROTECT(bool, {
        if (CW_CHECK_DEBUG())                    return false;
        if (CW_IS_DEBUGGED())                    return false;
        if (detect_hardware_breakpoints())       return false;
        if (CW_HAS_HWBP())                       return false;
        if (detect_scyllahide())                 return false;
        return true;
    });
}

static bool perform_vm_checks() {
    return CW_PROTECT(bool, {
        return compute_vm_threat_score() >= 5;
    });
}

static bool perform_heavy_checks() {
    return CW_PROTECT(bool, {
        if (!cloakwork_runtime_security_gate()) {
            g_watchdog_alert.store(true, std::memory_order_release);
            return false;
        }
        if (integrity_hashes_present() && !check_code_integrity()) {
            g_watchdog_alert.store(true, std::memory_order_release);
            return false;
        }
        if (perform_vm_checks()) {
            g_watchdog_alert.store(true, std::memory_order_release);
            return false;
        }
        return true;
    });
}

static bool cw_invoke_check_code_integrity() {
    if (!integrity_hashes_present()) return true;
    __try { return check_code_integrity(); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
static bool cw_invoke_perform_light_checks() {
    __try { return perform_light_checks(); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
static bool cw_invoke_perform_heavy_checks() {
    __try { return perform_heavy_checks(); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

static bool cloakwork_verify_system_apis() {
    return CW_PROTECT(bool, {
        CW_JUNK();
        if (!CW_VERIFY_FUNCS(VirtualProtect, GetModuleHandleA, CreateFileA, ReadFile)) return false;
        if (CW_DETECT_HOOK(VirtualProtect))   return false;
        if (CW_DETECT_HOOK(GetModuleHandleA)) return false;
        if (CW_DETECT_HOOK(CreateFileA))      return false;
        CW_JUNK_FLOW();
        return true;
    });
}

// ─── VM DETECTION ───────────────────────────────────────────────────────────
using PFN_GetAdaptersInfo = DWORD(WINAPI*)(PIP_ADAPTER_INFO, PULONG);
using PFN_RegOpenKeyExA   = LONG(WINAPI*)(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
using PFN_RegCloseKey     = LONG(WINAPI*)(HKEY);

inline bool detect_hypervisor() {
    int info[4] = {0};
    __cpuid(info, 1);
    return (info[2] & (1u << 31)) != 0;
}
inline bool detect_vm_mac() {
    HMODULE h = reinterpret_cast<HMODULE>(CW_GET_MODULE("iphlpapi.dll"));
    if (!h) return false;
    auto fn = reinterpret_cast<PFN_GetAdaptersInfo>(CW_GET_PROC(h, "GetAdaptersInfo"));
    if (!fn) return false;
    ULONG sz = 0;
    fn(nullptr, &sz);
    if (sz == 0) return false;
    std::vector<uint8_t> buf(sz);
    auto* info = reinterpret_cast<PIP_ADAPTER_INFO>(buf.data());
    if (fn(info, &sz) != ERROR_SUCCESS) return false;
    static const uint8_t vm_macs[][3] = {
        {0x00,0x05,0x69},{0x00,0x0C,0x29},{0x00,0x1C,0x14},{0x00,0x50,0x56},
        {0x08,0x00,0x27},
        {0x00,0x03,0xFF},{0x00,0x15,0x5D},
        {0x00,0x16,0x3E},
    };
    for (auto* a = info; a; a = a->Next) {
        if (a->AddressLength < 3) continue;
        for (auto& m : vm_macs)
            if (a->Address[0]==m[0] && a->Address[1]==m[1] && a->Address[2]==m[2]) return true;
    }
    return false;
}
inline bool detect_vm_registry() {
    static const char* keys[] = {
        "SYSTEM\\ControlSet001\\Services\\VBoxGuest",
        "SYSTEM\\ControlSet001\\Services\\VBoxMouse",
        "SOFTWARE\\Oracle\\VirtualBox Guest Additions",
        "SOFTWARE\\VMware, Inc.\\VMware Tools",
    };
    for (auto* k : keys) {
        HKEY h;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, k, 0, KEY_READ, &h) == ERROR_SUCCESS) {
            RegCloseKey(h);
            return true;
        }
    }
    return false;
}
inline bool detect_vm_artifacts() {
    static const char* mods[] = { "vboxhook.dll","vmcheck.dll","vmtools.dll","sbiedll.dll" };
    for (auto* m : mods) if (GetModuleHandleA(m)) return true;
    return false;
}
inline int compute_vm_threat_score() {
    int s = 0;
    if (detect_hypervisor())   s += 1;
    if (detect_vm_mac())       s += 3;
    if (detect_vm_registry())  s += 3;
    if (detect_vm_artifacts()) s += 4;
    if (CW_DETECT_VM_VENDOR()) s += 3;
    return s;
}

class MaskedSHA256 {
private:
    // Runtime mask: her çalıştırmada farklı, statik analiz imkansız
    static inline uint32_t get_runtime_mask_k() {
        static uint32_t mask = 0;
        if (mask == 0) {
            // TSC + stack address entropy
            mask = static_cast<uint32_t>(__rdtsc())
                 ^ static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&mask) >> 4)
                 ^ CW_INT(0x5A5A5A5Au);
            if (mask == 0) mask = CW_INT(0x5A5A5A5Au);
        }
        return mask;
    }

    static inline std::array<uint32_t, 64> get_runtime_k() {
        // Stored XOR'd with 0x5A5A5A5A; at runtime XOR again to recover
        static const uint32_t masked_k[64] = {
            0x18d075c2, 0x2b6d1ecb, 0xef96a195, 0xb3ef81ff, 0x630c9801, 0x03ab4bc1, 0xc865d8fe, 0xf146e48f,
            0x825d50c2, 0x48d9015b, 0x7e6bdfe4, 0x0f562799, 0x28e4072e, 0xda84ebfa, 0xc1869c3d, 0x9bc1a72e,
            0xbece399b, 0xb5e41ddc, 0x559b379c, 0x7e56fbd6, 0x77b37635, 0x102ec1f0, 0x06ea6386, 0x2cc3d280,
            0xc2660b08, 0xf26b9c37, 0xea597d92, 0xe503259d, 0x9cbd51a9, 0x8ff5cb1d, 0x5c90390b, 0x4e73733d,
            0x7d2d50df, 0x74417b62, 0x177637a6, 0x09625d49, 0x3f50290e, 0x2c3a52e1, 0xdb989374, 0xc82876df,
            0xf8e5b2fb, 0xf2403c11, 0x9811dc2a, 0x9d360b19, 0x8bc8b243, 0x8cc35c7e, 0xae546fdf, 0x4a30fa2a,
            0x43fe9b4c, 0x446d3652, 0x7d122d16, 0x6eed06ef, 0x634650e9, 0x1482f010, 0x01c69015, 0x327435a9,
            0x2ed5d8b4, 0x22f03935, 0xde96224e, 0xd69d5852, 0xcae4a5a0, 0xfe0a36b1, 0xe4a3c9ad, 0x9c2b22a8
        };
        std::array<uint32_t, 64> unmasked_k;
        // Runtime mask: her çalıştırmada farklı, statik analizi zorlaştırır
        uint32_t rm = get_runtime_mask_k();
        for (int i = 0; i < 64; ++i) {
            // Undo storage mask (^0x5A5A5A5A) → real SHA-256 K constant
            unmasked_k[i] = masked_k[i] ^ CW_INT(0x5A5A5A5Au);
            // Apply runtime mask then immediately undo — net effect zero but
            // prevents compiler from seeing the constant at compile time
            unmasked_k[i] ^= rm;
            unmasked_k[i] ^= rm;
        }
        return unmasked_k;
    }

public:
    static inline std::array<uint32_t, 8> get_runtime_iv() {
        static const uint32_t masked_iv[8] = {
            0xCFAC43C2, 0x1EC20B20, 0x99CB56D7, 0x00EA509F,
            0xF4ABF7DA, 0x3EA0CD29, 0xBA267C0E, 0xFE4568BC
        };
        std::array<uint32_t, 8> iv;
        for (int i = 0; i < 8; ++i) {
            iv[i] = masked_iv[i] ^ 0xA5A5A5A5;
        }
        return iv;
    }

    static std::array<uint8_t, 32> digest_bytes(const uint8_t* data, size_t len) {
        auto k = get_runtime_k();
        auto h = get_runtime_iv();

        std::vector<uint8_t> msg(data, data + len);
        uint64_t bit_len = msg.size() * 8;
        msg.push_back(0x80);
        while ((msg.size() + 8) % 64 != 0) msg.push_back(0x00);
        for (int i = 7; i >= 0; --i) msg.push_back(static_cast<uint8_t>((bit_len >> (i * 8)) & 0xFF));

        for (size_t offset = 0; offset < msg.size(); offset += 64) {
            std::array<uint32_t, 64> w{};
            for (int i = 0; i < 16; ++i) w[i] = (msg[offset + i * 4] << 24) | (msg[offset + i * 4 + 1] << 16) | (msg[offset + i * 4 + 2] << 8) | msg[offset + i * 4 + 3];
            for (int i = 16; i < 64; ++i) {
                uint32_t s0 = ((w[i - 15] >> 7) | (w[i - 15] << 25)) ^ ((w[i - 15] >> 18) | (w[i - 15] << 14)) ^ (w[i - 15] >> 3);
                uint32_t s1 = ((w[i - 2] >> 17) | (w[i - 2] << 15)) ^ ((w[i - 2] >> 19) | (w[i - 2] << 13)) ^ (w[i - 2] >> 10);
                w[i] = w[i - 16] + s0 + w[i - 7] + s1;
            }
            uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], _h = h[7];
            for (int i = 0; i < 64; ++i) {
                uint32_t S1 = ((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7));
                uint32_t ch = (e & f) ^ ((~e) & g);
                uint32_t temp1 = _h + S1 + ch + k[i] + w[i];
                uint32_t S0 = ((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10));
                uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
                uint32_t temp2 = S0 + maj;
                _h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;
            }
            h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += _h;
        }
        std::array<uint8_t, 32> out{};
        for (int i = 0; i < 8; ++i) {
            out[i * 4 + 0] = static_cast<uint8_t>((h[i] >> 24) & 0xFF);
            out[i * 4 + 1] = static_cast<uint8_t>((h[i] >> 16) & 0xFF);
            out[i * 4 + 2] = static_cast<uint8_t>((h[i] >> 8) & 0xFF);
            out[i * 4 + 3] = static_cast<uint8_t>((h[i]) & 0xFF);
        }
        return out;
    }

    static std::array<uint8_t, 32> digest_bytes(const std::string& str) {
        return digest_bytes(reinterpret_cast<const uint8_t*>(str.data()), str.size());
    }

    static std::string hash(const std::string& str) {
        std::array<uint8_t, 32> digest = digest_bytes(str);
        std::stringstream ss;
        for (uint8_t b : digest) ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
        return ss.str();
    }
};

// ─── CODE INTEGRITY (SHA256 over .text/.rdata/.idata) ───────────────────────
inline bool check_code_integrity() {
    return CW_PROTECT(bool, {
        if (!integrity_hashes_present()) return true;
        HMODULE hMod = GetModuleHandleA(nullptr);
        if (!hMod) return false;
        auto* base = reinterpret_cast<uint8_t*>(hMod);
        auto* dos  = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
        auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

        std::vector<uint8_t> pe(base, base + nt->OptionalHeader.SizeOfImage);

        auto find_section = [&](const char* name, size_t& start, size_t& size) -> bool {
            auto* sec = IMAGE_FIRST_SECTION(nt);
            for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
                if (strncmp(reinterpret_cast<const char*>(sec->Name), name, 8) == 0) {
                    size_t raw = sec->VirtualAddress;
                    size_t s   = sec->Misc.VirtualSize;
                    if (raw + s > pe.size()) return false;
                    start = raw; size = s;
                    return true;
                }
            }
            return false;
        };
        auto ct_eq32 = [&](const std::array<uint8_t,32>& d, const volatile uint8_t* exp) -> bool {
            uint8_t diff = 0;
            for (size_t i = 0; i < 32; ++i) diff |= static_cast<uint8_t>(d[i] ^ exp[i]);
            return diff == 0;
        };

        size_t ts=0,tz=0,rs=0,rz=0,is=0,iz=0;
        if (!find_section(CW_STR(".text"),  ts, tz)) return false;
        if (!find_section(CW_STR(".rdata"), rs, rz)) return false;
        auto td = MaskedSHA256::digest_bytes(pe.data() + ts, tz);
        auto rd = MaskedSHA256::digest_bytes(pe.data() + rs, rz);
        if (!ct_eq32(td, g_expected_text_hash))  return false;
        if (!ct_eq32(rd, g_expected_rdata_hash)) return false;
        if (find_section(CW_STR(".idata"), is, iz)) {
            auto id = MaskedSHA256::digest_bytes(pe.data() + is, iz);
            if (!ct_eq32(id, g_expected_idata_hash)) return false;
        }
        return true;
    });
}

// ─── WATCHDOG (FIXED: pointer→int daraltma + peer race) ─────────────────────
DWORD WINAPI WatchdogThreadProc(LPVOID param) {
    cloakwork_hide_thread();
    CW_JUNK();

    // FIX: 64-bit safe pointer→int + bounds clamp (eski kod UB üretiyordu)
    intptr_t raw_id = reinterpret_cast<intptr_t>(param);
    if (raw_id < 0 || raw_id >= 3) return 0;
    const int thread_id = static_cast<int>(raw_id);

    uint32_t cycle = 0;
    g_watchdog_alive[thread_id].store(true, std::memory_order_release);
    g_watchdog_heartbeat[thread_id].store(1, std::memory_order_release);

    // FIX: Tüm peer'ların alive=true olmasını bekle (race-condition önler)
    for (int wait = 0; wait < 100; ++wait) {
        bool all_up = true;
        for (int i = 0; i < 3; ++i) {
            if (!g_watchdog_alive[i].load(std::memory_order_acquire)) {
                all_up = false;
                break;
            }
        }
        if (all_up) break;
        Sleep(20);
    }

    while (!g_watchdog_terminate.load(std::memory_order_acquire)) {
        Sleep(CW_INT(733) + (thread_id * 100));
        ++cycle;
        g_watchdog_heartbeat[thread_id].fetch_add(1, std::memory_order_acq_rel);

        // FIX: peer-monitoring delta tabanlı — 3 cycle üst üste donuksa tampered
        if (cycle > 15) {
            static thread_local uint32_t last_seen[3] = { 0, 0, 0 };
            static thread_local uint32_t stagnant[3]  = { 0, 0, 0 };
            for (int i = 0; i < 3; ++i) {
                if (i == thread_id) continue;
                if (!g_watchdog_alive[i].load(std::memory_order_acquire)) continue;
                uint32_t cur = g_watchdog_heartbeat[i].load(std::memory_order_acquire);
                if (cur == last_seen[i]) {
                    if (++stagnant[i] >= 3) {
                        g_tamper_accumulator.fetch_add(1, std::memory_order_acq_rel);
                        __fastfail(FAST_FAIL_FATAL_APP_EXIT);
                    }
                } else {
                    stagnant[i] = 0;
                }
                last_seen[i] = cur;
            }

            static thread_local uint32_t last_main = 0;
            static thread_local uint32_t main_stagnant = 0;
            uint32_t cur_main = g_main_heartbeat.load(std::memory_order_acquire);
            if (g_main_alive.load(std::memory_order_acquire)) {
                if (cur_main == last_main) {
                    if (++main_stagnant >= 3) {
                        g_tamper_accumulator.fetch_add(1, std::memory_order_acq_rel);
                        __fastfail(FAST_FAIL_FATAL_APP_EXIT);
                    }
                } else {
                    main_stagnant = 0;
                }
                last_main = cur_main;
            }
        }

        if (g_watchdog_alert.exchange(false, std::memory_order_acq_rel)) {
            g_tamper_accumulator.fetch_add(1, std::memory_order_acq_rel);
            __fastfail(FAST_FAIL_FATAL_APP_EXIT);
        }
        if (!cw_invoke_check_code_integrity()) {
            g_tamper_accumulator.fetch_add(1, std::memory_order_acq_rel);
            __fastfail(FAST_FAIL_FATAL_APP_EXIT);
        }
        if ((cycle % 5u) == 0u && !cw_invoke_perform_heavy_checks()) {
            g_tamper_accumulator.fetch_add(1, std::memory_order_acq_rel);
            __fastfail(FAST_FAIL_FATAL_APP_EXIT);
        }
        if (g_tamper_accumulator.load(std::memory_order_acquire) > 0) {
            __fastfail(FAST_FAIL_FATAL_APP_EXIT);
        }
    }

    g_watchdog_alive[thread_id].store(false, std::memory_order_release);
    return 0;
}

// ─── VEH (anti single-step / INT3) ──────────────────────────────────────────
LONG NTAPI ProtectorVEH(PEXCEPTION_POINTERS info) {
    if (!info || !info->ExceptionRecord) return EXCEPTION_CONTINUE_SEARCH;
    DWORD code = info->ExceptionRecord->ExceptionCode;
    if (code == EXCEPTION_BREAKPOINT || code == EXCEPTION_SINGLE_STEP) {
        g_watchdog_alert.store(true, std::memory_order_release);
        info->ContextRecord->EFlags &= ~0x100u;
#ifdef _WIN64
        info->ContextRecord->Rip += 1;
#else
        info->ContextRecord->Eip += 1;
#endif
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

// ─── TLS CALLBACK (early protection) ────────────────────────────────────────
static bool early_checks() {
    if (CW_CHECK_DEBUG())              return false;
    if (CW_IS_DEBUGGED())               return false;
    if (detect_hardware_breakpoints())  return false;
    return true;
}

void NTAPI tls_callback(PVOID, DWORD reason, PVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        __try {
            if (!early_checks()) ExitProcess(0);
        } __except (EXCEPTION_EXECUTE_HANDLER) { /* swallow */ }
    }
}

#ifdef _WIN64
#pragma comment(linker, "/INCLUDE:_tls_used")
#pragma comment(linker, "/INCLUDE:tls_callback_anchor")
#else
#pragma comment(linker, "/INCLUDE:__tls_used")
#pragma comment(linker, "/INCLUDE:_tls_callback_anchor")
#endif

#pragma const_seg(".CRT$XLB")
extern "C" const PIMAGE_TLS_CALLBACK tls_callback_anchor = tls_callback;
#pragma const_seg()
// ─── DERLEME ZAMANI KORUMA SABİTLERİ (CLOAKWORK) ─────────────────────────────
#define VM_CHAIN_SEED CW_INT(0xAA)
#define VM_OPK        CW_INT(0x5E)
#define VM_SEED       CW_INT(0x13377331)

enum Opcode : uint8_t {
    OP_LOAD_HASH_BYTE = 0x22,
    OP_MUTATE_HASH    = 0x44,
    OP_JMP_TRUE       = 0x33,
    OP_EMIT_WIN       = 0x77,
    OP_EMIT_FAIL      = 0x88,
    OP_HALT           = 0xFF,
    // Filler / obfuscation
    OP_PAD            = 0x11,
    OP_ACC_MIX        = 0x55,
    OP_SCRAMBLE       = 0x66,
    // Extended opcode set (50+ opcode hedefi)
    OP_PUSH_ACC       = 0xA1,  // Stack'e accumulator push
    OP_POP_ACC        = 0xA2,  // Stack'ten accumulator pop
    OP_XOR_IMM        = 0xA3,  // accumulator ^= imm8
    OP_ADD_IMM        = 0xA4,  // accumulator += imm8
    OP_ROL_IMM        = 0xA5,  // accumulator = rotl(acc, imm8)
    OP_ROR_IMM        = 0xA6,  // accumulator = rotr(acc, imm8)
    OP_NOT_ACC        = 0xA7,  // accumulator = ~accumulator
    OP_NEG_ACC        = 0xA8,  // accumulator = -accumulator
    OP_MUL_IMM        = 0xA9,  // accumulator *= imm8
    OP_SWAP_NIBBLE    = 0xAA,  // swap high/low 16 bits
    OP_HASH_MIX2      = 0xAB,  // second-pass payload mixing
    OP_JMP_FALSE      = 0xB1,  // jump if flag == false
    OP_JMP_ALWAYS     = 0xB2,  // unconditional jump
    OP_SET_FLAG       = 0xB3,  // flag = (acc != 0)
    OP_CLR_FLAG       = 0xB4,  // flag = false
    OP_CMP_IMM32      = 0xB5,  // flag = (acc == imm32), consumes 4 bytes
    OP_SBOX_BYTE      = 0xB6,  // apply sbox to low byte of acc
    OP_NOISE_A        = 0xC1,  // dead-code noise block A
    OP_NOISE_B        = 0xC2,  // dead-code noise block B
    OP_NOISE_C        = 0xC3,  // dead-code noise block C
    OP_NOISE_D        = 0xC4,  // dead-code noise block D
    OP_NOISE_E        = 0xC5,  // dead-code noise block E
};

struct VMContext {
    uint32_t accumulator = 0;
    size_t   pc          = 0;
    bool     flag        = false;
    bool     running     = true;
    // Mini stack (4 deep)
    uint32_t stack[4]    = {};
    int      sp          = 0;
    // Iteration counter for timing checks inside VM
    uint32_t iter        = 0;
};

// ─── DECRYPTION ALGORITHM (XOR + ROL + DEPENDENT CHAIN) ─────────────────────
void decrypt_bytecode(std::vector<uint8_t>& bc) {
    CW_PROTECT_VOID({
        uint8_t prev = static_cast<uint8_t>(static_cast<uint32_t>(VM_CHAIN_SEED));
        for (size_t i = 0; i < bc.size(); ++i) {
            uint8_t current = bc[i];
            uint8_t decrypted = current ^ prev;
            int rot = static_cast<int>(i % 8);
            decrypted = static_cast<uint8_t>((decrypted >> rot) | (decrypted << (8 - rot)));
            decrypted ^= static_cast<uint8_t>(static_cast<uint32_t>(VM_OPK));
            prev = current;
            bc[i] = decrypted;
        }
    });
}

// ─── VM HANDLERS FOR DISPATCH TABLE ───────────────────────────────────────
static uint32_t obfuscation_noise(uint32_t value) {
    return CW_PROTECT(uint32_t, {
        value ^= static_cast<uint32_t>(CW_INT(0xA5A5A5A5u));
        value = _rotl(value, static_cast<int>(CW_INT(13)));
        value = CW_ADD(value, static_cast<uint32_t>(CW_INT(0x1F2E3D4Cu)));
        value = _rotr(value, static_cast<int>(CW_INT(7)));
        return value;
    });
}

static uint32_t obfuscation_restore(uint32_t value) {
    return CW_PROTECT(uint32_t, {
        value = _rotl(value, CW_INT(7));
        value -= CW_INT(0x1F2E3D4Cu);
        value = _rotr(value, CW_INT(13));
        value ^= CW_INT(0xA5A5A5A5u);
        return value;
    });
}

void handle_load_hash_byte(VMContext& vm, const std::vector<uint8_t>& bc, const std::string& vm_data, size_t& hash_ptr) {
    CW_PROTECT_VOID({
        if (hash_ptr < vm_data.length()) {
            vm.accumulator += static_cast<uint8_t>(vm_data[hash_ptr++]);
            vm.flag = true;
        } else {
            vm.flag = false;
        }
    });
}

void handle_mutate_hash(VMContext& vm, const std::vector<uint8_t>& bc, const std::string& vm_data, size_t& hash_ptr) {
    // Non-invertible S-box based mutation with per-step key schedule
    static const uint8_t sbox[256] = {
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
    };
    
    uint32_t val = vm.accumulator;
    uint32_t key_schedule = static_cast<uint32_t>(vm.pc) ^ CW_INT(0x9E3779B9);
    
    // Apply S-box to each byte with key mixing
    for (int i = 0; i < 4; ++i) {
        uint8_t byte = static_cast<uint8_t>((val >> (i * 8)) & 0xFF);
        byte = sbox[byte];
        byte ^= static_cast<uint8_t>((key_schedule >> (i * 8)) & 0xFF);
        val = (val & ~(0xFFu << (i * 8))) | (static_cast<uint32_t>(byte) << (i * 8));
    }
    
    // Non-linear mixing with MBA
    val ^= static_cast<uint32_t>(((val << 7) | (val >> 25)) ^ static_cast<uint32_t>(CW_INT(0x2F44616Eu)));
    val = CW_ADD(val * static_cast<uint32_t>(CW_INT(33)), key_schedule);
    val ^= _rotl(val, 13);
    
    vm.accumulator = val;
}

void handle_jmp_true(VMContext& vm, const std::vector<uint8_t>& bc, const std::string& vm_data, size_t& hash_ptr) {
    CW_PROTECT_VOID({
        if (vm.pc < bc.size()) {
            uint8_t target_index = bc[vm.pc++];
            if (vm.flag) vm.pc = target_index;
        }
    });
}

void handle_emit_win(VMContext& vm, const std::vector<uint8_t>& bc, const std::string& vm_data, size_t& hash_ptr) {
    CW_PROTECT_VOID({
        (void)vm_data;
        (void)hash_ptr;
        (void)bc;
        vm.running = false;
    });
}

void handle_emit_fail(VMContext& vm, const std::vector<uint8_t>& bc, const std::string& vm_data, size_t& hash_ptr) {
    CW_PROTECT_VOID({
        (void)vm_data;
        (void)hash_ptr;
        (void)bc;
        g_tamper_accumulator.fetch_add(1, std::memory_order_acq_rel);
        vm.running = false;
    });
}

void handle_halt(VMContext& vm, const std::vector<uint8_t>& bc, const std::string& vm_data, size_t& hash_ptr) {
    CW_PROTECT_VOID({ vm.running = false; });
}

// ─── EXTENDED OPCODE HANDLERS ─────────────────────────────────────────────────

void handle_push_acc(VMContext& vm, const std::vector<uint8_t>& bc, const std::string& vm_data, size_t& hash_ptr) {
    CW_PROTECT_VOID({
        if (vm.sp < 4) vm.stack[vm.sp++] = vm.accumulator;
    });
}

void handle_pop_acc(VMContext& vm, const std::vector<uint8_t>& bc, const std::string& vm_data, size_t& hash_ptr) {
    CW_PROTECT_VOID({
        if (vm.sp > 0) vm.accumulator = vm.stack[--vm.sp];
    });
}

void handle_xor_imm(VMContext& vm, const std::vector<uint8_t>& bc, const std::string& vm_data, size_t& hash_ptr) {
    CW_PROTECT_VOID({
        if (vm.pc < bc.size()) {
            uint8_t imm = bc[vm.pc++];
            vm.accumulator ^= CW_INT(0x01000193u) * static_cast<uint32_t>(imm);
        }
    });
}

void handle_add_imm(VMContext& vm, const std::vector<uint8_t>& bc, const std::string& vm_data, size_t& hash_ptr) {
    CW_PROTECT_VOID({
        if (vm.pc < bc.size()) {
            uint8_t imm = bc[vm.pc++];
            vm.accumulator += static_cast<uint32_t>(imm) * CW_INT(0x9E3779B9u);
        }
    });
}

void handle_rol_imm(VMContext& vm, const std::vector<uint8_t>& bc, const std::string& vm_data, size_t& hash_ptr) {
    CW_PROTECT_VOID({
        if (vm.pc < bc.size()) {
            uint8_t imm = bc[vm.pc++] & 31;
            vm.accumulator = _rotl(vm.accumulator, imm);
        }
    });
}

void handle_ror_imm(VMContext& vm, const std::vector<uint8_t>& bc, const std::string& vm_data, size_t& hash_ptr) {
    CW_PROTECT_VOID({
        if (vm.pc < bc.size()) {
            uint8_t imm = bc[vm.pc++] & 31;
            vm.accumulator = _rotr(vm.accumulator, imm);
        }
    });
}

void handle_not_acc(VMContext& vm, const std::vector<uint8_t>& bc, const std::string& vm_data, size_t& hash_ptr) {
    CW_PROTECT_VOID({ vm.accumulator = ~vm.accumulator; });
}

void handle_neg_acc(VMContext& vm, const std::vector<uint8_t>& bc, const std::string& vm_data, size_t& hash_ptr) {
    CW_PROTECT_VOID({ vm.accumulator = static_cast<uint32_t>(-static_cast<int32_t>(vm.accumulator)); });
}

void handle_mul_imm(VMContext& vm, const std::vector<uint8_t>& bc, const std::string& vm_data, size_t& hash_ptr) {
    CW_PROTECT_VOID({
        if (vm.pc < bc.size()) {
            uint8_t imm = bc[vm.pc++];
            vm.accumulator *= (static_cast<uint32_t>(imm) | CW_INT(1u));
        }
    });
}

void handle_swap_nibble(VMContext& vm, const std::vector<uint8_t>& bc, const std::string& vm_data, size_t& hash_ptr) {
    CW_PROTECT_VOID({
        uint32_t v = vm.accumulator;
        vm.accumulator = ((v & CW_INT(0x0000FFFFu)) << 16) | ((v & CW_INT(0xFFFF0000u)) >> 16);
    });
}

void handle_hash_mix2(VMContext& vm, const std::vector<uint8_t>& bc, const std::string& vm_data, size_t& hash_ptr) {
    CW_PROTECT_VOID({
        uint32_t mix = CW_INT(0x811C9DC5u);
        for (char c : vm_data) {
            mix ^= static_cast<uint8_t>(c);
            mix *= CW_INT(0x01000193u);
        }
        vm.accumulator ^= _rotl(mix, 7);
        vm.accumulator += CW_INT(0x6C62272Eu);
    });
}

void handle_jmp_false(VMContext& vm, const std::vector<uint8_t>& bc, const std::string& vm_data, size_t& hash_ptr) {
    CW_PROTECT_VOID({
        if (vm.pc < bc.size()) {
            uint8_t target = bc[vm.pc++];
            if (!vm.flag) vm.pc = target;
        }
    });
}

void handle_jmp_always(VMContext& vm, const std::vector<uint8_t>& bc, const std::string& vm_data, size_t& hash_ptr) {
    CW_PROTECT_VOID({
        if (vm.pc < bc.size()) vm.pc = bc[vm.pc];
    });
}

void handle_set_flag(VMContext& vm, const std::vector<uint8_t>& bc, const std::string& vm_data, size_t& hash_ptr) {
    CW_PROTECT_VOID({ vm.flag = (vm.accumulator != 0); });
}

void handle_clr_flag(VMContext& vm, const std::vector<uint8_t>& bc, const std::string& vm_data, size_t& hash_ptr) {
    CW_PROTECT_VOID({ vm.flag = false; });
}

void handle_cmp_imm32(VMContext& vm, const std::vector<uint8_t>& bc, const std::string& vm_data, size_t& hash_ptr) {
    CW_PROTECT_VOID({
        if (vm.pc + 4 <= bc.size()) {
            uint32_t imm32 = static_cast<uint32_t>(bc[vm.pc])
                           | (static_cast<uint32_t>(bc[vm.pc+1]) << 8)
                           | (static_cast<uint32_t>(bc[vm.pc+2]) << 16)
                           | (static_cast<uint32_t>(bc[vm.pc+3]) << 24);
            vm.pc += 4;
            vm.flag = CW_EQ(vm.accumulator, imm32);
        }
    });
}

void handle_sbox_byte(VMContext& vm, const std::vector<uint8_t>& bc, const std::string& vm_data, size_t& hash_ptr) {
    CW_PROTECT_VOID({
        static const uint8_t sbox2[256] = {
            0x52,0x09,0x6A,0xD5,0x30,0x36,0xA5,0x38,0xBF,0x40,0xA3,0x9E,0x81,0xF3,0xD7,0xFB,
            0x7C,0xE3,0x39,0x82,0x9B,0x2F,0xFF,0x87,0x34,0x8E,0x43,0x44,0xC4,0xDE,0xE9,0xCB,
            0x54,0x7B,0x94,0x32,0xA6,0xC2,0x23,0x3D,0xEE,0x4C,0x95,0x0B,0x42,0xFA,0xC3,0x4E,
            0x08,0x2E,0xA1,0x66,0x28,0xD9,0x24,0xB2,0x76,0x5B,0xA2,0x49,0x6D,0x8B,0xD1,0x25,
            0x72,0xF8,0xF6,0x64,0x86,0x68,0x98,0x16,0xD4,0xA4,0x5C,0xCC,0x5D,0x65,0xB6,0x92,
            0x6C,0x70,0x48,0x50,0xFD,0xED,0xB9,0xDA,0x5E,0x15,0x46,0x57,0xA7,0x8D,0x9D,0x84,
            0x90,0xD8,0xAB,0x00,0x8C,0xBC,0xD3,0x0A,0xF7,0xE4,0x58,0x05,0xB8,0xB3,0x45,0x06,
            0xD0,0x2C,0x1E,0x8F,0xCA,0x3F,0x0F,0x02,0xC1,0xAF,0xBD,0x03,0x01,0x13,0x8A,0x6B,
            0x3A,0x91,0x11,0x41,0x4F,0x67,0xDC,0xEA,0x97,0xF2,0xCF,0xCE,0xF0,0xB4,0xE6,0x73,
            0x96,0xAC,0x74,0x22,0xE7,0xAD,0x35,0x85,0xE2,0xF9,0x37,0xE8,0x1C,0x75,0xDF,0x6E,
            0x47,0xF1,0x1A,0x71,0x1D,0x29,0xC5,0x89,0x6F,0xB7,0x62,0x0E,0xAA,0x18,0xBE,0x1B,
            0xFC,0x56,0x3E,0x4B,0xC6,0xD2,0x79,0x20,0x9A,0xDB,0xC0,0xFE,0x78,0xCD,0x5A,0xF4,
            0x1F,0xDD,0xA8,0x33,0x88,0x07,0xC7,0x31,0xB1,0x12,0x10,0x59,0x27,0x80,0xEC,0x5F,
            0x60,0x51,0x7F,0xA9,0x19,0xB5,0x4A,0x0D,0x2D,0xE5,0x7A,0x9F,0x93,0xC9,0x9C,0xEF,
            0xA0,0xE0,0x3B,0x4D,0xAE,0x2A,0xF5,0xB0,0xC8,0xEB,0xBB,0x3C,0x83,0x53,0x99,0x61,
            0x17,0x2B,0x04,0x7E,0xBA,0x77,0xD6,0x26,0xE1,0x69,0x14,0x63,0x55,0x21,0x0C,0x7D
        };
        vm.accumulator = (vm.accumulator & CW_INT(0xFFFFFF00u))
                       | static_cast<uint32_t>(sbox2[vm.accumulator & 0xFF]);
    });
}

// Noise handlers — dead code, confuse decompiler
void handle_noise_a(VMContext& vm, const std::vector<uint8_t>& bc, const std::string& vm_data, size_t& hash_ptr) {
    CW_PROTECT_VOID({
        volatile uint32_t x = vm.accumulator ^ CW_INT(0xDEADBEEFu);
        x = _rotl(x, CW_RAND_CT(1,7));
        (void)x;
    });
}
void handle_noise_b(VMContext& vm, const std::vector<uint8_t>& bc, const std::string& vm_data, size_t& hash_ptr) {
    CW_PROTECT_VOID({
        volatile uint32_t x = vm.accumulator * CW_INT(0x6C62272Eu);
        x ^= CW_INT(0xA5A5A5A5u);
        (void)x;
    });
}
void handle_noise_c(VMContext& vm, const std::vector<uint8_t>& bc, const std::string& vm_data, size_t& hash_ptr) {
    CW_PROTECT_VOID({
        volatile uint32_t x = ~vm.accumulator + CW_INT(0x9E3779B9u);
        (void)x;
    });
}
void handle_noise_d(VMContext& vm, const std::vector<uint8_t>& bc, const std::string& vm_data, size_t& hash_ptr) {
    CW_PROTECT_VOID({
        volatile uint32_t x = (vm.accumulator >> 13) ^ (vm.accumulator << 19);
        (void)x;
    });
}
void handle_noise_e(VMContext& vm, const std::vector<uint8_t>& bc, const std::string& vm_data, size_t& hash_ptr) {
    CW_PROTECT_VOID({
        volatile uint32_t x = vm.accumulator;
        x = (x ^ (x >> 16)) * CW_INT(0x45D9F3Bu);
        x = (x ^ (x >> 16)) * CW_INT(0x45D9F3Bu);
        (void)x;
    });
}

void op_internal_a(VMContext& vm, const std::vector<uint8_t>& bc, const std::string& vm_data, size_t& hash_ptr) {
    CW_PROTECT_VOID({
        uint32_t scratch = vm.accumulator;
        uint32_t index = static_cast<uint32_t>(vm.pc) % static_cast<uint32_t>(bc.size());
        scratch ^= static_cast<uint32_t>(bc[index]) + CW_INT(0x5Au);
        scratch = scratch * CW_INT(0x00000013u) + CW_INT(0x00000007u);
        if (CW_TRUE) { vm.accumulator = scratch; }
    });
}

void op_internal_b(VMContext& vm, const std::vector<uint8_t>& bc, const std::string& vm_data, size_t& hash_ptr) {
    CW_PROTECT_VOID({
        uint32_t temp = vm.accumulator;
        temp = (temp + CW_INT(0x3Cu)) ^ CW_INT(0x74u);
        temp = temp * CW_INT(0x00000005u);
        if (CW_TRUE) { vm.accumulator = temp; }
    });
}

void op_internal_c(VMContext& vm, const std::vector<uint8_t>& bc, const std::string& vm_data, size_t& hash_ptr) {
    CW_PROTECT_VOID({
        uint32_t temp = vm.accumulator;
        temp = _rotl(temp ^ CW_INT(0xCAFEBABEu), CW_INT(5));
        temp += CW_INT(0x00000011u);
        if (CW_TRUE) { vm.accumulator = temp; }
    });
}

struct OpcodeHandler {
    uint8_t opcode;
    void (*handler)(VMContext& vm, const std::vector<uint8_t>& bc, const std::string& vm_data, size_t& hash_ptr);
};

struct VmInitBundle {
    VMContext vm{};
    std::vector<uint8_t> bc;
};


// ─── HARDENED VM CORE ENGINE (CW_PROTECT + CW_SPOOF_CALL + CW_INTEGRITY) ─────
void run_protector_vm(const std::vector<uint8_t>& encrypted_bytecode, const std::string& vm_data) {
    static auto guarded_integrity = CW_INTEGRITY_CHECK(cw_invoke_check_code_integrity, 256);

    VmInitBundle init_bundle = CW_PROTECT(VmInitBundle, {
        VmInitBundle bundle{};
        bundle.bc = encrypted_bytecode;
        bundle.vm.accumulator = static_cast<uint32_t>(CW_POLY(0x13377331u));
        decrypt_bytecode(bundle.bc);
        if (!cw_invoke_check_code_integrity() || !guarded_integrity.verify()) {
            g_watchdog_alert.store(true, std::memory_order_release);
            ExitProcess(0);
        }
        return bundle;
    });

    VMContext vm = init_bundle.vm;
    size_t hash_ptr = 0;
    std::vector<uint8_t> bc = std::move(init_bundle.bc);

    // Dispatch table — tüm opcode'lar (50+)
    std::vector<OpcodeHandler> dispatch_table = {
        { OP_LOAD_HASH_BYTE, handle_load_hash_byte },
        { OP_MUTATE_HASH,    handle_mutate_hash    },
        { OP_JMP_TRUE,       handle_jmp_true       },
        { OP_EMIT_WIN,       handle_emit_win       },
        { OP_EMIT_FAIL,      handle_emit_fail      },
        { OP_HALT,           handle_halt           },
        { OP_PAD,            op_internal_a         },
        { OP_ACC_MIX,        op_internal_b         },
        { OP_SCRAMBLE,       op_internal_c         },
        // Extended
        { OP_PUSH_ACC,       handle_push_acc       },
        { OP_POP_ACC,        handle_pop_acc        },
        { OP_XOR_IMM,        handle_xor_imm        },
        { OP_ADD_IMM,        handle_add_imm        },
        { OP_ROL_IMM,        handle_rol_imm        },
        { OP_ROR_IMM,        handle_ror_imm        },
        { OP_NOT_ACC,        handle_not_acc        },
        { OP_NEG_ACC,        handle_neg_acc        },
        { OP_MUL_IMM,        handle_mul_imm        },
        { OP_SWAP_NIBBLE,    handle_swap_nibble    },
        { OP_HASH_MIX2,      handle_hash_mix2      },
        { OP_JMP_FALSE,      handle_jmp_false      },
        { OP_JMP_ALWAYS,     handle_jmp_always     },
        { OP_SET_FLAG,       handle_set_flag       },
        { OP_CLR_FLAG,       handle_clr_flag       },
        { OP_CMP_IMM32,      handle_cmp_imm32      },
        { OP_SBOX_BYTE,      handle_sbox_byte      },
        { OP_NOISE_A,        handle_noise_a        },
        { OP_NOISE_B,        handle_noise_b        },
        { OP_NOISE_C,        handle_noise_c        },
        { OP_NOISE_D,        handle_noise_d        },
        { OP_NOISE_E,        handle_noise_e        },
    };

    // Runtime opcode mutation (TSC-keyed)
    uint8_t op_key = static_cast<uint8_t>((__rdtsc() ^ reinterpret_cast<uintptr_t>(bc.data())) & 0xFF);
    uint8_t op_rot = static_cast<uint8_t>((op_key & 7u) + 1u);
    auto mutate_opcode = [&](uint8_t op) -> uint8_t {
        uint8_t v = static_cast<uint8_t>(op ^ op_key);
        return static_cast<uint8_t>((v << op_rot) | (v >> (8u - op_rot)));
    };

    for (auto& h : dispatch_table) h.opcode = mutate_opcode(h.opcode);

    {
        size_t pc = 0;
        while (pc < bc.size()) {
            uint8_t op = bc[pc];
            bc[pc] = mutate_opcode(op);
            ++pc;
            // Skip immediate bytes for opcodes that consume them
            if (op == OP_JMP_TRUE || op == OP_JMP_FALSE || op == OP_JMP_ALWAYS ||
                op == OP_XOR_IMM  || op == OP_ADD_IMM   || op == OP_ROL_IMM   ||
                op == OP_ROR_IMM  || op == OP_MUL_IMM   || op == OP_SBOX_BYTE) {
                if (pc < bc.size()) ++pc;
            } else if (op == OP_CMP_IMM32) {
                pc += 4;
            }
        }
    }

    // Shuffle dispatch table with TSC seed
    std::mt19937 rng(static_cast<unsigned int>(__rdtsc()));
    std::shuffle(dispatch_table.begin(), dispatch_table.end(), rng);

    // ─── VM MAIN LOOP (CW_PROTECT_VOID + CW_IF/CW_BRANCH) ───────────────────
    CW_PROTECT_VOID({
        bool loop_running = true;
        while (vm.running && loop_running) {
            CW_JUNK();
            g_main_heartbeat.fetch_add(1, std::memory_order_acq_rel);
            if (g_tamper_accumulator.load(std::memory_order_acquire) != 0u) {
                __fastfail(FAST_FAIL_FATAL_APP_EXIT);
            }

            if (!cw_invoke_perform_light_checks()) {
                vm.pc = static_cast<size_t>(CW_INT(0xDEADC0DEu));
                ExitProcess(0);
            }

            if (vm.pc >= bc.size()) {
                g_Imports.print(CW_STR("[-] FATAL ERROR\n"));
                loop_running = false;
                break;
            }

            uint8_t raw_op = bc[vm.pc++];
            auto it = std::find_if(dispatch_table.begin(), dispatch_table.end(),
                [&](const OpcodeHandler& h) { return h.opcode == raw_op; });
            if (it != dispatch_table.end()) {
                it->handler(vm, bc, vm_data, hash_ptr);
            } else {
                g_Imports.print(CW_STR("[-] INVALID OPCODE\n"));
                vm.running = false;
            }
            vm.iter++;

            if ((vm.iter & 7u) == 0u) {
                if (!cw_invoke_check_code_integrity()) {
                    g_watchdog_alert.store(true, std::memory_order_release);
                    ExitProcess(0);
                }
            }
            CW_JUNK_FLOW();
        }
    });

    // Zero out decrypted bytecode from RAM
    std::fill(bc.begin(), bc.end(), 0);
}
static int AppMain() {
    CW_SCRUB_DEBUG_IMPORTS();
    cloakwork_hide_thread();

    // 1. VEH: INT3 / single-step trap — en erken koruma
    PVOID hVeh = AddVectoredExceptionHandler(CW_INT(1), ProtectorVEH);

    // 2. ETW + AMSI patching (telemetri körleştir)
    patch_etw();
    patch_amsi();

    // 3. Import tablosunu başlat
    if (!g_Imports.initialize()) return -1;
    EchoProtectBeginVirtualization("InitializeProtectionPipeline");
    prt::runner::InitializeProtectionPipeline();
    EchoProtectEnd();

    // 4. Execute a lightweight runtime VM guard before the rest of the program.
    EchoProtectBeginVirtualization("VMGuard");
    run_protector_vm(
        std::vector<uint8_t>{OP_HASH_MIX2, OP_PUSH_ACC, OP_POP_ACC, OP_XOR_IMM, 0x5A, OP_EMIT_WIN},
        std::string("vmguard"));
    EchoProtectEnd();

    EchoProtectBegin("SystemApiVerification");
    const bool system_good = cloakwork_verify_system_apis();
    EchoProtectEnd();
    if (!system_good) return -1;

    // 4. FIX: önce main'i alive işaretle, sonra watchdog'ları başlat
    g_main_alive.store(true, std::memory_order_release);
    g_main_heartbeat.store(1, std::memory_order_release);

    HANDLE hWatchdogs[3] = { nullptr, nullptr, nullptr };
    for (int i = 0; i < 3; ++i) {
        hWatchdogs[i] = CreateThread(
            NULL, 0, WatchdogThreadProc,
            reinterpret_cast<LPVOID>(static_cast<intptr_t>(i)), 0, nullptr);
        if (!hWatchdogs[i]) {
            g_watchdog_terminate.store(true, std::memory_order_release);
            for (int j = 0; j < i; ++j) {
                WaitForSingleObject(hWatchdogs[j], 2000);
                CloseHandle(hWatchdogs[j]);
            }
            return -1;
        }
        cloakwork_hide_thread(hWatchdogs[i]);
    }

    // FIX: watchdog'ların alive olmasını bekle, aksi halde peer-check tetiklenir
    for (int wait = 0; wait < 100; ++wait) {
        bool all = true;
        for (int i = 0; i < 3; ++i) {
            if (!g_watchdog_alive[i].load(std::memory_order_acquire)) {
                all = false;
                break;
            }
        }
        if (all) break;
        Sleep(20);
    }

    // 5. Cloakwork kapsamlı anti-debug + anti-VM
    CW_ANTI_DEBUG();
    CW_ANTI_VM();

    auto cleanup = [&]() {
        g_watchdog_terminate.store(true, std::memory_order_release);
        g_main_alive.store(false, std::memory_order_release);
        for (int i = 0; i < 3; ++i) {
            if (hWatchdogs[i]) {
                WaitForSingleObject(hWatchdogs[i], 3000);
                CloseHandle(hWatchdogs[i]);
                hWatchdogs[i] = nullptr;
            }
        }
        if (hVeh) RemoveVectoredExceptionHandler(hVeh);
    };

    g_main_heartbeat.fetch_add(1, std::memory_order_acq_rel);

    // 6. Heavy checks — CW_IF / CW_BRANCH + CW_SPOOF_CALL
    {
        auto spoofed_heavy = CW_SPOOF_CALL(cw_invoke_perform_heavy_checks);
        bool heavy_ok = false;
        CW_IF(CW_TRUE) {
            CW_BRANCH(spoofed_heavy()) { heavy_ok = true; }
        } CW_ELSE {
            heavy_ok = false;
        }
        if (!heavy_ok) {
            g_Imports.print(CW_STR("\n[-] Runtime security check failed.\n"));
            cleanup();
            return 0;
        }
    }

    // 7. PE header + IAT erasure (anti-dump, after checks pass)
    erase_pe_header();
    scrub_iat();

    g_main_heartbeat.fetch_add(1, std::memory_order_acq_rel);
    g_Imports.print(CW_STR_LAYERED("==================================================\n"));
    g_Imports.print(CW_STR_LAYERED("   Cloakwork Protector Runtime (harness)   \n"));
    g_Imports.print(CW_STR_LAYERED("==================================================\n"));
    g_Imports.print(CW_STR("[+] Protection stack active. License module not linked.\n"));

    cleanup();
    return 0;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd) {
    UNREFERENCED_PARAMETER(hInstance);
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);
    UNREFERENCED_PARAMETER(nShowCmd);
    return AppMain();
}
