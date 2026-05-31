#include "EchoProtectSDK.h"
#include <windows.h>
#include <atomic>
#include <cstring>
#include <cstdlib>

static std::atomic<int> g_echo_protect_nesting{0};
static const char* g_echo_protect_section = nullptr;

extern "C" {

void EchoProtectBegin(const char* section) {
    InterlockedIncrement(&g_echo_protect_nesting);
    g_echo_protect_section = section;
    // Yerel projede gerçek sanallaştırma sadece işaretleri okuyacaktır.
    // Bu fonksiyon, korumalı blokların soyutlanması için API sağlar.
    (void)section;
}

void EchoProtectBeginVirtualization(const char* section) {
    EchoProtectBegin(section);
}

void EchoProtectBeginMutation(const char* section) {
    EchoProtectBegin(section);
}

void EchoProtectBeginUltra(const char* section) {
    EchoProtectBegin(section);
}

void EchoProtectBeginVirtualizationLockByKey(const char* section) {
    EchoProtectBegin(section);
}

void EchoProtectBeginUltraLockByKey(const char* section) {
    EchoProtectBegin(section);
}

void EchoProtectEnd(void) {
    if (g_echo_protect_nesting.load(std::memory_order_acquire) > 0) {
        InterlockedDecrement(&g_echo_protect_nesting);
    }
    if (g_echo_protect_nesting.load(std::memory_order_acquire) == 0) {
        g_echo_protect_section = nullptr;
    }
}

bool EchoProtectIsProtected() {
    return g_echo_protect_nesting.load(std::memory_order_acquire) > 0;
}

bool EchoProtectIsDebuggerPresent(bool ignore) {
    (void)ignore;
    return IsDebuggerPresent() != FALSE;
}

bool EchoProtectIsVirtualMachinePresent(void) {
    // Yerel uygulama içinde VM algılama için kendi koruma katmanınızı ekleyebilirsiniz.
    return false;
}

bool EchoProtectIsValidImageCRC(void) {
    // Kendi bütünlük doğrulama mekanizmanızı uygulamak için genişletilebilir.
    return true;
}

const char* EchoProtectDecryptStringA(const char* value) {
    if (!value) return nullptr;
    size_t len = std::strlen(value) + 1;
    char* buffer = static_cast<char*>(std::malloc(len));
    if (!buffer) return nullptr;
    std::memcpy(buffer, value, len);
    return buffer;
}

const wchar_t* EchoProtectDecryptStringW(const wchar_t* value) {
    if (!value) return nullptr;
    size_t len = std::wcslen(value) + 1;
    wchar_t* buffer = static_cast<wchar_t*>(std::malloc(len * sizeof(wchar_t)));
    if (!buffer) return nullptr;
    std::memcpy(buffer, value, len * sizeof(wchar_t));
    return buffer;
}

bool EchoProtectFreeString(const void* value) {
    if (!value) return false;
    std::free(const_cast<void*>(value));
    return true;
}

} // extern "C"
