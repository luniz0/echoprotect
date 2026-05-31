#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// EchoProtect runtime API.
// Buradaki implementasyon tamamen yereldir ve VMProtect DLL/SDK bağımlılığı içermez.

void EchoProtectBegin(const char* sectionName);
void EchoProtectBeginVirtualization(const char* sectionName);
void EchoProtectBeginMutation(const char* sectionName);
void EchoProtectBeginUltra(const char* sectionName);
void EchoProtectBeginVirtualizationLockByKey(const char* sectionName);
void EchoProtectBeginUltraLockByKey(const char* sectionName);
void EchoProtectEnd(void);

bool EchoProtectIsProtected();
bool EchoProtectIsDebuggerPresent(bool ignore);
bool EchoProtectIsVirtualMachinePresent(void);
bool EchoProtectIsValidImageCRC(void);
const char* EchoProtectDecryptStringA(const char* value);
const wchar_t* EchoProtectDecryptStringW(const wchar_t* value);
bool EchoProtectFreeString(const void* value);

#ifdef __cplusplus
}
#endif

