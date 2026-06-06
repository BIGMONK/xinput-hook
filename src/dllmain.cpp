/**
 * xinput9_1_0.dll - WinHTTP + WinINet Inline Hook
 * 通过劫持xinput9_1_0.dll（XInput手柄库）注入到3D-KSZW.exe
 *
 * 优势：
 * - UnityPlayer.dll导入了xinput9_1_0.dll，启动时即加载
 * - 游戏运行期间不会卸载（手柄轮询需要）
 * - 只需转发4个导出函数，极其简单
 * - DllMain中加载winhttp.dll并安装Inline Hook
 */

#include <windows.h>
#include <winhttp.h>
#include <wininet.h>
#include <cstring>
#include <cstdio>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "wininet.lib")

// ============================================================
// 配置：要拦截的URL路径和返回数据
// ============================================================

static const char* TARGET_PATH = "/ksuserjk/checkUser";
static const char* FAKE_RESPONSE = "{\"code\":200,\"data\":{\"userId\":\"hooked\",\"status\":1},\"msg\":\"success\"}";

// ============================================================
// 日志系统
// ============================================================

static const char* g_logPath = "C:\\Users\\Twan\\Desktop\\xinput-hook.log";
static CRITICAL_SECTION g_logCs;

static void Log(const char* fmt, ...) {
    EnterCriticalSection(&g_logCs);
    FILE* f = nullptr;
    fopen_s(&f, g_logPath, "a");
    if (f) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        fprintf(f, "[%02d:%02d:%02d.%03d] ", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
        va_list args;
        va_start(args, fmt);
        vfprintf(f, fmt, args);
        va_end(args);
        fprintf(f, "\n");
        fclose(f);
    }
    LeaveCriticalSection(&g_logCs);
}

// ============================================================
// x86 Inline Hook 引擎
// ============================================================

#pragma pack(push, 1)
struct JmpRel {
    BYTE  opcode;     // 0xE9
    DWORD offset;
};
#pragma pack(pop)

struct HookContext {
    void*   target;
    void*   detour;
    void*   trampoline;
    BYTE    origBytes[8];
    DWORD   origSize;
    BOOL    installed;
};

static HookContext g_hooks[16] = {};
static int g_hookCount = 0;
static CRITICAL_SECTION g_cs;

static BOOL InstallHook(void* target, void* detour, void** origFunc) {
    if (g_hookCount >= 16) return FALSE;

    HookContext* ctx = &g_hooks[g_hookCount];
    ctx->target = target;
    ctx->detour = detour;
    memcpy(ctx->origBytes, target, 8);

    JmpRel jmp;
    jmp.opcode = 0xE9;
    jmp.offset = (DWORD)((UINT_PTR)detour - (UINT_PTR)target - 5);
    ctx->origSize = 5;

    ctx->trampoline = VirtualAlloc(NULL, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!ctx->trampoline) {
        Log("VirtualAlloc失败: %u", GetLastError());
        return FALSE;
    }

    memcpy(ctx->trampoline, ctx->origBytes, ctx->origSize);
    JmpRel* trampolineJmp = (JmpRel*)((BYTE*)ctx->trampoline + ctx->origSize);
    trampolineJmp->opcode = 0xE9;
    trampolineJmp->offset = (DWORD)((UINT_PTR)target + 5 - (UINT_PTR)trampolineJmp - 5);

    *origFunc = ctx->trampoline;

    DWORD oldProt;
    if (!VirtualProtect(target, 8, PAGE_EXECUTE_READWRITE, &oldProt)) {
        Log("VirtualProtect失败: %u", GetLastError());
        VirtualFree(ctx->trampoline, 0, MEM_RELEASE);
        return FALSE;
    }

    memcpy(target, &jmp, sizeof(jmp));
    VirtualProtect(target, 8, oldProt, &oldProt);
    FlushInstructionCache(GetCurrentProcess(), target, 8);

    ctx->installed = TRUE;
    g_hookCount++;
    return TRUE;
}

// ============================================================
// WinHTTP Hook 函数指针
// ============================================================

typedef HINTERNET (WINAPI *pWinHttpOpenRequest)(
    HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD);
typedef BOOL (WINAPI *pWinHttpReceiveResponse)(HINTERNET, LPVOID);
typedef BOOL (WINAPI *pWinHttpReadData)(HINTERNET, LPVOID, DWORD, LPDWORD);
typedef BOOL (WINAPI *pWinHttpCloseHandle)(HINTERNET);

static pWinHttpOpenRequest     g_origWinHttpOpenRequest = NULL;
static pWinHttpReceiveResponse g_origWinHttpReceiveResponse = NULL;
static pWinHttpReadData        g_origWinHttpReadData = NULL;
static pWinHttpCloseHandle     g_origWinHttpCloseHandle = NULL;

// ============================================================
// WinINet Hook 函数指针
// ============================================================

typedef HINTERNET (WINAPI *pHttpOpenRequestA)(
    HINTERNET, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPCSTR*, DWORD);
typedef HINTERNET (WINAPI *pHttpOpenRequestW)(
    HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD);
typedef BOOL (WINAPI *pHttpSendRequestA)(HINTERNET, LPCSTR, DWORD, LPVOID, DWORD);
typedef BOOL (WINAPI *pHttpSendRequestW)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD);
typedef BOOL (WINAPI *pInternetReadFile)(HINTERNET, LPVOID, DWORD, LPDWORD);
typedef BOOL (WINAPI *pInternetCloseHandle)(HINTERNET);

static pHttpOpenRequestA   g_origHttpOpenRequestA = NULL;
static pHttpOpenRequestW   g_origHttpOpenRequestW = NULL;
static pHttpSendRequestA   g_origHttpSendRequestA = NULL;
static pHttpSendRequestW   g_origHttpSendRequestW = NULL;
static pInternetReadFile   g_origInternetReadFile = NULL;
static pInternetCloseHandle g_origInternetCloseHandle = NULL;

// ============================================================
// 被拦截的请求句柄集合
// ============================================================

#define MAX_TRACKED 64
static HINTERNET g_trackedRequests[MAX_TRACKED] = {};
static int g_trackedCount = 0;

static BOOL IsTracked(HINTERNET h) {
    EnterCriticalSection(&g_cs);
    for (int i = 0; i < g_trackedCount; i++) {
        if (g_trackedRequests[i] == h) {
            LeaveCriticalSection(&g_cs);
            return TRUE;
        }
    }
    LeaveCriticalSection(&g_cs);
    return FALSE;
}

static void TrackRequest(HINTERNET h) {
    EnterCriticalSection(&g_cs);
    if (g_trackedCount < MAX_TRACKED) {
        g_trackedRequests[g_trackedCount++] = h;
    }
    LeaveCriticalSection(&g_cs);
}

static void UntrackRequest(HINTERNET h) {
    EnterCriticalSection(&g_cs);
    for (int i = 0; i < g_trackedCount; i++) {
        if (g_trackedRequests[i] == h) {
            g_trackedRequests[i] = g_trackedRequests[--g_trackedCount];
            break;
        }
    }
    LeaveCriticalSection(&g_cs);
}

// ============================================================
// WinHTTP Hook 实现
// ============================================================

HINTERNET WINAPI Hook_WinHttpOpenRequest(
    HINTERNET hConnect, LPCWSTR pwszVerb, LPCWSTR pwszObjectName,
    LPCWSTR pwszVersion, LPCWSTR pwszReferrer, LPCWSTR* ppwszAcceptTypes, DWORD dwFlags)
{
    if (pwszObjectName) {
        char pathA[512] = {};
        WideCharToMultiByte(CP_ACP, 0, pwszObjectName, -1, pathA, 512, NULL, NULL);
        Log("WinHttpOpenRequest: %s", pathA);

        if (strstr(pathA, TARGET_PATH)) {
            Log("*** 拦截WinHTTP请求: %s ***", pathA);
            HINTERNET hReq = g_origWinHttpOpenRequest(hConnect, pwszVerb, pwszObjectName,
                pwszVersion, pwszReferrer, ppwszAcceptTypes, dwFlags);
            if (hReq) TrackRequest(hReq);
            return hReq;
        }
    }
    return g_origWinHttpOpenRequest(hConnect, pwszVerb, pwszObjectName,
        pwszVersion, pwszReferrer, ppwszAcceptTypes, dwFlags);
}

BOOL WINAPI Hook_WinHttpReceiveResponse(HINTERNET hRequest, LPVOID lpReserved) {
    if (IsTracked(hRequest)) {
        Log("WinHttpReceiveResponse: 被拦截请求");
    }
    return g_origWinHttpReceiveResponse(hRequest, lpReserved);
}

BOOL WINAPI Hook_WinHttpReadData(HINTERNET hRequest, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead) {
    if (IsTracked(hRequest)) {
        Log("WinHttpReadData: 返回假数据 (%d字节)", (int)strlen(FAKE_RESPONSE));
        DWORD len = (DWORD)strlen(FAKE_RESPONSE);
        if (len > dwNumberOfBytesToRead) len = dwNumberOfBytesToRead;
        memcpy(lpBuffer, FAKE_RESPONSE, len);
        if (lpdwNumberOfBytesRead) *lpdwNumberOfBytesRead = len;
        return TRUE;
    }
    return g_origWinHttpReadData(hRequest, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead);
}

BOOL WINAPI Hook_WinHttpCloseHandle(HINTERNET hInternet) {
    if (IsTracked(hInternet)) {
        UntrackRequest(hInternet);
    }
    return g_origWinHttpCloseHandle(hInternet);
}

// ============================================================
// WinINet Hook 实现
// ============================================================

HINTERNET WINAPI Hook_HttpOpenRequestA(
    HINTERNET hConnect, LPCSTR lpszVerb, LPCSTR lpszObjectName,
    LPCSTR lpszVersion, LPCSTR lpszReferrer, LPCSTR* lplpszAcceptTypes, DWORD dwFlags)
{
    if (lpszObjectName) {
        Log("HttpOpenRequestA: %s", lpszObjectName);
        if (strstr(lpszObjectName, TARGET_PATH)) {
            Log("*** 拦截WinINet-A请求: %s ***", lpszObjectName);
            HINTERNET hReq = g_origHttpOpenRequestA(hConnect, lpszVerb, lpszObjectName,
                lpszVersion, lpszReferrer, lplpszAcceptTypes, dwFlags);
            if (hReq) TrackRequest(hReq);
            return hReq;
        }
    }
    return g_origHttpOpenRequestA(hConnect, lpszVerb, lpszObjectName,
        lpszVersion, lpszReferrer, lplpszAcceptTypes, dwFlags);
}

HINTERNET WINAPI Hook_HttpOpenRequestW(
    HINTERNET hConnect, LPCWSTR lpszVerb, LPCWSTR lpszObjectName,
    LPCWSTR lpszVersion, LPCWSTR lpszReferrer, LPCWSTR* lplpszAcceptTypes, DWORD dwFlags)
{
    if (lpszObjectName) {
        char pathA[512] = {};
        WideCharToMultiByte(CP_ACP, 0, lpszObjectName, -1, pathA, 512, NULL, NULL);
        Log("HttpOpenRequestW: %s", pathA);
        if (strstr(pathA, TARGET_PATH)) {
            Log("*** 拦截WinINet-W请求: %s ***", pathA);
            HINTERNET hReq = g_origHttpOpenRequestW(hConnect, lpszVerb, lpszObjectName,
                lpszVersion, lpszReferrer, lplpszAcceptTypes, dwFlags);
            if (hReq) TrackRequest(hReq);
            return hReq;
        }
    }
    return g_origHttpOpenRequestW(hConnect, lpszVerb, lpszObjectName,
        lpszVersion, lpszReferrer, lplpszAcceptTypes, dwFlags);
}

BOOL WINAPI Hook_HttpSendRequestA(HINTERNET hRequest, LPCSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength) {
    if (IsTracked(hRequest)) {
        Log("HttpSendRequestA: 被拦截请求");
    }
    return g_origHttpSendRequestA(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength);
}

BOOL WINAPI Hook_HttpSendRequestW(HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength) {
    if (IsTracked(hRequest)) {
        Log("HttpSendRequestW: 被拦截请求");
    }
    return g_origHttpSendRequestW(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength);
}

BOOL WINAPI Hook_InternetReadFile(HINTERNET hFile, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead) {
    if (IsTracked(hFile)) {
        Log("InternetReadFile: 返回假数据 (%d字节)", (int)strlen(FAKE_RESPONSE));
        DWORD len = (DWORD)strlen(FAKE_RESPONSE);
        if (len > dwNumberOfBytesToRead) len = dwNumberOfBytesToRead;
        memcpy(lpBuffer, FAKE_RESPONSE, len);
        if (lpdwNumberOfBytesRead) *lpdwNumberOfBytesRead = len;
        return TRUE;
    }
    return g_origInternetReadFile(hFile, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead);
}

BOOL WINAPI Hook_InternetCloseHandle(HINTERNET hInternet) {
    if (IsTracked(hInternet)) {
        UntrackRequest(hInternet);
    }
    return g_origInternetCloseHandle(hInternet);
}

// ============================================================
// 系统 xinput9_1_0.dll 函数转发（仅4个！）
// ============================================================

static HMODULE g_hRealXInput = NULL;

typedef DWORD (WINAPI *pXInputGetState)(DWORD, XINPUT_STATE*);
typedef DWORD (WINAPI *pXInputSetState)(DWORD, XINPUT_VIBRATION*);
typedef DWORD (WINAPI *pXInputGetCapabilities)(DWORD, DWORD, XINPUT_CAPABILITIES*);
typedef void  (WINAPI *pXInputEnable)(BOOL);

static pXInputGetState        g_pXInputGetState = NULL;
static pXInputSetState        g_pXInputSetState = NULL;
static pXInputGetCapabilities g_pXInputGetCapabilities = NULL;
static pXInputEnable          g_pXInputEnable = NULL;

static void InitForwards() {
    // xinput9_1_0.dll 在system32目录下
    wchar_t sysPath[MAX_PATH];
    GetSystemDirectoryW(sysPath, MAX_PATH);
    wcscat_s(sysPath, MAX_PATH, L"\\xinput9_1_0.dll");

    g_hRealXInput = LoadLibraryW(sysPath);
    if (!g_hRealXInput) {
        // 备用：尝试xinput1_4
        GetSystemDirectoryW(sysPath, MAX_PATH);
        wcscat_s(sysPath, MAX_PATH, L"\\xinput1_4.dll");
        g_hRealXInput = LoadLibraryW(sysPath);
    }
    if (!g_hRealXInput) {
        Log("无法加载系统xinput DLL!");
        return;
    }

    g_pXInputGetState = (pXInputGetState)GetProcAddress(g_hRealXInput, "XInputGetState");
    g_pXInputSetState = (pXInputSetState)GetProcAddress(g_hRealXInput, "XInputSetState");
    g_pXInputGetCapabilities = (pXInputGetCapabilities)GetProcAddress(g_hRealXInput, "XInputGetCapabilities");
    g_pXInputEnable = (pXInputEnable)GetProcAddress(g_hRealXInput, "XInputEnable");

    Log("系统xinput已加载, base=%p", g_hRealXInput);
}

// 转发函数
DWORD WINAPI Fwd_XInputGetState(DWORD dwUserIndex, XINPUT_STATE* pState) {
    return g_pXInputGetState ? g_pXInputGetState(dwUserIndex, pState) : ERROR_DEVICE_NOT_CONNECTED;
}

DWORD WINAPI Fwd_XInputSetState(DWORD dwUserIndex, XINPUT_VIBRATION* pVibration) {
    return g_pXInputSetState ? g_pXInputSetState(dwUserIndex, pVibration) : ERROR_DEVICE_NOT_CONNECTED;
}

DWORD WINAPI Fwd_XInputGetCapabilities(DWORD dwUserIndex, DWORD dwFlags, XINPUT_CAPABILITIES* pCapabilities) {
    return g_pXInputGetCapabilities ? g_pXInputGetCapabilities(dwUserIndex, dwFlags, pCapabilities) : ERROR_DEVICE_NOT_CONNECTED;
}

void WINAPI Fwd_XInputEnable(BOOL enable) {
    if (g_pXInputEnable) g_pXInputEnable(enable);
}

// ============================================================
// Hook安装
// ============================================================

static void HookWinHttp(HMODULE hWinHttp) {
    Log("Hook winhttp.dll, base=%p", hWinHttp);

    void* pOpenRequest = (void*)GetProcAddress(hWinHttp, "WinHttpOpenRequest");
    void* pReceiveResponse = (void*)GetProcAddress(hWinHttp, "WinHttpReceiveResponse");
    void* pReadData = (void*)GetProcAddress(hWinHttp, "WinHttpReadData");
    void* pCloseHandle = (void*)GetProcAddress(hWinHttp, "WinHttpCloseHandle");

    if (pOpenRequest && InstallHook(pOpenRequest, (void*)Hook_WinHttpOpenRequest, (void**)&g_origWinHttpOpenRequest))
        Log("Hook WinHttpOpenRequest 成功");
    if (pReceiveResponse && InstallHook(pReceiveResponse, (void*)Hook_WinHttpReceiveResponse, (void**)&g_origWinHttpReceiveResponse))
        Log("Hook WinHttpReceiveResponse 成功");
    if (pReadData && InstallHook(pReadData, (void*)Hook_WinHttpReadData, (void**)&g_origWinHttpReadData))
        Log("Hook WinHttpReadData 成功");
    if (pCloseHandle && InstallHook(pCloseHandle, (void*)Hook_WinHttpCloseHandle, (void**)&g_origWinHttpCloseHandle))
        Log("Hook WinHttpCloseHandle 成功");
}

static void HookWinInet(HMODULE hWinInet) {
    Log("Hook wininet.dll, base=%p", hWinInet);

    void* pHttpOpenRequestA = (void*)GetProcAddress(hWinInet, "HttpOpenRequestA");
    void* pHttpOpenRequestW = (void*)GetProcAddress(hWinInet, "HttpOpenRequestW");
    void* pHttpSendRequestA = (void*)GetProcAddress(hWinInet, "HttpSendRequestA");
    void* pHttpSendRequestW = (void*)GetProcAddress(hWinInet, "HttpSendRequestW");
    void* pInternetReadFile = (void*)GetProcAddress(hWinInet, "InternetReadFile");
    void* pInternetCloseHandle = (void*)GetProcAddress(hWinInet, "InternetCloseHandle");

    if (pHttpOpenRequestA && InstallHook(pHttpOpenRequestA, (void*)Hook_HttpOpenRequestA, (void**)&g_origHttpOpenRequestA))
        Log("Hook HttpOpenRequestA 成功");
    if (pHttpOpenRequestW && InstallHook(pHttpOpenRequestW, (void*)Hook_HttpOpenRequestW, (void**)&g_origHttpOpenRequestW))
        Log("Hook HttpOpenRequestW 成功");
    if (pHttpSendRequestA && InstallHook(pHttpSendRequestA, (void*)Hook_HttpSendRequestA, (void**)&g_origHttpSendRequestA))
        Log("Hook HttpSendRequestA 成功");
    if (pHttpSendRequestW && InstallHook(pHttpSendRequestW, (void*)Hook_HttpSendRequestW, (void**)&g_origHttpSendRequestW))
        Log("Hook HttpSendRequestW 成功");
    if (pInternetReadFile && InstallHook(pInternetReadFile, (void*)Hook_InternetReadFile, (void**)&g_origInternetReadFile))
        Log("Hook InternetReadFile 成功");
    if (pInternetCloseHandle && InstallHook(pInternetCloseHandle, (void*)Hook_InternetCloseHandle, (void**)&g_origInternetCloseHandle))
        Log("Hook InternetCloseHandle 成功");
}

// 后台线程：等待winhttp.dll加载后Hook
static DWORD WINAPI BackgroundThread(LPVOID param) {
    Log("后台线程启动, 等待winhttp.dll...");

    for (int i = 0; i < 120; i++) {
        HMODULE hWinHttp = GetModuleHandleA("winhttp.dll");
        if (hWinHttp) {
            HookWinHttp(hWinHttp);
            break;
        }
        Sleep(500);
    }

    if (!g_origWinHttpOpenRequest) {
        Log("后台线程: 60秒后winhttp.dll仍未加载");
    }

    Log("后台线程: Hook任务完成");
    return 0;
}

// ============================================================
// DLL入口点
// ============================================================

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        DisableThreadLibraryCalls(hModule);
        InitializeCriticalSection(&g_cs);
        InitializeCriticalSection(&g_logCs);

        // 加载系统xinput并转发函数
        InitForwards();

        // 清空日志
        FILE* f = nullptr;
        fopen_s(&f, g_logPath, "w");
        if (f) fclose(f);
        Log("xinput9_1_0.dll 已加载 (劫持版), hModule=%p", hModule);
        Log("PID=%u", GetCurrentProcessId());

        // 立即Hook已加载的DLL
        HMODULE hWinHttp = GetModuleHandleA("winhttp.dll");
        if (hWinHttp) {
            HookWinHttp(hWinHttp);
        } else {
            Log("winhttp.dll 尚未加载，创建后台线程等待");
        }

        HMODULE hWinInet = GetModuleHandleA("wininet.dll");
        if (hWinInet) {
            HookWinInet(hWinInet);
        } else {
            Log("wininet.dll 尚未加载，创建后台线程等待");
            // 同时等待wininet
            CreateThread(NULL, 0, [](LPVOID p) -> DWORD {
                Log("后台线程(wininet): 等待wininet.dll...");
                for (int i = 0; i < 120; i++) {
                    HMODULE h = GetModuleHandleA("wininet.dll");
                    if (h) { HookWinInet(h); break; }
                    Sleep(500);
                }
                return 0;
            }, NULL, 0, NULL);
        }

        // 如果winhttp还没加载，创建后台线程等待
        if (!hWinHttp) {
            CreateThread(NULL, 0, BackgroundThread, NULL, 0, NULL);
        }

        Log("初始化完成，DLL将常驻内存");
        break;
    }

    case DLL_PROCESS_DETACH:
        Log("xinput9_1_0.dll 卸载");
        DeleteCriticalSection(&g_cs);
        DeleteCriticalSection(&g_logCs);
        break;
    }
    return TRUE;
}
