#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <math.h>
#include <stdio.h>
#include <vector>
#include <string>
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "psapi.lib")

// ============================================================
//  CONFIG
// ============================================================
namespace Off {
    const uintptr_t EntityList   = 0x06E8C4B0;
    const uintptr_t EntityCount  = 0x06E8C4B8;
    const uintptr_t LocalPlayer  = 0x06E8C490;
    const uintptr_t Health       = 0x0DC;
    const uintptr_t TeamID       = 0x128;
    const uintptr_t BoneMatrix   = 0x1A0;
    const uintptr_t Position     = 0x168;
    const uintptr_t Name         = 0x228;
    const int       BONE_HEAD    = 8;
    const int       BONE_STRIDE  = 0x30;
}
const uintptr_t OFF_VIEWMATRIX  = 0x06D1B2F0;
const float     AIM_FOV         = 120.f;
const float     AIM_SMOOTH      = 0.55f;
const int       SCREEN_W        = 1920;
const int       SCREEN_H        = 1080;

// ============================================================
//  GLOBALS
// ============================================================
HANDLE  g_hProc  = nullptr;
DWORD   g_pid    = 0;
uintptr_t g_base = 0;

struct Vec2 { float x, y; };
struct Vec3 { float x, y, z; };
struct Matrix4 { float m[16]; };

// ============================================================
//  READ / WRITE MEMORY
// ============================================================
template<typename T>
T Read(uintptr_t addr) {
    T val{};
    ReadProcessMemory(g_hProc, (LPCVOID)addr, &val, sizeof(T), nullptr);
    return val;
}

// ============================================================
//  FIND MSI / BLUESTACKS PROCESS
// ============================================================
DWORD findMSIProcess() {
    const wchar_t* targets[] = {
        L"HD-Player.exe",
        L"Bluestacks.exe",
        L"BstkSVC.exe",
        L"MSIAppPlayer.exe",
        L"AppPlayer.exe",
        L"HD-MultiPlayer.exe",
        nullptr
    };

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    DWORD found = 0;

    printf("[*] Scanning processes...\n");
    if (Process32FirstW(snap, &pe)) {
        do {
            for (int i = 0; targets[i]; i++) {
                if (_wcsicmp(pe.szExeFile, targets[i]) == 0) {
                    printf("[+] Found: ");
                    wprintf(L"%s", pe.szExeFile);
                    printf(" PID=%lu\n", pe.th32ProcessID);
                    found = pe.th32ProcessID;
                }
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}

// ============================================================
//  FIND LIBIL2CPP BASE — 3 METHODS
// ============================================================

// Method 1: EnumProcessModulesEx
uintptr_t findByModuleEnum() {
    HMODULE mods[2048];
    DWORD needed = 0;
    if (!EnumProcessModulesEx(g_hProc, mods, sizeof(mods), &needed, LIST_MODULES_ALL))
        return 0;

    int count = needed / sizeof(HMODULE);
    for (int i = 0; i < count; i++) {
        char name[512] = {};
        GetModuleFileNameExA(g_hProc, mods[i], name, sizeof(name));
        if (strstr(name, "libil2cpp") || strstr(name, "il2cpp")) {
            printf("[+] Method1 found: %s @ 0x%llX\n", name, (uintptr_t)mods[i]);
            return (uintptr_t)mods[i];
        }
    }
    return 0;
}

// Method 2: Scan all MEM_PRIVATE large regions for ELF magic
uintptr_t findByELFScan() {
    printf("[*] Method2: ELF magic scan...\n");
    MEMORY_BASIC_INFORMATION mbi;
    uintptr_t addr = 0;
    int checked = 0;

    while (VirtualQueryEx(g_hProc, (LPCVOID)addr, &mbi, sizeof(mbi))) {
        if (mbi.RegionSize >= 0x100000 &&
            mbi.State == MEM_COMMIT &&
            (mbi.Type == MEM_PRIVATE || mbi.Type == MEM_MAPPED) &&
            (mbi.Protect & PAGE_READONLY || mbi.Protect & PAGE_READWRITE ||
             mbi.Protect & PAGE_EXECUTE_READ || mbi.Protect & PAGE_EXECUTE_READWRITE)) {

            BYTE hdr[8] = {};
            SIZE_T rd = 0;
            if (ReadProcessMemory(g_hProc, mbi.BaseAddress, hdr, 8, &rd) && rd == 8) {
                // ELF magic: 0x7F 'E' 'L' 'F'
                if (hdr[0] == 0x7F && hdr[1] == 'E' && hdr[2] == 'L' && hdr[3] == 'F') {
                    printf("[+] Method2 ELF @ 0x%llX size=0x%llX\n",
                           (uintptr_t)mbi.BaseAddress, (uintptr_t)mbi.RegionSize);
                    // Check if size looks like il2cpp (usually >50MB)
                    if (mbi.RegionSize > 50 * 1024 * 1024) {
                        printf("[+] Large ELF — likely libil2cpp! Base=0x%llX\n",
                               (uintptr_t)mbi.BaseAddress);
                        return (uintptr_t)mbi.BaseAddress;
                    }
                }
                checked++;
                if (checked % 500 == 0)
                    printf("[*] Scanned %d regions...\n", checked);
            }
        }
        addr = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        if (addr < (uintptr_t)mbi.BaseAddress) break;
    }
    return 0;
}

// Method 3: Scan for HP float value near known offsets
// Pass a list of candidate bases from Method2 ELF finds
uintptr_t findByHPFloat(std::vector<uintptr_t>& candidates) {
    printf("[*] Method3: HP float scan over %zu ELF candidates...\n", candidates.size());
    for (auto base : candidates) {
        // Try reading Health at known offset
        uintptr_t localPlayerPtr = 0;
        ReadProcessMemory(g_hProc,
            (LPCVOID)(base + Off::LocalPlayer),
            &localPlayerPtr, sizeof(localPlayerPtr), nullptr);

        if (localPlayerPtr > 0x1000 && localPlayerPtr < 0x7FFFFFFFFFFF) {
            float hp = 0;
            ReadProcessMemory(g_hProc,
                (LPCVOID)(localPlayerPtr + Off::Health),
                &hp, sizeof(hp), nullptr);

            if (hp > 1.f && hp <= 220.f) {
                printf("[!!!] FOUND! Base=0x%llX LocalPlayer=0x%llX HP=%.1f\n",
                       base, localPlayerPtr, hp);
                return base;
            }
        }
    }
    return 0;
}

// Master finder — tries all methods, collects all ELF regions
uintptr_t findLibil2cppBase() {
    // Method 1
    uintptr_t base = findByModuleEnum();
    if (base) return base;

    // Method 2+3: collect all ELF regions then check HP
    printf("[*] Collecting all ELF regions for HP validation...\n");
    MEMORY_BASIC_INFORMATION mbi;
    uintptr_t addr = 0;
    std::vector<uintptr_t> elfs;

    while (VirtualQueryEx(g_hProc, (LPCVOID)addr, &mbi, sizeof(mbi))) {
        if (mbi.RegionSize >= 0x100000 &&
            mbi.State == MEM_COMMIT &&
            (mbi.Type == MEM_PRIVATE || mbi.Type == MEM_MAPPED) &&
            (mbi.Protect == PAGE_READONLY || mbi.Protect == PAGE_READWRITE ||
             mbi.Protect == PAGE_EXECUTE_READ || mbi.Protect == PAGE_EXECUTE_READWRITE ||
             mbi.Protect == PAGE_EXECUTE_WRITECOPY)) {

            BYTE hdr[4] = {};
            SIZE_T rd = 0;
            if (ReadProcessMemory(g_hProc, mbi.BaseAddress, hdr, 4, &rd) && rd == 4) {
                if (hdr[0] == 0x7F && hdr[1] == 'E' && hdr[2] == 'L' && hdr[3] == 'F') {
                    elfs.push_back((uintptr_t)mbi.BaseAddress);
                    printf("[~] ELF @ 0x%llX size=0x%llX prot=0x%X\n",
                           (uintptr_t)mbi.BaseAddress,
                           (uintptr_t)mbi.RegionSize,
                           mbi.Protect);
                }
            }
        }
        addr = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        if (addr < (uintptr_t)mbi.BaseAddress) break;
    }

    printf("[*] Total ELF regions found: %zu\n", elfs.size());

    // Try HP validation
    if (!elfs.empty()) {
        base = findByHPFloat(elfs);
        if (base) return base;

        // Return largest ELF as best guess
        uintptr_t bestBase = 0;
        SIZE_T bestSize = 0;
        for (auto elfBase : elfs) {
            MEMORY_BASIC_INFORMATION info;
            VirtualQueryEx(g_hProc, (LPCVOID)elfBase, &info, sizeof(info));
            if (info.RegionSize > bestSize) {
                bestSize = info.RegionSize;
                bestBase = elfBase;
            }
        }
        if (bestBase) {
            printf("[?] Best guess (largest ELF): 0x%llX size=0x%llX\n", bestBase, (SIZE_T)bestSize);
            return bestBase;
        }
    }

    return 0;
}

// ============================================================
//  WORLD TO SCREEN
// ============================================================
bool W2S(Vec3 world, Vec2& screen, const Matrix4& vm) {
    float x = vm.m[0]*world.x + vm.m[1]*world.y + vm.m[2]*world.z  + vm.m[3];
    float y = vm.m[4]*world.x + vm.m[5]*world.y + vm.m[6]*world.z  + vm.m[7];
    float w = vm.m[12]*world.x + vm.m[13]*world.y + vm.m[14]*world.z + vm.m[15];
    if (w < 0.01f) return false;
    screen.x = (SCREEN_W / 2.f) * (1.f + x / w);
    screen.y = (SCREEN_H / 2.f) * (1.f - y / w);
    return true;
}

// ============================================================
//  OVERLAY
// ============================================================
HWND    g_hwndOverlay = nullptr;
HDC     g_hdc         = nullptr;

LRESULT CALLBACK OverlayProc(HWND hw, UINT msg, WPARAM wp, LPARAM lp) {
    if (msg == WM_PAINT) {
        PAINTSTRUCT ps;
        HDC dc = BeginPaint(hw, &ps);
        EndPaint(hw, &ps);
        return 0;
    }
    if (msg == WM_DESTROY) { PostQuitMessage(0); return 0; }
    return DefWindowProcW(hw, msg, wp, lp);
}

bool createOverlay() {
    WNDCLASSEXW wc = {};
    wc.cbSize        = sizeof(wc);
    wc.lpfnWndProc   = OverlayProc;
    wc.lpszClassName = L"FFOverlay";
    wc.hInstance     = GetModuleHandleW(nullptr);
    RegisterClassExW(&wc);

    g_hwndOverlay = CreateWindowExW(
        WS_EX_TOPMOST | WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOOLWINDOW,
        L"FFOverlay", L"",
        WS_POPUP,
        0, 0, SCREEN_W, SCREEN_H,
        nullptr, nullptr, GetModuleHandleW(nullptr), nullptr);

    if (!g_hwndOverlay) return false;

    SetLayeredWindowAttributes(g_hwndOverlay, RGB(0,0,0), 0, LWA_COLORKEY);
    SetWindowDisplayAffinity(g_hwndOverlay, WDA_EXCLUDEFROMCAPTURE);
    ShowWindow(g_hwndOverlay, SW_SHOW);
    UpdateWindow(g_hwndOverlay);
    return true;
}

void drawBox(HDC dc, Vec2 head, Vec2 feet, float hp) {
    float h = feet.y - head.y;
    if (h < 5 || h > 1200) return;
    float w = h * 0.4f;
    float cx = (head.x + feet.x) / 2.f;

    RECT rc = {
        (LONG)(cx - w/2), (LONG)(head.y),
        (LONG)(cx + w/2), (LONG)(feet.y)
    };

    // HP color: green→yellow→red
    COLORREF col = hp > 70 ? RGB(0,255,0) : (hp > 30 ? RGB(255,220,0) : RGB(255,50,50));
    HPEN pen = CreatePen(PS_SOLID, 2, col);
    HPEN old = (HPEN)SelectObject(dc, pen);

    MoveToEx(dc, rc.left,  rc.top,    nullptr);
    LineTo  (dc, rc.right, rc.top);
    LineTo  (dc, rc.right, rc.bottom);
    LineTo  (dc, rc.left,  rc.bottom);
    LineTo  (dc, rc.left,  rc.top);

    SelectObject(dc, old);
    DeleteObject(pen);

    // HP text
    char buf[16];
    sprintf_s(buf, "%.0f", hp);
    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, col);
    TextOutA(dc, rc.left, rc.top - 16, buf, (int)strlen(buf));
}

// ============================================================
//  AIMBOT
// ============================================================
bool g_lmbDown = false;

LRESULT CALLBACK MouseHook(int code, WPARAM wp, LPARAM lp) {
    if (code == HC_ACTION) {
        MSLLHOOKSTRUCT* ms = (MSLLHOOKSTRUCT*)lp;
        if (wp == WM_LBUTTONDOWN) g_lmbDown = true;
        if (wp == WM_LBUTTONUP)   g_lmbDown = false;
    }
    return CallNextHookEx(nullptr, code, wp, lp);
}

struct AimTarget { float dist; Vec2 screen; };

void doAimbot(std::vector<AimTarget>& targets) {
    if (!g_lmbDown || targets.empty()) return;

    float cx = SCREEN_W / 2.f, cy = SCREEN_H / 2.f;
    AimTarget* best = nullptr;
    float bestDist = AIM_FOV;

    for (auto& t : targets) {
        float d = sqrtf((t.screen.x-cx)*(t.screen.x-cx) + (t.screen.y-cy)*(t.screen.y-cy));
        if (d < bestDist) { bestDist = d; best = &t; }
    }

    if (best) {
        float dx = (best->screen.x - cx) * AIM_SMOOTH;
        float dy = (best->screen.y - cy) * AIM_SMOOTH;
        INPUT in = {};
        in.type = INPUT_MOUSE;
        in.mi.dwFlags = MOUSEEVENTF_MOVE;
        in.mi.dx = (LONG)dx;
        in.mi.dy = (LONG)dy;
        SendInput(1, &in, sizeof(INPUT));
    }
}

// ============================================================
//  MAIN LOOP
// ============================================================
void mainLoop() {
    HHOOK mouseHook = SetWindowsHookExW(WH_MOUSE_LL, MouseHook, nullptr, 0);

    while (true) {
        // Check if game still running
        DWORD exitCode = 0;
        GetExitCodeProcess(g_hProc, &exitCode);
        if (exitCode != STILL_ACTIVE) {
            printf("[-] Process exited.\n");
            break;
        }

        // Read view matrix
        Matrix4 vm = Read<Matrix4>(g_base + OFF_VIEWMATRIX);

        // Read entity list
        uintptr_t localPlayer = Read<uintptr_t>(g_base + Off::LocalPlayer);
        int        entityCount = Read<int>(g_base + Off::EntityCount);
        uintptr_t entityList  = Read<uintptr_t>(g_base + Off::EntityList);

        int myTeam = 0;
        if (localPlayer) myTeam = Read<int>(localPlayer + Off::TeamID);

        // Clear overlay
        HDC dc = GetDC(g_hwndOverlay);
        HBRUSH black = CreateSolidBrush(RGB(0,0,0));
        RECT full = {0, 0, SCREEN_W, SCREEN_H};
        FillRect(dc, &full, black);
        DeleteObject(black);

        std::vector<AimTarget> aimbotTargets;

        for (int i = 0; i < entityCount && i < 64; i++) {
            uintptr_t entity = Read<uintptr_t>(entityList + i * 8);
            if (!entity) continue;

            int team = Read<int>(entity + Off::TeamID);
            if (team == myTeam) continue;

            float hp = Read<float>(entity + Off::Health);
            if (hp <= 0 || hp > 220) continue;

            Vec3 pos  = Read<Vec3>(entity + Off::Position);
            Vec3 boneBase = Read<Vec3>(entity + Off::BoneMatrix + Off::BONE_HEAD * Off::BONE_STRIDE);

            Vec2 headScreen, feetScreen;
            if (!W2S(boneBase, headScreen, vm)) continue;
            if (!W2S(pos, feetScreen, vm)) continue;

            drawBox(dc, headScreen, feetScreen, hp);

            float cx = SCREEN_W / 2.f, cy = SCREEN_H / 2.f;
            float d = sqrtf((headScreen.x-cx)*(headScreen.x-cx)+(headScreen.y-cy)*(headScreen.y-cy));
            aimbotTargets.push_back({d, headScreen});
        }

        doAimbot(aimbotTargets);
        ReleaseDC(g_hwndOverlay, dc);

        // Message pump
        MSG msg;
        while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }

        Sleep(1);
    }

    if (mouseHook) UnhookWindowsHookEx(mouseHook);
}

// ============================================================
//  ENTRY POINT
// ============================================================
int main() {
    printf("=== Free Fire External | MSI App Player ===\n\n");

    // Find process
    g_pid = findMSIProcess();
    if (!g_pid) {
        printf("[-] No emulator found. Launch MSI App Player first.\n");
        system("pause");
        return 1;
    }

    // Open process
    g_hProc = OpenProcess(
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
        FALSE, g_pid);
    if (!g_hProc) {
        printf("[-] OpenProcess failed. Run as Admin.\n");
        system("pause");
        return 1;
    }
    printf("[+] Process opened.\n");

    // Find libil2cpp
    printf("[*] Searching libil2cpp.so...\n");
    g_base = findLibil2cppBase();

    if (!g_base) {
        printf("[-] libil2cpp not found.\n");
        printf("[!] Make sure Free Fire is RUNNING in the emulator.\n");
        printf("[!] Open a match, then relaunch this tool.\n");
        system("pause");
        return 1;
    }

    printf("[+] g_base = 0x%llX\n", g_base);
    printf("[+] Starting overlay...\n");

    // Create overlay
    if (!createOverlay()) {
        printf("[-] Overlay creation failed.\n");
        system("pause");
        return 1;
    }

    printf("[+] ESP Active. LMB = Aimbot.\n");
    mainLoop();

    CloseHandle(g_hProc);
    return 0;
}
