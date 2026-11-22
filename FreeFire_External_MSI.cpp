// FreeFire_External_MSI.cpp
// External ESP + Headshot + Map Hack
// For: MSI App Player Engine (BlueStacks based)
// Build: cl /O2 /EHsc FreeFire_External_MSI.cpp /link user32.lib gdi32.lib

#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <iostream>
#include <vector>
#include <string>
#include <cmath>
#include <thread>

#pragma comment(lib, "psapi.lib")

// ─────────────────────────────────────────────────────────────
// OFFSETS — Free Fire OB47 (Cheat Engine से verify करो)
// ─────────────────────────────────────────────────────────────
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

struct Vec3 { float x, y, z; };
struct Vec2 { float x, y; };

// ─────────────────────────────────────────────────────────────
// MSI App Player / BlueStacks Process Finder
// ─────────────────────────────────────────────────────────────
DWORD findMSIProcess() {
    // BlueStacks/MSI App Player process names
    const wchar_t* targets[] = {
        L"HD-Player.exe",        // BlueStacks 5 main
        L"Bluestacks.exe",       // older
        L"BstkSVC.exe",          // BlueStacks service
        L"MSIAppPlayer.exe",     // MSI branded
        L"AppPlayer.exe",
        nullptr
    };

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);

    DWORD found = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            for (int i = 0; targets[i]; i++) {
                if (_wcsicmp(pe.szExeFile, targets[i]) == 0) {
                    std::wcout << L"[+] Found: " << pe.szExeFile
                               << L" (PID " << pe.th32ProcessID << L")\n";
                    found = pe.th32ProcessID;
                    break;
                }
            }
            if (found) break;
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);

    if (!found) {
        // सभी processes print करो ताकि सही name पता चले
        std::cout << "[!] MSI App Player not found. Running processes:\n";
        snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(snap, &pe)) {
            do {
                wprintf(L"  [%5d] %s\n", pe.th32ProcessID, pe.szExeFile);
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
    }
    return found;
}

// ─────────────────────────────────────────────────────────────
// BlueStacks में libil2cpp.so base ढूंढो
// BlueStacks memory को mapped shared region में रखता है
// ─────────────────────────────────────────────────────────────
uintptr_t findLibil2cppBase(HANDLE hProcess) {
    // Method 1: Module list में ढूंढो
    HMODULE mods[1024];
    DWORD needed = 0;
    if (EnumProcessModulesEx(hProcess, mods, sizeof(mods), &needed, LIST_MODULES_ALL)) {
        DWORD count = needed / sizeof(HMODULE);
        for (DWORD i = 0; i < count; i++) {
            wchar_t name[MAX_PATH] = {};
            GetModuleFileNameExW(hProcess, mods[i], name, MAX_PATH);
            if (wcsstr(name, L"libil2cpp") || wcsstr(name, L"il2cpp")) {
                std::wcout << L"[+] libil2cpp.so found: " << name << L"\n";
                return (uintptr_t)mods[i];
            }
        }
    }

    // Method 2: Memory scan — ELF header (0x7F454C46) ढूंढो
    // BlueStacks large private regions में Android libraries map होती हैं
    std::cout << "[*] Scanning memory for libil2cpp...\n";
    MEMORY_BASIC_INFORMATION mbi{};
    uintptr_t addr = 0x10000;
    uintptr_t best = 0;
    size_t bestSize = 0;

    while (VirtualQueryEx(hProcess, (LPCVOID)addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & PAGE_READONLY || mbi.Protect & PAGE_EXECUTE_READ) &&
            mbi.RegionSize > 0x1000000) {  // >16MB = likely a big native lib
            
            // ELF magic check
            uint8_t magic[4] = {};
            ReadProcessMemory(hProcess, mbi.BaseAddress, magic, 4, nullptr);
            if (magic[0] == 0x7F && magic[1] == 'E' &&
                magic[2] == 'L'  && magic[3] == 'F') {
                if (mbi.RegionSize > bestSize) {
                    bestSize = mbi.RegionSize;
                    best = (uintptr_t)mbi.BaseAddress;
                    printf("[+] ELF found at 0x%llX, size 0x%llX\n",
                           (unsigned long long)best,
                           (unsigned long long)bestSize);
                }
            }
        }
        addr = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        if (addr < (uintptr_t)mbi.BaseAddress) break;  // overflow guard
    }

    return best;
}

// ─────────────────────────────────────────────────────────────
// Memory helpers
// ─────────────────────────────────────────────────────────────
HANDLE g_hProc   = nullptr;
uintptr_t g_base = 0;

template<typename T>
T Read(uintptr_t addr) {
    T val{};
    ReadProcessMemory(g_hProc, (LPCVOID)addr, &val, sizeof(T), nullptr);
    return val;
}

std::string ReadStr(uintptr_t addr) {
    char buf[64] = {};
    ReadProcessMemory(g_hProc, (LPCVOID)addr, buf, 63, nullptr);
    return buf;
}

// ─────────────────────────────────────────────────────────────
// Overlay
// ─────────────────────────────────────────────────────────────
HWND g_overlay  = nullptr;
int  g_W        = 1920, g_H = 1080;

struct Enemy {
    Vec3 pos, head;
    float hp;
    int team;
    char name[32];
    // Screen coords (filled by update thread)
    Vec2 screenHead, screenFeet;
    bool onScreen;
};

std::vector<Enemy> g_enemies;
bool g_lmbDown = false;

LRESULT CALLBACK OverlayWndProc(HWND hw, UINT msg, WPARAM wp, LPARAM lp) {
    if (msg == WM_PAINT) {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hw, &ps);
        HDC mem = CreateCompatibleDC(hdc);
        HBITMAP bmp = CreateCompatibleBitmap(hdc, g_W, g_H);
        SelectObject(mem, bmp);

        // Black = transparent (LWA_COLORKEY)
        RECT r = {0,0,g_W,g_H};
        FillRect(mem, &r, (HBRUSH)GetStockObject(BLACK_BRUSH));
        SetBkMode(mem, TRANSPARENT);

        for (auto& e : g_enemies) {
            if (!e.onScreen || e.hp <= 0) continue;

            float h = e.screenFeet.y - e.screenHead.y;
            if (h < 5.f || h > 1000.f) continue;
            float w = h * 0.4f;
            float L = e.screenHead.x - w/2;
            float T = e.screenHead.y;

            // ESP box — red
            HPEN pen = CreatePen(PS_SOLID, 2, RGB(255,50,50));
            HPEN old = (HPEN)SelectObject(mem, pen);
            MoveToEx(mem, (int)L,   (int)T,   nullptr);
            LineTo  (mem, (int)(L+w),(int)T);
            LineTo  (mem, (int)(L+w),(int)(T+h));
            LineTo  (mem, (int)L,   (int)(T+h));
            LineTo  (mem, (int)L,   (int)T);
            SelectObject(mem, old);
            DeleteObject(pen);

            // Name + HP
            char info[64];
            snprintf(info, 64, "%s [%.0f]", e.name, e.hp);
            SetTextColor(mem, RGB(255,220,50));
            TextOutA(mem, (int)L, (int)T - 16, info, (int)strlen(info));

            // HP bar
            HBRUSH hpBrush = CreateSolidBrush(RGB(50,255,50));
            float hpPct = e.hp / 200.f;
            RECT hpRect = {
                (int)L, (int)(T + h + 2),
                (int)(L + w * hpPct), (int)(T + h + 7)
            };
            FillRect(mem, &hpRect, hpBrush);
            DeleteObject(hpBrush);
        }

        BitBlt(hdc, 0,0,g_W,g_H, mem,0,0, SRCCOPY);
        DeleteObject(bmp);
        DeleteDC(mem);
        EndPaint(hw, &ps);
        return 0;
    }
    if (msg == WM_DESTROY) PostQuitMessage(0);
    return DefWindowProcW(hw, msg, wp, lp);
}

void createOverlay() {
    WNDCLASSEXW wc{};
    wc.cbSize      = sizeof(wc);
    wc.lpfnWndProc = OverlayWndProc;
    wc.hInstance   = GetModuleHandle(nullptr);
    wc.lpszClassName = L"FFOverlay";
    RegisterClassExW(&wc);

    g_overlay = CreateWindowExW(
        WS_EX_TOPMOST | WS_EX_TRANSPARENT | WS_EX_LAYERED | WS_EX_TOOLWINDOW,
        L"FFOverlay", L"", WS_POPUP,
        0, 0, g_W, g_H,
        nullptr, nullptr, GetModuleHandle(nullptr), nullptr
    );

    SetLayeredWindowAttributes(g_overlay, RGB(0,0,0), 0, LWA_COLORKEY);

    // Anti-screenshot — Garena screenshot detection से बचाओ
    SetWindowDisplayAffinity(g_overlay, WDA_EXCLUDEFROMCAPTURE);

    ShowWindow(g_overlay, SW_SHOW);
    UpdateWindow(g_overlay);
}

// ─────────────────────────────────────────────────────────────
// World to Screen
// ─────────────────────────────────────────────────────────────
struct Matrix4 { float m[16]; };
const uintptr_t OFF_VIEWMATRIX = 0x06D1B2F0; // OB47 approximate — calibrate!

bool W2S(Vec3 world, Vec2& screen, const Matrix4& vm) {
    float w = vm.m[12]*world.x + vm.m[13]*world.y + vm.m[14]*world.z + vm.m[15];
    if (w < 0.01f) return false;
    float x = vm.m[0]*world.x + vm.m[1]*world.y + vm.m[2]*world.z + vm.m[3];
    float y = vm.m[4]*world.x + vm.m[5]*world.y + vm.m[6]*world.z + vm.m[7];
    screen.x = (g_W/2.f) * (1.f + x/w);
    screen.y = (g_H/2.f) * (1.f - y/w);
    return screen.x > 0 && screen.x < g_W && screen.y > 0 && screen.y < g_H;
}

// ─────────────────────────────────────────────────────────────
// Aimbot
// ─────────────────────────────────────────────────────────────
const float AIM_FOV    = 120.f;  // pixel radius
const float AIM_SMOOTH = 0.55f;  // 0.0=instant 1.0=no move

void doAimbot() {
    if (g_enemies.empty()) return;

    float    minDist = AIM_FOV;
    Vec2     best    = {};
    bool     found   = false;

    Vec2 center = { g_W/2.f, g_H/2.f };

    for (auto& e : g_enemies) {
        if (!e.onScreen || e.hp <= 0) continue;
        float dx = e.screenHead.x - center.x;
        float dy = e.screenHead.y - center.y;
        float d  = sqrtf(dx*dx + dy*dy);
        if (d < minDist) {
            minDist = d;
            best    = e.screenHead;
            found   = true;
        }
    }

    if (found) {
        int dx = (int)((best.x - center.x) * AIM_SMOOTH);
        int dy = (int)((best.y - center.y) * AIM_SMOOTH);
        INPUT inp{};
        inp.type     = INPUT_MOUSE;
        inp.mi.dx    = dx;
        inp.mi.dy    = dy;
        inp.mi.dwFlags = MOUSEEVENTF_MOVE;
        SendInput(1, &inp, sizeof(INPUT));
    }
}

// ─────────────────────────────────────────────────────────────
// Mouse hook
// ─────────────────────────────────────────────────────────────
HHOOK g_hook = nullptr;
LRESULT CALLBACK MouseHook(int code, WPARAM wp, LPARAM lp) {
    if (code == HC_ACTION) {
        if (wp == WM_LBUTTONDOWN) g_lmbDown = true;
        if (wp == WM_LBUTTONUP)   g_lmbDown = false;
    }
    return CallNextHookEx(g_hook, code, wp, lp);
}

// ─────────────────────────────────────────────────────────────
// Update thread
// ─────────────────────────────────────────────────────────────
void updateLoop() {
    while (true) {
        Matrix4 vm = Read<Matrix4>(g_base + OFF_VIEWMATRIX);

        uintptr_t localBase = Read<uintptr_t>(g_base + Off::LocalPlayer);
        int myTeam = 0;
        if (localBase) myTeam = Read<int>(localBase + Off::TeamID);

        int count = min(Read<int>(g_base + Off::EntityCount), 60);
        g_enemies.clear();

        for (int i = 0; i < count; i++) {
            uintptr_t ePtr = Read<uintptr_t>(
                g_base + Off::EntityList + (uintptr_t)i * 8
            );
            if (!ePtr) continue;

            int team = Read<int>(ePtr + Off::TeamID);
            if (team == myTeam) continue;

            float hp = Read<float>(ePtr + Off::Health);
            if (hp <= 0.f) continue;

            Enemy e{};
            e.hp   = hp;
            e.team = team;
            e.pos  = Read<Vec3>(ePtr + Off::Position);

            // Head bone
            uintptr_t boneBase = Read<uintptr_t>(ePtr + Off::BoneMatrix);
            e.head = Read<Vec3>(boneBase + Off::BONE_HEAD * Off::BONE_STRIDE);

            auto ns = ReadStr(ePtr + Off::Name);
            strncpy_s(e.name, ns.c_str(), 31);

            // Screen projection
            Vec3 feet = e.pos;
            feet.y   -= 1.0f;
            e.onScreen = W2S(e.head, e.screenHead, vm) &&
                         W2S(feet,   e.screenFeet,  vm);

            g_enemies.push_back(e);
        }

        if (g_lmbDown) doAimbot();
        if (g_overlay)  InvalidateRect(g_overlay, nullptr, TRUE);

        Sleep(16);
    }
}

// ─────────────────────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────────────────────
int main() {
    SetConsoleTitleW(L"FF External | MSI App Player");
    std::cout << "=== Free Fire External | MSI App Player ===\n\n";

    DWORD pid = findMSIProcess();
    if (!pid) {
        std::cout << "\n[!] MSI App Player mein Free Fire pehle launch karo.\n";
        system("pause");
        return 1;
    }

    g_hProc = OpenProcess(
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid
    );
    if (!g_hProc) {
        DWORD err = GetLastError();
        printf("[!] OpenProcess failed: %lu\n", err);
        printf("    Admin rights se run karo (Run as Administrator)\n");
        system("pause");
        return 1;
    }

    g_base = findLibil2cppBase(g_hProc);
    if (!g_base) {
        std::cout << "[!] libil2cpp.so nahi mili.\n";
        std::cout << "    Free Fire fully load hone ke baad try karo.\n";
        system("pause");
        return 1;
    }
    printf("[+] Base: 0x%llX\n", (unsigned long long)g_base);

    g_W = GetSystemMetrics(SM_CXSCREEN);
    g_H = GetSystemMetrics(SM_CYSCREEN);

    createOverlay();
    std::cout << "[+] Overlay active\n";

    g_hook = SetWindowsHookExW(WH_MOUSE_LL, MouseHook, nullptr, 0);
    std::cout << "[+] LMB = aimbot snap to head\n";
    std::cout << "[+] ESP = red boxes + HP\n";
    std::cout << "[+] Running... (Ctrl+C to exit)\n\n";

    std::thread(updateLoop).detach();

    MSG msg{};
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    UnhookWindowsHookEx(g_hook);
    CloseHandle(g_hProc);
    return 0;
}
