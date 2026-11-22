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
HANDLE    g_hProc  = nullptr;
DWORD     g_pid    = 0;
uintptr_t g_base   = 0;

struct Vec2 { float x, y; };
struct Vec3 { float x, y, z; };
struct Matrix4 { float m[16]; };

template<typename T>
T Read(uintptr_t addr) {
    T val{};
    ReadProcessMemory(g_hProc, (LPCVOID)addr, &val, sizeof(T), nullptr);
    return val;
}

// ============================================================
//  SCAN ALL PROCESSES — find the one with ELF + HP
// ============================================================
struct ProcInfo { DWORD pid; char name[260]; };

std::vector<ProcInfo> getAllProcesses() {
    std::vector<ProcInfo> list;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return list;
    PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            ProcInfo pi;
            pi.pid = pe.th32ProcessID;
            WideCharToMultiByte(CP_ACP, 0, pe.szExeFile, -1, pi.name, 260, nullptr, nullptr);
            list.push_back(pi);
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return list;
}

// Scan one process for ELF magic — returns all ELF bases found
std::vector<uintptr_t> scanELF(HANDLE hProc) {
    std::vector<uintptr_t> elfs;
    MEMORY_BASIC_INFORMATION mbi;
    uintptr_t addr = 0;
    while (VirtualQueryEx(hProc, (LPCVOID)addr, &mbi, sizeof(mbi))) {
        if (mbi.RegionSize >= 0x100000 &&
            mbi.State == MEM_COMMIT &&
            (mbi.Protect == PAGE_READONLY ||
             mbi.Protect == PAGE_READWRITE ||
             mbi.Protect == PAGE_EXECUTE_READ ||
             mbi.Protect == PAGE_EXECUTE_READWRITE ||
             mbi.Protect == PAGE_EXECUTE_WRITECOPY ||
             mbi.Protect == PAGE_WRITECOPY)) {
            BYTE hdr[4] = {}; SIZE_T rd = 0;
            if (ReadProcessMemory(hProc, mbi.BaseAddress, hdr, 4, &rd) && rd == 4) {
                if (hdr[0]==0x7F && hdr[1]=='E' && hdr[2]=='L' && hdr[3]=='F')
                    elfs.push_back((uintptr_t)mbi.BaseAddress);
            }
        }
        addr = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        if (addr < (uintptr_t)mbi.BaseAddress) break;
    }
    return elfs;
}

// Try HP validation on a base
bool validateHP(HANDLE hProc, uintptr_t base) {
    uintptr_t lp = 0;
    ReadProcessMemory(hProc, (LPCVOID)(base + Off::LocalPlayer), &lp, 8, nullptr);
    if (lp < 0x1000 || lp > 0x7FFFFFFFFFFF) return false;
    float hp = 0;
    ReadProcessMemory(hProc, (LPCVOID)(lp + Off::Health), &hp, 4, nullptr);
    return (hp >= 1.f && hp <= 220.f);
}

// Master: scan ALL processes, find the one with ELF + valid HP
bool findGameProcess() {
    printf("[*] Scanning ALL processes for Android game memory...\n\n");

    auto procs = getAllProcesses();
    printf("[*] Total processes: %zu\n\n", procs.size());

    for (auto& pi : procs) {
        // Skip system/idle
        if (pi.pid <= 4) continue;

        HANDLE hProc = OpenProcess(
            PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pi.pid);
        if (!hProc) continue;

        auto elfs = scanELF(hProc);

        if (!elfs.empty()) {
            printf("[~] PID=%-6lu %-30s ELFs=%zu\n", pi.pid, pi.name, elfs.size());

            // Try HP validation on each ELF
            for (auto base : elfs) {
                if (validateHP(hProc, base)) {
                    printf("\n[!!!] MATCH! PID=%lu %s Base=0x%llX\n",
                           pi.pid, pi.name, base);
                    // Upgrade handle with write if needed
                    CloseHandle(hProc);
                    g_hProc = OpenProcess(
                        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pi.pid);
                    g_pid  = pi.pid;
                    g_base = base;
                    return true;
                }
            }

            // No HP match but has ELFs — save as fallback
            // Use largest ELF
            if (strstr(pi.name, "HD-") || strstr(pi.name, "Bstk") ||
                strstr(pi.name, "MSI") || strstr(pi.name, "App")) {
                printf("     ^ BlueStacks process with ELF — trying as fallback\n");
                // Keep handle for now, will try later
            }
        }

        CloseHandle(hProc);
    }

    // Second pass — if no HP match, pick the process with most ELFs
    printf("\n[*] HP validation failed — picking best candidate...\n");

    DWORD   bestPid   = 0;
    uintptr_t bestBase = 0;
    size_t  bestCount = 0;
    char    bestName[260] = {};

    for (auto& pi : procs) {
        if (pi.pid <= 4) continue;
        HANDLE hProc = OpenProcess(
            PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pi.pid);
        if (!hProc) continue;
        auto elfs = scanELF(hProc);
        if (elfs.size() > bestCount) {
            bestCount = elfs.size();
            bestPid   = pi.pid;
            bestBase  = elfs[0];
            strncpy_s(bestName, pi.name, 259);
        }
        CloseHandle(hProc);
    }

    if (bestPid) {
        printf("[?] Best guess: PID=%lu %s ELFs=%zu Base=0x%llX\n",
               bestPid, bestName, bestCount, bestBase);
        g_hProc = OpenProcess(
            PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, bestPid);
        g_pid  = bestPid;
        g_base = bestBase;
        return true;
    }

    return false;
}

// ============================================================
//  WORLD TO SCREEN
// ============================================================
bool W2S(Vec3 world, Vec2& screen, const Matrix4& vm) {
    float x = vm.m[0]*world.x + vm.m[1]*world.y + vm.m[2]*world.z  + vm.m[3];
    float y = vm.m[4]*world.x + vm.m[5]*world.y + vm.m[6]*world.z  + vm.m[7];
    float w = vm.m[12]*world.x+ vm.m[13]*world.y+ vm.m[14]*world.z + vm.m[15];
    if (w < 0.01f) return false;
    screen.x = (SCREEN_W/2.f)*(1.f + x/w);
    screen.y = (SCREEN_H/2.f)*(1.f - y/w);
    return true;
}

// ============================================================
//  OVERLAY
// ============================================================
HWND g_hwndOverlay = nullptr;

LRESULT CALLBACK OverlayProc(HWND hw,UINT msg,WPARAM wp,LPARAM lp){
    if(msg==WM_PAINT){PAINTSTRUCT ps;BeginPaint(hw,&ps);EndPaint(hw,&ps);return 0;}
    if(msg==WM_DESTROY){PostQuitMessage(0);return 0;}
    return DefWindowProcW(hw,msg,wp,lp);
}

bool createOverlay(){
    WNDCLASSEXW wc={};
    wc.cbSize=sizeof(wc);wc.lpfnWndProc=OverlayProc;
    wc.lpszClassName=L"FFOv";wc.hInstance=GetModuleHandleW(nullptr);
    RegisterClassExW(&wc);
    g_hwndOverlay=CreateWindowExW(
        WS_EX_TOPMOST|WS_EX_LAYERED|WS_EX_TRANSPARENT|WS_EX_TOOLWINDOW,
        L"FFOv",L"",WS_POPUP,0,0,SCREEN_W,SCREEN_H,
        nullptr,nullptr,GetModuleHandleW(nullptr),nullptr);
    if(!g_hwndOverlay)return false;
    SetLayeredWindowAttributes(g_hwndOverlay,RGB(0,0,0),0,LWA_COLORKEY);
    SetWindowDisplayAffinity(g_hwndOverlay,WDA_EXCLUDEFROMCAPTURE);
    ShowWindow(g_hwndOverlay,SW_SHOW);
    UpdateWindow(g_hwndOverlay);
    return true;
}

void drawBox(HDC dc,Vec2 head,Vec2 feet,float hp){
    float h=feet.y-head.y;
    if(h<5||h>1200)return;
    float w=h*0.4f,cx=(head.x+feet.x)/2.f;
    COLORREF col=hp>70?RGB(0,255,0):(hp>30?RGB(255,220,0):RGB(255,50,50));
    HPEN pen=CreatePen(PS_SOLID,2,col);
    HPEN old=(HPEN)SelectObject(dc,pen);
    MoveToEx(dc,(LONG)(cx-w/2),(LONG)head.y,nullptr);
    LineTo(dc,(LONG)(cx+w/2),(LONG)head.y);
    LineTo(dc,(LONG)(cx+w/2),(LONG)feet.y);
    LineTo(dc,(LONG)(cx-w/2),(LONG)feet.y);
    LineTo(dc,(LONG)(cx-w/2),(LONG)head.y);
    SelectObject(dc,old);DeleteObject(pen);
    char buf[16];sprintf_s(buf,"%.0f",hp);
    SetBkMode(dc,TRANSPARENT);SetTextColor(dc,col);
    TextOutA(dc,(int)(cx-w/2),(int)head.y-16,buf,(int)strlen(buf));
}

// ============================================================
//  AIMBOT
// ============================================================
bool g_lmb=false;
LRESULT CALLBACK MouseHook(int code,WPARAM wp,LPARAM lp){
    if(code==HC_ACTION){
        if(wp==WM_LBUTTONDOWN)g_lmb=true;
        if(wp==WM_LBUTTONUP)  g_lmb=false;
    }
    return CallNextHookEx(nullptr,code,wp,lp);
}

struct AimTarget{float dist;Vec2 screen;};
void doAimbot(std::vector<AimTarget>&targets){
    if(!g_lmb||targets.empty())return;
    float cx=SCREEN_W/2.f,cy=SCREEN_H/2.f;
    AimTarget*best=nullptr;float bestD=AIM_FOV;
    for(auto&t:targets){
        float d=sqrtf((t.screen.x-cx)*(t.screen.x-cx)+(t.screen.y-cy)*(t.screen.y-cy));
        if(d<bestD){bestD=d;best=&t;}
    }
    if(best){
        INPUT in={};in.type=INPUT_MOUSE;in.mi.dwFlags=MOUSEEVENTF_MOVE;
        in.mi.dx=(LONG)((best->screen.x-cx)*AIM_SMOOTH);
        in.mi.dy=(LONG)((best->screen.y-cy)*AIM_SMOOTH);
        SendInput(1,&in,sizeof(INPUT));
    }
}

// ============================================================
//  MAIN LOOP
// ============================================================
void mainLoop(){
    HHOOK hook=SetWindowsHookExW(WH_MOUSE_LL,MouseHook,nullptr,0);
    printf("[+] ESP Active. LMB=Aimbot. Base=0x%llX\n\n",g_base);

    while(true){
        DWORD ec=0; GetExitCodeProcess(g_hProc,&ec);
        if(ec!=STILL_ACTIVE){printf("[-] Process exited.\n");break;}

        Matrix4 vm=Read<Matrix4>(g_base+OFF_VIEWMATRIX);
        uintptr_t lp=Read<uintptr_t>(g_base+Off::LocalPlayer);
        int ec2=Read<int>(g_base+Off::EntityCount);
        uintptr_t el=Read<uintptr_t>(g_base+Off::EntityList);
        int myTeam=lp?Read<int>(lp+Off::TeamID):0;

        HDC dc=GetDC(g_hwndOverlay);
        HBRUSH blk=CreateSolidBrush(RGB(0,0,0));
        RECT full={0,0,SCREEN_W,SCREEN_H};
        FillRect(dc,&full,blk);DeleteObject(blk);

        std::vector<AimTarget> aims;
        for(int i=0;i<ec2&&i<64;i++){
            uintptr_t ent=Read<uintptr_t>(el+i*8);
            if(!ent)continue;
            int team=Read<int>(ent+Off::TeamID);
            if(team==myTeam)continue;
            float hp=Read<float>(ent+Off::Health);
            if(hp<=0||hp>220)continue;
            Vec3 pos=Read<Vec3>(ent+Off::Position);
            Vec3 head=Read<Vec3>(ent+Off::BoneMatrix+Off::BONE_HEAD*Off::BONE_STRIDE);
            Vec2 hs,fs;
            if(!W2S(head,hs,vm))continue;
            if(!W2S(pos,fs,vm))continue;
            drawBox(dc,hs,fs,hp);
            float cx=SCREEN_W/2.f,cy=SCREEN_H/2.f;
            float d=sqrtf((hs.x-cx)*(hs.x-cx)+(hs.y-cy)*(hs.y-cy));
            aims.push_back({d,hs});
        }
        doAimbot(aims);
        ReleaseDC(g_hwndOverlay,dc);

        MSG msg;
        while(PeekMessageW(&msg,nullptr,0,0,PM_REMOVE)){
            TranslateMessage(&msg);DispatchMessageW(&msg);
        }
        Sleep(1);
    }
    if(hook)UnhookWindowsHookEx(hook);
}

// ============================================================
//  ENTRY
// ============================================================
int main(){
    printf("=== Free Fire External | MSI App Player ===\n\n");

    if(!findGameProcess()){
        printf("\n[-] No game process found.\n");
        printf("[!] Make sure Free Fire match is OPEN in emulator.\n");
        system("pause");return 1;
    }

    printf("\n[+] g_base=0x%llX PID=%lu\n",g_base,g_pid);
    printf("[+] Starting overlay...\n");

    if(!createOverlay()){
        printf("[-] Overlay failed.\n");
        system("pause");return 1;
    }

    mainLoop();
    CloseHandle(g_hProc);
    return 0;
}
