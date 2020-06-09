#define _CRT_SECURE_NO_WARNINGS

#include <conio.h>
#include <iostream>
#include <Windows.h>
#include <tlhelp32.h>
#include <comdef.h>

#define ENABLE_DBG_MSG 1
#define PIPE_BUFFER_SIZE 1000
#define DLL_NAME "\\Injection.dll" 

LPVOID ptrAllocatedInOtherProcessMemory = NULL;

using namespace std;

bool GetProccessID(string processName, DWORD& processId)
{
    /*
    //  Takes a snapshot of the specified processes, as well as
    //  the heaps, modules, and threads used by these processes.  
    //
    //  TH32CS_SNAPPROCESS - Includes all processes in the system
    //  in the snapshot.
    //
    //  Second argument is ignored during call with TH32CS_SNAPPROCESS
    //  as first argument.
    */
    HANDLE hSnapshot;
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        printf("ERROR: GetProccessID: CreateToolhelp32Snapshot returned \
            invalid handle. Line = %d, GetLastError = %d\n", __LINE__, GetLastError());
        return false;
    }

    /*
    //  Retrieves information about the first process encountered 
    //  in a system snapshot.
    */   
    PROCESSENTRY32 processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(hSnapshot, &processEntry))
    {
        CloseHandle(hSnapshot);
        printf("ERROR: GetProccessID: Process32First failed. Line = %d,  \
            GetLastError = %d\n", __LINE__, GetLastError());
        return false;
    }

    /*
    //  Traverse through the snapshot searching for process with
    //  specified name.
    */
    bool isProccesFound = false;
    do
    {
        _bstr_t exeFileName(processEntry.szExeFile);
        if (0 == strcmp(processName.c_str(), exeFileName))
        {
            processId = processEntry.th32ProcessID;
            isProccesFound = true;
            break;
        }

    } while (Process32Next(hSnapshot, &processEntry));

    CloseHandle(hSnapshot);

    if (!isProccesFound)
    {
        printf("ERROR: Process with name \"%s\" wasn't found.\n", processName.c_str());
        return false;
    }

    return true;
}

bool InjectDll(DWORD targetProcessID)
{
    HANDLE hThreadID = INVALID_HANDLE_VALUE;
    HANDLE hTargetProcess = INVALID_HANDLE_VALUE;
    HMODULE h_kernel32dll = NULL;
    LPVOID ptrLoadLibraryA = NULL;
    LPVOID ptrLoadLibraryA_args = NULL;
    bool isInjectionSuccessful = false;

    hTargetProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetProcessID);
    if (hTargetProcess == NULL)
    {
        printf("ERROR: InjectDll: OpenProcess failed. Line = %d,  \
            GetLastError = %d\n", __LINE__, GetLastError());
        goto InjectDll_exit_routine;
    }
 
    h_kernel32dll = GetModuleHandleW(L"kernel32.dll");
    if (h_kernel32dll == NULL)
    {
        printf("ERROR: InjectDll: GetModuleHandleW failed. Line = %d,  \
            GetLastError = %d\n", __LINE__, GetLastError());
        goto InjectDll_exit_routine;
    }

    ptrLoadLibraryA = GetProcAddress(h_kernel32dll, "LoadLibraryA");
    if (ptrLoadLibraryA == NULL)
    {
        printf("ERROR: InjectDll: GetProcAddress failed. Line = %d,  \
            GetLastError = %d\n", __LINE__, GetLastError());
        goto InjectDll_exit_routine;
    }

    char injectionDllFullPath[MAX_PATH];
    GetCurrentDirectoryA(sizeof(injectionDllFullPath), injectionDllFullPath);
    strcat(injectionDllFullPath, DLL_NAME);

    ptrLoadLibraryA_args = (LPVOID)VirtualAllocEx(hTargetProcess, NULL, 
        strlen(injectionDllFullPath), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    ptrAllocatedInOtherProcessMemory = ptrLoadLibraryA_args;
    if (ptrLoadLibraryA_args == NULL)
    {
        printf("ERROR: InjectDll: VirtualAllocEx failed. Line = %d,  \
            GetLastError = %d\n", __LINE__, GetLastError());
        goto InjectDll_exit_routine;
    }

    if (WriteProcessMemory(hTargetProcess, ptrLoadLibraryA_args, injectionDllFullPath, 
        strlen(injectionDllFullPath), NULL) == NULL)
    {
        printf("ERROR: InjectDll: WriteProcessMemory failed. Line = %d,  \
            GetLastError = %d\n", __LINE__, GetLastError());
        goto InjectDll_exit_routine;
    }

    hThreadID = CreateRemoteThread(hTargetProcess, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibrary, 
        ptrLoadLibraryA_args, NULL, NULL);
    if (hThreadID == NULL)
    {
        printf("ERROR: InjectDll: CreateRemoteThread failed. Line = %d, GetLastError = %d\n", 
            __LINE__, GetLastError());
        goto InjectDll_exit_routine;
    }

    isInjectionSuccessful = true;

InjectDll_exit_routine:

    if (ptrLoadLibraryA_args != NULL && !isInjectionSuccessful)
    {
        VirtualFreeEx(hTargetProcess, ptrLoadLibraryA_args, 0,
            MEM_RELEASE);
    }
    if (hTargetProcess != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hTargetProcess);
    }
    if (h_kernel32dll != INVALID_HANDLE_VALUE)
    {
        FreeLibrary(h_kernel32dll);
    }
    if (hThreadID != INVALID_HANDLE_VALUE)
    {
        FreeLibrary(h_kernel32dll);
    }

    if (isInjectionSuccessful)
    {
        return true;
    }
    else
    {
        return false;
    }
}

int main(int argc, char* argv[])
{
    if (argc != 5)
    {
       printf("ERROR: Wrong arguments quantity.\n");
       return 0;
    }

    DWORD targetProcessPid = 0;
    if (argv[1] == string("-name"))
    {
        if (!GetProccessID(argv[2], targetProcessPid))
        {
            printf("ERROR: main: GetProccessID failed. Line = %d\n", __LINE__);
            return 0;
        }
    }
    else if (argv[1] == string("-pid"))
    {
        targetProcessPid = atoi(argv[2]);
    }
    else
    {
        printf("ERROR: Wrong first argument type.\n");
        return 0;
    }

    if (ENABLE_DBG_MSG) { printf("DEBUG: process ID = %u\n", targetProcessPid); }

    HANDLE hPipe;
    LPCTSTR pipeName = L"\\\\.\\pipe\\hook-inject";
    hPipe = CreateNamedPipe(pipeName, 
                            PIPE_ACCESS_DUPLEX, 
                            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, 
                            PIPE_UNLIMITED_INSTANCES, 
                            PIPE_BUFFER_SIZE,
                            PIPE_BUFFER_SIZE,
                            0, 
                            NULL);
    if (hPipe == INVALID_HANDLE_VALUE)
    {
        printf("ERROR: main: CreateNamedPipe returned invalid handle. Line = %d, \
            GetLastError = %d\n", __LINE__, GetLastError());
        CloseHandle(hPipe);
        return 0;
    }

    if (!InjectDll(targetProcessPid))
    {
        printf("ERROR: main: InjectDll failed. Line = %d\n", __LINE__);
        CloseHandle(hPipe);
        return 0;
    }

    _getch();
    CloseHandle(hPipe);
}

