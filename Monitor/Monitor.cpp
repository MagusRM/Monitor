#define _CRT_SECURE_NO_WARNINGS

#include <conio.h>
#include <iostream>
#include <Windows.h>
#include <tlhelp32.h>
#include <comdef.h>

#define ENABLE_DBG_MSG 1
#define PIPE_BUFFER_SIZE 1000
#define DLL_NAME "\\Injection.dll" 
#define PIPE_NAME L"\\\\.\\pipe\\hook-inject"

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
        printf("[E]: GetProccessID: CreateToolhelp32Snapshot returned \
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
        printf("[E]: GetProccessID: Process32First failed. Line = %d,  \
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
        printf("[E]: Process with name \"%s\" wasn't found.\n", processName.c_str());
        return false;
    }

    return true;
}

bool InjectDll(DWORD targetProcessID, 
    LPVOID& ptrAllocatedInOtherProcessMemory, HANDLE& hTargetProcess)
{
    HANDLE hThreadID = INVALID_HANDLE_VALUE;
    HMODULE h_kernel32dll = NULL;
    LPVOID ptrLoadLibraryA = NULL;
    LPVOID ptrLoadLibraryA_args = NULL;
    bool isInjectionSuccessful = false;

    hTargetProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetProcessID);
    if (hTargetProcess == NULL)
    {
        printf("[E]: InjectDll: OpenProcess failed. Line = %d,  \
            GetLastError = %d\n", __LINE__, GetLastError());
        goto InjectDll_exit_routine;
    }
 
    h_kernel32dll = GetModuleHandleW(L"kernel32.dll");
    if (h_kernel32dll == NULL)
    {
        printf("[E]: InjectDll: GetModuleHandleW failed. Line = %d,  \
            GetLastError = %d\n", __LINE__, GetLastError());
        goto InjectDll_exit_routine;
    }

    ptrLoadLibraryA = GetProcAddress(h_kernel32dll, "LoadLibraryA");
    if (ptrLoadLibraryA == NULL)
    {
        printf("[E]: InjectDll: GetProcAddress failed. Line = %d,  \
            GetLastError = %d\n", __LINE__, GetLastError());
        goto InjectDll_exit_routine;
    }

    char injectionDllFullPath[MAX_PATH];
    GetCurrentDirectoryA(sizeof(injectionDllFullPath), injectionDllFullPath);
    strcat(injectionDllFullPath, DLL_NAME);

    if (ENABLE_DBG_MSG) { printf("[D]: Full path to injection dll = %s\n", injectionDllFullPath); }

    ptrLoadLibraryA_args = (LPVOID)VirtualAllocEx(hTargetProcess, NULL, 
        strlen(injectionDllFullPath) + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    ptrAllocatedInOtherProcessMemory = ptrLoadLibraryA_args;
    if (ptrLoadLibraryA_args == NULL)
    {
        printf("[E]: InjectDll: VirtualAllocEx failed. Line = %d,  \
            GetLastError = %d\n", __LINE__, GetLastError());
        goto InjectDll_exit_routine;
    }

    if (WriteProcessMemory(hTargetProcess, ptrLoadLibraryA_args, injectionDllFullPath, 
        strlen(injectionDllFullPath) + 1, NULL) == NULL)
    {
        printf("[E]: InjectDll: WriteProcessMemory failed. Line = %d,  \
            GetLastError = %d\n", __LINE__, GetLastError());
        goto InjectDll_exit_routine;
    }

    hThreadID = CreateRemoteThread(hTargetProcess, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, 
        ptrLoadLibraryA_args, NULL, NULL);
    if (hThreadID == NULL)
    {
        printf("[E]: InjectDll: CreateRemoteThread failed. Line = %d, GetLastError = %d\n", 
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
        if (ENABLE_DBG_MSG) { printf("[D]: DLL is injected.\n"); }
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
       printf("[E]: Wrong arguments quantity.\n");
       return 0;
    }

    DWORD targetProcessPid = 0;
    if (argv[1] == string("-name"))
    {
        if (!GetProccessID(argv[2], targetProcessPid))
        {
            printf("[E]: main: GetProccessID failed. Line = %d\n", __LINE__);
            return 0;
        }
    }
    else if (argv[1] == string("-pid"))
    {
        targetProcessPid = atoi(argv[2]);
    }
    else
    {
        printf("[E]: Wrong first argument type.\n");
        return 0;
    }

    if (ENABLE_DBG_MSG) { printf("[D]: process ID = %u\n", targetProcessPid); }

    HANDLE hPipe;
    LPCTSTR pipeName = PIPE_NAME;
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
        printf("[E]: main: CreateNamedPipe returned invalid handle. Line = %d, \
            GetLastError = %d\n", __LINE__, GetLastError());
        return 0;
    }

    if (ENABLE_DBG_MSG) { printf("[D]: Pipe created.\n"); }

    LPVOID ptrAllocatedInOtherProcessMemory = NULL;
    HANDLE hTargetProcess = INVALID_HANDLE_VALUE;
    if (!InjectDll(targetProcessPid, ptrAllocatedInOtherProcessMemory, hTargetProcess))
    {
        printf("[E]: main: InjectDll failed. Line = %d\n", __LINE__);
        CloseHandle(hPipe);
        return 0;
    }

    if (!ConnectNamedPipe(hPipe, NULL))
    {
        printf("[E]: main: ConnectNamedPipe failed. Line = %d  \
            GetLastError = %d\n", __LINE__, GetLastError());
        CloseHandle(hPipe);
        return 0;
    }

    VirtualFreeEx(hTargetProcess, ptrAllocatedInOtherProcessMemory, 0, MEM_RELEASE);
    CloseHandle(hTargetProcess);

    printf("[*] Injection.dll connected to Monitor.exe via pipe.\n");

    BYTE pipeBuffer[PIPE_BUFFER_SIZE] = { 0 };

    DWORD numberOfBytesRead;
    if (!ReadFile(hPipe, pipeBuffer, PIPE_BUFFER_SIZE * sizeof(BYTE), &numberOfBytesRead, NULL))
    {
        printf("[E]: main: ReadFile failed. Line = %d  \
            GetLastError = %d\n", __LINE__, GetLastError());
        CloseHandle(hPipe);
        return 0;
    }

    printf("Message from DLL: \"%s\"\n", pipeBuffer);

    CloseHandle(hPipe);

    return 0;
}

