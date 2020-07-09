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

enum class ProgrammMode
{
    kTrackCallOfFunction,
    kHideFileFromProcess
};

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

bool InjectDll( IN DWORD targetProcessID, 
                OUT LPVOID& ptrAllocatedInOtherProcessMemory, HANDLE& hTargetProcess)
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

bool SanitizeAndProcessCmdArgs( IN int& argc, char**& argv,
                                OUT DWORD& targetProcessPid, enum class ProgrammMode& programmMode, string& functionName, string& fileName)
{
    if (argc != 5)
    {
        printf("[E]: Wrong arguments quantity.\n");
        return false;
    }

    if (argv[1] == string("-name"))
    {
        if (!GetProccessID(argv[2], targetProcessPid))
        {
            printf("[E]: main: GetProccessID failed. Line = %d\n", __LINE__);
            return false;
        }
    }
    else if (argv[1] == string("-pid"))
    {
        targetProcessPid = atoi(argv[2]);
    }
    else
    {
        printf("[E]: Wrong first argument type.\n");
        return false;
    }

    if (ENABLE_DBG_MSG) { printf("[D]: Target process ID = %u\n", targetProcessPid); }

    if (argv[3] == string("-func"))
    {
        programmMode = ProgrammMode::kTrackCallOfFunction;
        functionName = string(argv[4]);

        if (ENABLE_DBG_MSG) { printf("[D]: Programm mode = kTrackCallOfFunction, function name = %s \n", functionName.c_str()); }

    }
    else if (argv[3] == string("-hide"))
    {
        programmMode = ProgrammMode::kHideFileFromProcess;
        fileName = string(argv[4]);

        if (ENABLE_DBG_MSG) { printf("[D]: Programm mode = hideFileFromProcess, file name = %s \n", fileName.c_str()); }
    }
    else
    {
        printf("[E]: Wrong third argument type.\n");
        return false;
    }

    return true;
}

bool EstablishConnectionWithInjectionDll(HANDLE& hPipe, LPCTSTR& pipeName)
{
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
        return false;
    }

    if (ENABLE_DBG_MSG) { printf("[D]: Pipe created.\n"); }

    if (!ConnectNamedPipe(hPipe, NULL))
    {
        printf("[E]: main: ConnectNamedPipe failed. Line = %d  \
            GetLastError = %d\n", __LINE__, GetLastError());
        CloseHandle(hPipe);
        return false;
    }

    return true;
}

void ReleaseResourcesAssociatedWithTargetProcess(LPVOID& ptrAllocatedInOtherProcessMemory,HANDLE& hTargetProcess)
{
    VirtualFreeEx(hTargetProcess, ptrAllocatedInOtherProcessMemory, 0, MEM_RELEASE);
    CloseHandle(hTargetProcess);
}

int main(int argc, char* argv[])
{ 
    DWORD targetProcessPid = 0;
    enum class ProgrammMode programmMode;
    string functionName = "";
    string fileName = "";
    if (!SanitizeAndProcessCmdArgs(argc, argv, 
                                   targetProcessPid, programmMode, functionName, fileName))
    {
        return 0;
    }

    LPVOID ptrAllocatedInOtherProcessMemory = NULL;
    HANDLE hTargetProcess = INVALID_HANDLE_VALUE;
    if (!InjectDll(targetProcessPid, ptrAllocatedInOtherProcessMemory, hTargetProcess))
    {
        printf("[E]: main: InjectDll failed. Line = %d\n", __LINE__);
        CloseHandle(hPipe);
        return 0;
    }

    HANDLE hPipe;
    LPCTSTR pipeName = PIPE_NAME;
    if (!EstablishConnectionWithInjectionDll(hPipe, pipeName))
    {
        ReleaseResourcesAssociatedWithTargetProcess(hTargetProcess, ptrAllocatedInOtherProcessMemory);
        return 0;
    }

    ReleaseResourcesAssociatedWithTargetProcess(hTargetProcess, ptrAllocatedInOtherProcessMemory);

    printf("[*] Injection.dll connected to Monitor.exe via pipe.\n");



    CloseHandle(hPipe);

    return 0;
}

