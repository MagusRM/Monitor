#define _CRT_SECURE_NO_WARNINGS

#include <conio.h>
#include <iostream>
#include <Windows.h>
#include <tlhelp32.h>
#include <comdef.h>
#include <string.h>

#include "../Hook-Inject.h"

#define DLL_NAME "\\Injection.dll" 

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

void ReleaseResourcesAssociatedWithTargetProcess(LPVOID& ptrAllocatedInOtherProcessMemory, HANDLE& hTargetProcess)
{
    // Doesn't work but why?
    //if (!VirtualFreeEx(hTargetProcess, ptrAllocatedInOtherProcessMemory, 0, MEM_RELEASE))
    //{
    //    printf("[E]: ReleaseResourcesAssociatedWithTargetProcess: VirtualFreeEx failed. Line = %d, \
    //        GetLastError = %d\n", __LINE__, GetLastError());
    //}
    //if (!CloseHandle(hTargetProcess))
    //{
    //    printf("[E]: ReleaseResourcesAssociatedWithTargetProcess: CloseHandle failed. Line = %d, \
    //        GetLastError = %d\n", __LINE__, GetLastError());
    //}
}

bool InjectDll( IN DWORD targetProcessID, 
                OUT LPVOID& ptrAllocatedInOtherProcessMemory, HANDLE& hTargetProcess)
{
    HANDLE hThreadID = INVALID_HANDLE_VALUE;
    HMODULE h_kernel32dll = NULL;
    LPVOID ptrLoadLibraryA = NULL;
    bool isInjectionSuccessful = false;

    ptrAllocatedInOtherProcessMemory = NULL;

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

#ifdef _DEBUG
    printf("[D]: Full path to injection dll = %s\n", injectionDllFullPath);
#endif

    ptrAllocatedInOtherProcessMemory = (LPVOID)VirtualAllocEx(hTargetProcess, NULL,
        strlen(injectionDllFullPath) + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (ptrAllocatedInOtherProcessMemory == NULL)
    {
        printf("[E]: InjectDll: VirtualAllocEx failed. Line = %d,  \
            GetLastError = %d\n", __LINE__, GetLastError());
        goto InjectDll_exit_routine;
    }

    if (WriteProcessMemory(hTargetProcess, ptrAllocatedInOtherProcessMemory, injectionDllFullPath,
        strlen(injectionDllFullPath) + 1, NULL) == NULL)
    {
        printf("[E]: InjectDll: WriteProcessMemory failed. Line = %d,  \
            GetLastError = %d\n", __LINE__, GetLastError());
        goto InjectDll_exit_routine;
    }

    hThreadID = CreateRemoteThread(hTargetProcess, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, 
        ptrAllocatedInOtherProcessMemory, NULL, NULL);
    if (hThreadID == NULL)
    {
        printf("[E]: InjectDll: CreateRemoteThread failed. Line = %d, GetLastError = %d\n", 
            __LINE__, GetLastError());
        goto InjectDll_exit_routine;
    }

    isInjectionSuccessful = true;

InjectDll_exit_routine:

    if (!isInjectionSuccessful)
    {
        if (ptrAllocatedInOtherProcessMemory != NULL)
        {
            VirtualFreeEx(hTargetProcess, ptrAllocatedInOtherProcessMemory, 0,
                MEM_RELEASE);
        }
        if (hTargetProcess != NULL)
        {
            CloseHandle(hTargetProcess);
        }
    }
    if (h_kernel32dll != INVALID_HANDLE_VALUE)
    {
        FreeLibrary(h_kernel32dll);
    }
    if (hThreadID != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hThreadID);
    }

    if (isInjectionSuccessful)
    {

#ifdef _DEBUG
        printf("[D]: DLL is injected.\n");
#endif
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

#ifdef _DEBUG
    printf("[D]: Target process ID = %u\n", targetProcessPid);
#endif

    if (argv[3] == string("-func"))
    {
        programmMode = ProgrammMode::kTrackCallOfFunction;
        functionName = string(argv[4]);

#ifdef _DEBUG
        printf("[D]: Programm mode = kTrackCallOfFunction, function name = %s \n", functionName.c_str());
#endif
    }
    else if (argv[3] == string("-hide"))
    {
        programmMode = ProgrammMode::kHideFileFromProcess;
        fileName = string(argv[4]);

#ifdef _DEBUG
        printf("[D]: Programm mode = hideFileFromProcess, file name = %s \n", fileName.c_str());
#endif
    }
    else
    {
        printf("[E]: Wrong third argument type.\n");
        return false;
    }

    return true;
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

    LPCTSTR pipeName = TEXT(PIPE_NAME);
    HANDLE hPipe = CreateNamedPipe(pipeName,
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

#ifdef _DEBUG
    printf("[D]: Pipe created.\n");
#endif

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
        ReleaseResourcesAssociatedWithTargetProcess(hTargetProcess, ptrAllocatedInOtherProcessMemory);
        return 0;
    }

    ReleaseResourcesAssociatedWithTargetProcess(hTargetProcess, ptrAllocatedInOtherProcessMemory);

    printf("[*] Injection.dll connected to Monitor.exe via pipe.\n");

    BYTE pipeBuf[PIPE_BUFFER_SIZE] = { 0 };
    memcpy(pipeBuf, &programmMode, sizeof(programmMode));
    if (programmMode == ProgrammMode::kTrackCallOfFunction)
    {
        strcpy_s((char*)pipeBuf + sizeof(programmMode), PIPE_BUFFER_SIZE - sizeof(programmMode), functionName.c_str());
    }
    else // programmMode == ProgrammMode::kHideFileFromProcess
    {
        strcpy_s((char*)pipeBuf + sizeof(programmMode), PIPE_BUFFER_SIZE - sizeof(programmMode), fileName.c_str());
    }

    DWORD numberOfBytesSent;
    if (!WriteFile(hPipe, pipeBuf, PIPE_BUFFER_SIZE, &numberOfBytesSent, NULL))
    {
        printf("[E]: main: WriteFile failed. Can't send arguments to the Injection.dll. Line = %d\n", __LINE__);
        CloseHandle(hPipe);
        return 0;
    }

    if (programmMode == ProgrammMode::kTrackCallOfFunction)
    {
        while (1)
        {
            DWORD numberOfBytesRead;
            memset(pipeBuf, 0, PIPE_BUFFER_SIZE);
            if (ReadFile(hPipe, pipeBuf, PIPE_BUFFER_SIZE, &numberOfBytesRead, NULL))
            {
                printf("[*] Message from Injection.dll: \"%s is called (%s)\"\n", functionName.c_str(), (char*)pipeBuf);
            }
            else
            {
                printf("[E] DllMain: ReadFile() failed, GetLastError() = %d, line = %d\n", GetLastError(), __LINE__);
                CloseHandle(hPipe);
                return 0;
            }  
        }
    }

    CloseHandle(hPipe);

    return 0;
}

