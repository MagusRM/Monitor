
#include <conio.h>
#include <iostream>
#include <Windows.h>
#include <tlhelp32.h>
#include <comdef.h>

#define ENABLE_DBG_MSG 1

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
    DWORD processID;
    bool isProccesFound = false;
    do
    {
        _bstr_t exeFileName(processEntry.szExeFile);
        if (0 == strcmp(processName.c_str(), exeFileName))
        {
            processID = processEntry.th32ProcessID;
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

    return processID;
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
}

