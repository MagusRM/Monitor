#define WIN32_LEAN_AND_MEAN

#include <Windows.h>
#include <stdio.h>
#include <cstdlib>
#include <string>

#include "../Hook-Inject.h"

using namespace std;

bool EstablishConnectionWithMonitor( IN LPCSTR pipeName,
                                     OUT HANDLE& hPipe)
{
    if (!WaitNamedPipeA(pipeName, 10000))
    {
        MessageBox(NULL, (LPCWSTR)L"[E]: DllMain: WaitNamedPipeA failed.",
            (LPCWSTR)L"Injection.dll", MB_ICONERROR);
        return false;
    }

    hPipe = CreateFileA(pipeName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hPipe == INVALID_HANDLE_VALUE)
    {
        MessageBox(NULL, (LPCWSTR)L"[E]: DllMain: CreateFileA (opening pipe) failed.",
            (LPCWSTR)L"Injection.dll", MB_ICONERROR);
        return false;
    }

    DWORD pipeMode = PIPE_READMODE_MESSAGE;
    if (!SetNamedPipeHandleState(hPipe, &pipeMode, NULL, NULL))
    {
        MessageBox(NULL, (LPCWSTR)L"[E]: DllMain: Cant't set pipe state.",
            (LPCWSTR)L"Injection.dll", MB_ICONERROR);
        CloseHandle(hPipe);
        return false;
    }

    return true;
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        HANDLE hPipe;
        if(!EstablishConnectionWithMonitor(PIPE_NAME, hPipe))
        {
            return false;
        }

        BYTE pipeBuf[PIPE_BUFFER_SIZE];
        DWORD numberOfBytesRead;
        if (!ReadFile(hPipe, pipeBuf, PIPE_BUFFER_SIZE, &numberOfBytesRead, NULL))
        {
            MessageBox(NULL, (LPCWSTR)L"[E]: DllMain: Cant't get arguments from Monitor.exe",
                (LPCWSTR)L"Injection.dll", MB_ICONERROR);
            CloseHandle(hPipe);
            return false;
        }
        
        ProgrammMode programmMode = *((ProgrammMode*)pipeBuf);
        string fileOrFunctionName = (char*)(pipeBuf + sizeof(ProgrammMode));

        if (ENABLE_DBG_MSG) 
        {
            if (programmMode == ProgrammMode::kHideFileFromProcess)
            {
                printf("\n[D]: programmMode == kHideFileFromProcess\n");
            }
            else if (programmMode == ProgrammMode::kTrackCallOfFunction)
            {
                printf("\n[D]: programmMode == kTrackCallOfFunction\n");
            }
            else
            {
                printf("\n[D]: ERROR: unknown programm mode.\n");
            }

            printf("\n[D]: argument = %s\n", fileOrFunctionName.c_str());
        }
    }

    return true;
}

