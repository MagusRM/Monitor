#define WIN32_LEAN_AND_MEAN

#include <Windows.h>
#include <stdio.h>
#include <cstdlib>

#define PIPE_NAME "\\\\.\\pipe\\hook-inject"

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        if (!WaitNamedPipeA(PIPE_NAME, 10000))
        {
            MessageBox(NULL, (LPCWSTR)L"[E]: DllMain: WaitNamedPipeA failed.",
                (LPCWSTR)L"Injection.dll", MB_ICONERROR);
            return false;
        }

        HANDLE hPipe = CreateFileA(PIPE_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
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

        //LPCSTR initialMsg = "Injections.dll is connected via pipe.";
        //DWORD numberOfBytesWritten;
        //if (!WriteFile(hPipe, initialMsg, lstrlenA(initialMsg) + 1, &numberOfBytesWritten, NULL))
        //{
        //    MessageBox(NULL, (LPCWSTR)L"[E]: DllMain: Cant't write to the pipe.",
        //        (LPCWSTR)L"Injection.dll", MB_ICONERROR);
        //    CloseHandle(hPipe);
        //    return false;
        //}       
        

    }

    return true;
}

