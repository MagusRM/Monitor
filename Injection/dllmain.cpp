#define WIN32_LEAN_AND_MEAN

#include <Windows.h>
#include <stdio.h>
#include <cstdlib>
#include <string>
#include <cstdio>

#include "../Detours/include/detours.h"
#include "../Hook-Inject.h"

extern "C" void hook();
extern "C" LPVOID ptrTargetFunction = NULL;

HANDLE hPipe;

using namespace std;

string ExplainDetourError(LONG detourErrorCode)
{
    if (detourErrorCode == ERROR_INVALID_DATA)
    {
        return "ERROR_INVALID_DATA";
    }
    else if (detourErrorCode == ERROR_INVALID_OPERATION)
    {
        return "ERROR_INVALID_OPERATION";
    }
    else if (detourErrorCode == ERROR_NOT_ENOUGH_MEMORY)
    {
        return "ERROR_NOT_ENOUGH_MEMORY";
    }
    else if (detourErrorCode == ERROR_INVALID_BLOCK)
    {
        return "ERROR_INVALID_BLOCK";
    }
    else if (detourErrorCode == ERROR_INVALID_HANDLE)
    {
        return "ERROR_INVALID_HANDLE";
    }
    else if (detourErrorCode == ERROR_INVALID_OPERATION)
    {
        return "ERROR_INVALID_OPERATION";
    }
    else if (detourErrorCode == NO_ERROR)
    {
        return "NO_ERROR";
    }
    else
    {
        return "Unknown detour error = " + to_string(detourErrorCode);
    }
}

bool EstablishConnectionWithMonitor( IN LPCSTR pipeName)
{
    if (!WaitNamedPipeA(pipeName, 10000))
    {
#ifdef _DEBUG
        printf("[E] EstablishConnectionWithMonitor: WaitNamedPipeA() failed, GetLastError() = %d, line = %d\n", GetLastError(), __LINE__);
#endif
        return false;
    }

    hPipe = CreateFileA(pipeName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hPipe == INVALID_HANDLE_VALUE)
    {
#ifdef _DEBUG
        printf("[E] EstablishConnectionWithMonitor: CreateFileA() failed, GetLastError() = %d, line = %d\n", GetLastError(), __LINE__);
#endif
        return false;
    }

    DWORD pipeMode = PIPE_READMODE_MESSAGE;
    if (!SetNamedPipeHandleState(hPipe, &pipeMode, NULL, NULL))
    {
#ifdef _DEBUG
        printf("[E] EstablishConnectionWithMonitor: SetNamedPipeHandleState() failed, GetLastError() = %d, line = %d\n", GetLastError(), __LINE__);
#endif
        CloseHandle(hPipe);
        return false;
    }

    return true;
}

void LogTargetFunctionCall()
{
    BYTE pipeBuf[PIPE_BUFFER_SIZE] = { 0 };

    SYSTEMTIME SysTime;
    GetLocalTime(&SysTime);
    sprintf_s(reinterpret_cast<char*>(pipeBuf), PIPE_BUFFER_SIZE, "%02d:%02d:%02d", SysTime.wHour, SysTime.wMinute, SysTime.wSecond);

#ifdef _DEBUG
    printf("[D] Sending log info: \"%s\"\n", reinterpret_cast<char*>(pipeBuf));
#endif

    DWORD numberOfBytesSent;
    if (!WriteFile(hPipe, pipeBuf, PIPE_BUFFER_SIZE, &numberOfBytesSent, NULL))
    {
#ifdef _DEBUG
        printf("[E] LogTargetFunctionCall: WriteFile() failed, GetLastError() = %d, line = %d\n", GetLastError(), __LINE__);
#endif
    }
}

extern "C" void InjectionFunction()
{
    LogTargetFunctionCall();
}

bool HideFile()
{
    return false;
}

bool TrackFuncCall(string& funcName)
{
    ptrTargetFunction = DetourFindFunction("kernel32.dll", funcName.c_str());
    if (ptrTargetFunction == NULL)
    {
#ifdef _DEBUG
        printf("[E] TrackFuncCall: DetourFindFunction() failed, line = %d\n", __LINE__);
#endif
        return false;
    }

    LONG detourErrorCode = DetourTransactionBegin();
    if (detourErrorCode != NO_ERROR)
    {
#ifdef _DEBUG
        printf("[E] TrackFuncCall: DetourTransactionBegin() failed, detour error = \"%s\", line = %d\n", (ExplainDetourError(detourErrorCode)).c_str(), __LINE__);
#endif
        DetourTransactionAbort();
        return false;
    }

    detourErrorCode = DetourUpdateThread(GetCurrentThread());
    if (detourErrorCode != NO_ERROR)
    {
#ifdef _DEBUG
        printf("[E] TrackFuncCall: DetourUpdateThread() failed, detour error = \"%s\", line = %d\n", (ExplainDetourError(detourErrorCode)).c_str(), __LINE__);
#endif
        DetourTransactionAbort();
        return false;
    }

#ifdef _DEBUG
    printf("[D] Before DetourAttach: ptrTargetFunction = %p\n", ptrTargetFunction);
#endif

    PDETOUR_TRAMPOLINE pRealTrampoline;
    PVOID pRealTarget;
    PVOID pRealDetour;
    detourErrorCode = DetourAttachEx((PVOID*)&ptrTargetFunction, hook, &pRealTrampoline, &pRealTarget, &pRealDetour);
    if (detourErrorCode != NO_ERROR)
    {
#ifdef _DEBUG
        printf("[E] TrackFuncCall: DetourAttach() failed, detour error = \"%s\", line = %d\n", (ExplainDetourError(detourErrorCode)).c_str(), __LINE__);
#endif
        DetourTransactionAbort();
        return false;
    }

#ifdef _DEBUG
    printf("[D] After DetourAttach: ptrTargetFunction = %p\n", ptrTargetFunction);
    printf("[D] \t pRealTrampoline = %p\n", pRealTrampoline);
    printf("[D] \t pRealTarget = %p\n", pRealTarget);
    printf("[D] \t pRealDetour = %p\n", pRealDetour);
#endif

    detourErrorCode = DetourTransactionCommit();
    if (detourErrorCode != NO_ERROR)
    {
#ifdef _DEBUG
        printf("[E] TrackFuncCall: DetourTransactionCommit() failed, detour error = \"%s\", line = %d\n", (ExplainDetourError(detourErrorCode)).c_str(), __LINE__);
#endif
        DetourTransactionAbort();
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

#ifdef _DEBUG
        if(!AllocConsole())
        {
            DWORD lastErr = GetLastError();
            if (lastErr != ERROR_ACCESS_DENIED)
            {
                wstring errMsg = L"[E] DllMain: AllocConsole() failed, GetLastError() = " + 
                    to_wstring(lastErr) + L"line = " + to_wstring(__LINE__) + L"\n";

                MessageBox(NULL, errMsg.c_str(), (LPCWSTR)L"Injection.dll", MB_ICONERROR);
                return false;
            }
        }
#endif

        if(!EstablishConnectionWithMonitor(PIPE_NAME))
        {
            return false;
        }

        BYTE pipeBuf[PIPE_BUFFER_SIZE];
        DWORD numberOfBytesRead;
        if (!ReadFile(hPipe, pipeBuf, PIPE_BUFFER_SIZE, &numberOfBytesRead, NULL))
        {
#ifdef _DEBUG
            printf("[E] DllMain: ReadFile() failed, GetLastError() = %d, line = %d\n", GetLastError(), __LINE__);
#endif
            CloseHandle(hPipe);
            return false;
        }
        
        ProgrammMode programmMode = *((ProgrammMode*)pipeBuf);
        string fileOrFunctionName = (char*)(pipeBuf + sizeof(ProgrammMode));

#ifdef _DEBUG
        if (programmMode == ProgrammMode::kHideFileFromProcess)
        {
            printf("\n[D]: programmMode = kHideFileFromProcess\n");
        }
        else if (programmMode == ProgrammMode::kTrackCallOfFunction)
        {
            printf("\n[D]: programmMode = kTrackCallOfFunction\n");
        }
        else
        {
            printf("[D]: ERROR: unknown programm mode.\n");
        }

        printf("\n[D]: argument = %s\n", fileOrFunctionName.c_str());
#endif

        if (programmMode == ProgrammMode::kHideFileFromProcess)
        {
            // DO
        }
        else if (programmMode == ProgrammMode::kTrackCallOfFunction)
        {
            if (!TrackFuncCall(fileOrFunctionName))
            {
#ifdef _DEBUG
                printf("[E] DllMain: TrackFuncCall() failed, line = %d\n", __LINE__);
#endif
                CloseHandle(hPipe);
                return false;
            }
        }
        else
        {
#ifdef _DEBUG
            printf("[E] DllMain: Unknown programm mode, line = %d\n", __LINE__);
#endif
            CloseHandle(hPipe);
            return false;
        }
    }

    return true;
}

