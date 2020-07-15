#define WIN32_LEAN_AND_MEAN

#include <Windows.h>
#include <stdio.h>
#include <cstdlib>
#include <string>
#include <cstdio>

#include "../Detours/include/detours.h"
#include "../Hook-Inject.h"

using namespace std;

extern "C" void hook();
extern "C" LPVOID ptrTargetFunctionToTrack = NULL;

string strFileToHide;

HANDLE hPipe;

decltype(CreateFileW)* CreateFileW_trampoline;

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

extern "C" void LogTargetFunctionCall()
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

bool InjectFunction(string dllName, string functionToDetourName, LPVOID injectionFunction, LPVOID& ptrTargetFunction)
{
#ifdef _DEBUG
    printf("[D] Detouring \"%s\" from \"%s\".\n", functionToDetourName.c_str(), dllName.c_str());
#endif

    ptrTargetFunction = DetourFindFunction(dllName.c_str(), functionToDetourName.c_str());
    if (ptrTargetFunction == NULL)
    {
#ifdef _DEBUG
        printf("[E] InjectFunction: DetourFindFunction() failed, line = %d\n", __LINE__);
#endif
        return false;
    }

    LONG detourErrorCode = DetourTransactionBegin();
    if (detourErrorCode != NO_ERROR)
    {
#ifdef _DEBUG
        printf("[E] InjectFunction: DetourTransactionBegin() failed, detour error = \"%s\", line = %d\n", (ExplainDetourError(detourErrorCode)).c_str(), __LINE__);
#endif
        DetourTransactionAbort();
        return false;
    }

    detourErrorCode = DetourUpdateThread(GetCurrentThread());
    if (detourErrorCode != NO_ERROR)
    {
#ifdef _DEBUG
        printf("[E] InjectFunction: DetourUpdateThread() failed, detour error = \"%s\", line = %d\n", (ExplainDetourError(detourErrorCode)).c_str(), __LINE__);
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
    detourErrorCode = DetourAttachEx((PVOID*)&ptrTargetFunction, injectionFunction, &pRealTrampoline, &pRealTarget, &pRealDetour);
    if (detourErrorCode != NO_ERROR)
    {
#ifdef _DEBUG
        printf("[E] InjectFunction: DetourAttach() failed, detour error = \"%s\", line = %d\n", (ExplainDetourError(detourErrorCode)).c_str(), __LINE__);
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
        printf("[E] InjectFunction: DetourTransactionCommit() failed, detour error = \"%s\", line = %d\n", (ExplainDetourError(detourErrorCode)).c_str(), __LINE__);
#endif
        DetourTransactionAbort();
        return false;
    }

    return true;
}

HANDLE CreateFileW_detour (
    LPCWSTR               lpFileName,
    DWORD                 dwDesiredAccess,
    DWORD                 dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD                 dwCreationDisposition,
    DWORD                 dwFlagsAndAttributes,
    HANDLE                hTemplateFile
)
{
    wstring wstrFileNameToHide(strFileToHide.begin(), strFileToHide.end());
    wstring wstrArgFileName(lpFileName);

#ifdef _DEBUG
    wprintf(L"[D] CreateFileW_detour: lpFileName = %s\n", lpFileName);
#endif


    if (wstrArgFileName.find(wstrFileNameToHide) == wstring::npos)
    {
        return CreateFileW_trampoline(
            lpFileName,
            dwDesiredAccess,
            dwShareMode,
            lpSecurityAttributes,
            dwCreationDisposition,
            dwFlagsAndAttributes,
            hTemplateFile
        );
    }
    else
    {
        return INVALID_HANDLE_VALUE;
    }
}

bool HideFile(string& fileName)
{
    strFileToHide = fileName;

    LPVOID ptrTargetFunction;
    if (!InjectFunction("kernel32.dll", "CreateFileW", CreateFileW_detour, ptrTargetFunction))
    {
#ifdef _DEBUG
        printf("[E] HideFile: InjectFunction() failed, line = %d\n", __LINE__);
#endif
        return false;
    }
    CreateFileW_trampoline = (decltype(CreateFileW_trampoline))ptrTargetFunction;

    // Do ...

    return true;
}

bool TrackFuncCall(string& funcName)
{
    if (!InjectFunction("kernel32.dll", funcName.c_str(), hook, ptrTargetFunctionToTrack))
    {
#ifdef _DEBUG
        printf("[E] TrackFuncCall: InjectFunction() failed, line = %d\n", __LINE__);
#endif
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
            if (!HideFile(fileOrFunctionName))
            {
#ifdef _DEBUG
                printf("[E] DllMain: HideFile() failed, line = %d\n", __LINE__);
#endif
                CloseHandle(hPipe);
                return false;
            }
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

