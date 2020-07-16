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
extern "C" LPVOID ptrTargetFunctionToTrackTrampoline = NULL;

string strFileToHide;

HANDLE hPipe;

decltype(CreateFileW)* CreateFileW_trampoline;
decltype(CreateFileA)* CreateFileA_trampoline;
decltype(FindFirstFileW)* FindFirstFileW_trampoline;
decltype(FindFirstFileA)* FindFirstFileA_trampoline;
decltype(FindNextFileW)* FindNextFileW_trampoline;
decltype(FindNextFileA)* FindNextFileA_trampoline;
decltype(FindFirstFileExW)* FindFirstFileExW_trampoline;
decltype(FindFirstFileExA)* FindFirstFileExA_trampoline;

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

bool InjectFunction(string dllName, string functionToDetourName, LPVOID injectionFunction, LPVOID& ptrTargetFunctionTrampoline)
{
#ifdef _DEBUG
    printf("[D] Detouring \"%s\" from \"%s\".\n", functionToDetourName.c_str(), dllName.c_str());
#endif

    ptrTargetFunctionTrampoline = DetourFindFunction(dllName.c_str(), functionToDetourName.c_str());
    if (ptrTargetFunctionTrampoline == NULL)
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
    printf("[D] Before DetourAttach: ptrTargetFunction = %p\n", ptrTargetFunctionTrampoline);
#endif

    PDETOUR_TRAMPOLINE pRealTrampoline;
    PVOID pRealTarget;
    PVOID pRealDetour;
    detourErrorCode = DetourAttachEx((PVOID*)&ptrTargetFunctionTrampoline, injectionFunction, &pRealTrampoline, &pRealTarget, &pRealDetour);
    if (detourErrorCode != NO_ERROR)
    {
#ifdef _DEBUG
        printf("[E] InjectFunction: DetourAttach() failed, detour error = \"%s\", line = %d\n", (ExplainDetourError(detourErrorCode)).c_str(), __LINE__);
#endif
        DetourTransactionAbort();
        return false;
    }

#ifdef _DEBUG
    printf("[D] After DetourAttach: ptrTargetFunction = %p\n", ptrTargetFunctionTrampoline);
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
    wstring wstrFileToHide(strFileToHide.begin(), strFileToHide.end());
    wstring wstrArgFileName(lpFileName);

#ifdef _DEBUG
    wprintf(L"[D] CreateFileW_detour: lpFileName = %s\n", lpFileName);
#endif

    if (wstrArgFileName.find(wstrFileToHide) == wstring::npos)
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
        SetLastError(ERROR_FILE_NOT_FOUND);
        return INVALID_HANDLE_VALUE;
    }
}

HANDLE CreateFileA_detour(
    LPCSTR                lpFileName,
    DWORD                 dwDesiredAccess,
    DWORD                 dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD                 dwCreationDisposition,
    DWORD                 dwFlagsAndAttributes,
    HANDLE                hTemplateFile
)
{
    string strArgFileName(lpFileName);

#ifdef _DEBUG
    wprintf(L"[D] CreateFileA_detour: lpFileName = %s\n", lpFileName);
#endif

    if (strArgFileName.find(strFileToHide) == wstring::npos)
    {
        return CreateFileA_trampoline(
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
        SetLastError(ERROR_FILE_NOT_FOUND);
        return INVALID_HANDLE_VALUE;
    }
}

HANDLE FindFirstFileW_detour(
    LPCWSTR            lpFileName,
    LPWIN32_FIND_DATAW lpFindFileData
)
{
    WIN32_FIND_DATAW findFileData;
    HANDLE fileHandle = FindFirstFileW_trampoline(lpFileName, &findFileData);
    if (fileHandle != INVALID_HANDLE_VALUE)
    {
        wstring wstrFileToHide(strFileToHide.begin(), strFileToHide.end());
        wstring wstrFoundFileName(findFileData.cFileName);

#ifdef _DEBUG
        wprintf(L"[D] FindFirstFileW_detour: found file name = %s\n", findFileData.cFileName);
#endif

        if (wstrFoundFileName.find(wstrFileToHide) == wstring::npos)
        {
            memcpy(lpFindFileData, &findFileData, sizeof(WIN32_FIND_DATAW));
            return fileHandle;
        }
        else
        {
            FindClose(fileHandle);
            SetLastError(ERROR_FILE_NOT_FOUND);
            return INVALID_HANDLE_VALUE;
        }
    }
    else
    {
        return INVALID_HANDLE_VALUE;
    }
}

HANDLE FindFirstFileA_detour(
    LPCSTR             lpFileName,
    LPWIN32_FIND_DATAA lpFindFileData
)
{
    WIN32_FIND_DATAA findFileData;
    HANDLE fileHandle = FindFirstFileA_trampoline(lpFileName, &findFileData);
    if (fileHandle != INVALID_HANDLE_VALUE)
    {
        string strFoundFileName(findFileData.cFileName);

#ifdef _DEBUG
        wprintf(L"[D] FindFirstFileA_detour: found file name = %s\n", findFileData.cFileName);
#endif

        if (strFoundFileName.find(strFileToHide) == wstring::npos)
        {
            memcpy(lpFindFileData, &findFileData, sizeof(WIN32_FIND_DATAA));
            return fileHandle;
        }
        else
        {
            FindClose(fileHandle);
            SetLastError(ERROR_FILE_NOT_FOUND);
            return INVALID_HANDLE_VALUE;
        }
    }
    else
    {
        return INVALID_HANDLE_VALUE;
    }
}

BOOL FindNextFileW_detour(
    HANDLE             hFindFile,
    LPWIN32_FIND_DATAW lpFindFileData
)
{
    WIN32_FIND_DATAW findFileData;
    bool isFindNextFileW_successful = FindNextFileW_trampoline(hFindFile, &findFileData);
    
    if (isFindNextFileW_successful)
    {
        wstring wstrFileToHide(strFileToHide.begin(), strFileToHide.end());
        wstring wstrFoundFileName(findFileData.cFileName);

#ifdef _DEBUG
        wprintf(L"[D] FindNextFileW_detour: found file name = %s\n", findFileData.cFileName);
#endif

        if (wstrFoundFileName.find(wstrFileToHide) == wstring::npos)
        {
            memcpy(lpFindFileData, &findFileData, sizeof(WIN32_FIND_DATAW));
            return true;
        }
        else
        {
            SetLastError(ERROR_NO_MORE_FILES);
            return false;
        }
    }
    else
    {
        return false;
    }
}

BOOL FindNextFileA_detour(
    HANDLE             hFindFile,
    LPWIN32_FIND_DATAA lpFindFileData
)
{
    WIN32_FIND_DATAA findFileData;
    bool isFindNextFileW_successful = FindNextFileA_trampoline(hFindFile, &findFileData);

    if (isFindNextFileW_successful)
    {
        string strFoundFileName(findFileData.cFileName);

#ifdef _DEBUG
        wprintf(L"[D] FindNextFileA_detour: found file name = %s\n", findFileData.cFileName);
#endif

        if (strFoundFileName.find(strFileToHide) == wstring::npos)
        {
            memcpy(lpFindFileData, &findFileData, sizeof(WIN32_FIND_DATAA));
            return true;
        }
        else
        {
            SetLastError(ERROR_NO_MORE_FILES);
            return false;
        }
    }
    else
    {
        return false;
    }
}

HANDLE FindFirstFileExW_detour(
    LPCWSTR            lpFileName,
    FINDEX_INFO_LEVELS fInfoLevelId,
    LPVOID             lpFindFileData,
    FINDEX_SEARCH_OPS  fSearchOp,
    LPVOID             lpSearchFilter,
    DWORD              dwAdditionalFlags
)
{
    WIN32_FIND_DATAW findFileData;
    HANDLE fileHandle = FindFirstFileExW_trampoline(
        lpFileName,
        fInfoLevelId,
        &findFileData,
        fSearchOp,
        lpSearchFilter,
        dwAdditionalFlags);

    if (fileHandle != INVALID_HANDLE_VALUE)
    {
        wstring wstrFileToHide(strFileToHide.begin(), strFileToHide.end());
        wstring wstrFoundFileName(findFileData.cFileName);

#ifdef _DEBUG
        wprintf(L"[D] FindFirstFileW_detour: found file name = %s\n", findFileData.cFileName);
#endif

        if (wstrFoundFileName.find(wstrFileToHide) == wstring::npos)
        {
            memcpy(lpFindFileData, &findFileData, sizeof(WIN32_FIND_DATAW));
            return fileHandle;
        }
        else
        {
            FindClose(fileHandle);
            SetLastError(ERROR_FILE_NOT_FOUND);
            return INVALID_HANDLE_VALUE;
        }
    }
    else
    {
        return INVALID_HANDLE_VALUE;
    }
}

HANDLE FindFirstFileExA_detour(
    LPCSTR             lpFileName,
    FINDEX_INFO_LEVELS fInfoLevelId,
    LPVOID             lpFindFileData,
    FINDEX_SEARCH_OPS  fSearchOp,
    LPVOID             lpSearchFilter,
    DWORD              dwAdditionalFlags
)
{
    WIN32_FIND_DATAA findFileData;
    HANDLE fileHandle = FindFirstFileExA_trampoline(
        lpFileName,
        fInfoLevelId,
        &findFileData,
        fSearchOp,
        lpSearchFilter,
        dwAdditionalFlags);

    if (fileHandle != INVALID_HANDLE_VALUE)
    {
        string strFoundFileName(findFileData.cFileName);

#ifdef _DEBUG
        wprintf(L"[D] FindFirstFileA_detour: found file name = %s\n", findFileData.cFileName);
#endif

        if (strFoundFileName.find(strFileToHide) == wstring::npos)
        {
            memcpy(lpFindFileData, &findFileData, sizeof(WIN32_FIND_DATAA));
            return fileHandle;
        }
        else
        {
            FindClose(fileHandle);
            SetLastError(ERROR_FILE_NOT_FOUND);
            return INVALID_HANDLE_VALUE;
        }
    }
    else
    {
        return INVALID_HANDLE_VALUE;
    }
}

bool HideFile(string& fileName)
{
    strFileToHide = fileName;
    LPVOID ptrTargetFunctionTrampoline;

    if (!InjectFunction("kernel32.dll", "CreateFileW", CreateFileW_detour, ptrTargetFunctionTrampoline))
    {
#ifdef _DEBUG
        printf("[E] HideFile: InjectFunction() failed, line = %d\n", __LINE__);
#endif
        return false;
    }
    CreateFileW_trampoline = (decltype(CreateFileW_trampoline))ptrTargetFunctionTrampoline;

    if (!InjectFunction("kernel32.dll", "CreateFileA", CreateFileA_detour, ptrTargetFunctionTrampoline))
    {
#ifdef _DEBUG
        printf("[E] HideFile: InjectFunction() failed, line = %d\n", __LINE__);
#endif
        return false;
    }
    CreateFileA_trampoline = (decltype(CreateFileA_trampoline))ptrTargetFunctionTrampoline;

    if (!InjectFunction("kernel32.dll", "FindFirstFileW", FindFirstFileW_detour, ptrTargetFunctionTrampoline))
    {
#ifdef _DEBUG
        printf("[E] HideFile: InjectFunction() failed, line = %d\n", __LINE__);
#endif
        return false;
    }
    FindFirstFileW_trampoline = (decltype(FindFirstFileW_trampoline))ptrTargetFunctionTrampoline;

    if (!InjectFunction("kernel32.dll", "FindFirstFileA", FindFirstFileA_detour, ptrTargetFunctionTrampoline))
    {
#ifdef _DEBUG
        printf("[E] HideFile: InjectFunction() failed, line = %d\n", __LINE__);
#endif
        return false;
    }
    FindFirstFileA_trampoline = (decltype(FindFirstFileA_trampoline))ptrTargetFunctionTrampoline;

    if (!InjectFunction("kernel32.dll", "FindNextFileW", FindNextFileW_detour, ptrTargetFunctionTrampoline))
    {
#ifdef _DEBUG
        printf("[E] HideFile: InjectFunction() failed, line = %d\n", __LINE__);
#endif
        return false;
    }
    FindNextFileW_trampoline = (decltype(FindNextFileW_trampoline))ptrTargetFunctionTrampoline;

    if (!InjectFunction("kernel32.dll", "FindNextFileA", FindNextFileA_detour, ptrTargetFunctionTrampoline))
    {
#ifdef _DEBUG
        printf("[E] HideFile: InjectFunction() failed, line = %d\n", __LINE__);
#endif
        return false;
    }
    FindNextFileA_trampoline = (decltype(FindNextFileA_trampoline))ptrTargetFunctionTrampoline;

    if (!InjectFunction("kernel32.dll", "FindFirstFileExW", FindFirstFileExW_detour, ptrTargetFunctionTrampoline))
    {
#ifdef _DEBUG
        printf("[E] HideFile: InjectFunction() failed, line = %d\n", __LINE__);
#endif
        return false;
    }
    FindFirstFileExW_trampoline = (decltype(FindFirstFileExW_trampoline))ptrTargetFunctionTrampoline;

    if (!InjectFunction("kernel32.dll", "FindFirstFileExA", FindFirstFileExA_detour, ptrTargetFunctionTrampoline))
    {
#ifdef _DEBUG
        printf("[E] HideFile: InjectFunction() failed, line = %d\n", __LINE__);
#endif
        return false;
    }
    FindFirstFileExA_trampoline = (decltype(FindFirstFileExA_trampoline))ptrTargetFunctionTrampoline;

    return true;
}

bool TrackFuncCall(string& funcName)
{
    if (!InjectFunction("kernel32.dll", funcName.c_str(), hook, ptrTargetFunctionToTrackTrampoline))
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

