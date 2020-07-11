#pragma once

#define ENABLE_DBG_MSG 1

#define PIPE_NAME "\\\\.\\pipe\\hook-inject"
#define PIPE_BUFFER_SIZE 1000

enum class ProgrammMode
{
    kTrackCallOfFunction = 1,
    kHideFileFromProcess = 2
};