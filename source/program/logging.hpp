#pragma once
#include <cstdarg>

#include "lib.hpp"
#include "nn.hpp"

namespace exl::log
{
    Result Initialize();
    void Finalize();

    void DebugLog(const char *fmt, ...);
    void DebugLogImpl(const char *fmt, std::va_list args);
    void DebugDataDump(const void *data, size_t size, const char *fmt, ...);

#define DEBUG_LOG(fmt, ...) exl::log::DebugLog(fmt "\n", ##__VA_ARGS__)
#define DEBUG_DATA_DUMP(data, size, fmt, ...) exl::log::DebugDataDump(data, size, fmt "[%#x]:\n", ##__VA_ARGS__, size)

}
