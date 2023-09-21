#include "lib/util/format/util_format_string.hpp"
#include "logging.hpp"

const size_t TlsBackupSize = 0x100;
#define BACKUP_TLS()               \
    u8 _tls_backup[TlsBackupSize]; \
    memcpy(_tls_backup, armGetTls(), TlsBackupSize);
#define RESTORE_TLS() memcpy(armGetTls(), _tls_backup, TlsBackupSize);

namespace exl::log
{
    namespace
    {
        constexpr const char LogFilePath[] = "sdmc:/exlaunch.log";
        nn::fs::FileHandle LogFile;
        s64 LogOffset;

        bool initialized = false;

        nn::os::MutexType g_log_lock;
    }

    Result Initialize()
    {
        if (initialized)
        {
            return result::Success;
        }

        nn::os::InitializeMutex(&g_log_lock, false, 1);

        // Open log file if it exists otherwise create it
        Result rc = nn::fs::OpenFile(&LogFile, LogFilePath, nn::fs::OpenMode_Write | nn::fs::OpenMode_Append);
        if (R_FAILED(rc))
        {
            R_TRY(nn::fs::CreateFile(LogFilePath, 0));
            R_TRY(nn::fs::OpenFile(&LogFile, LogFilePath, nn::fs::OpenMode_Write | nn::fs::OpenMode_Append));
        }

        // Get file write offset
        R_TRY(nn::fs::GetFileSize(&LogOffset, LogFile));

        char buff[0x100];
        int len = ams::util::TSNPrintf(buff, sizeof(buff), "======================== LOG STARTED ========================\n");
        R_ABORT_UNLESS(nn::fs::WriteFile(LogFile, LogOffset, buff, len, nn::fs::WriteOption::CreateOption(nn::fs::WriteOptionFlag_Flush)));
        LogOffset += len;

        nn::fs::CloseFile(LogFile);

        initialized = true;

        return result::Success;
    }

    void Finalize()
    {
        nn::fs::FlushFile(LogFile);
        nn::fs::CloseFile(LogFile);

        nn::os::FinalizeMutex(&g_log_lock);

        initialized = false;
    }

    void DebugLogImpl(const char *fmt, std::va_list args)
    {
        BACKUP_TLS();

        if (initialized)
        {
            R_ABORT_UNLESS(nn::fs::OpenFile(&LogFile, LogFilePath, nn::fs::OpenMode_Write | nn::fs::OpenMode_Append));
        }

        char buff[0x100];
        int len;

        auto thread = nn::os::GetCurrentThread();
        auto ts = nn::os::GetSystemTick().ToTimeSpan();
        len = ams::util::TSNPrintf(buff, sizeof(buff), "[ts: %6lums t: (%lu) %-22s p: %d/%d] ",
                                   ts.GetMilliSeconds(),
                                   nn::os::GetThreadId(thread),
                                   nn::os::GetThreadNamePointer(thread),
                                   nn::os::GetThreadPriority(thread) + 28,
                                   nn::os::GetThreadCurrentPriority(thread) + 28);

        svcOutputDebugString(buff, len);
        if (initialized)
        {
            R_ABORT_UNLESS(nn::fs::WriteFile(LogFile, LogOffset, buff, len, nn::fs::WriteOption::CreateOption(nn::fs::WriteOptionFlag_None)));
            LogOffset += len;
        }

        // len = std::vsnprintf(buff, sizeof(buff), fmt, args);
        len = ams::util::TVSNPrintf(buff, sizeof(buff), fmt, args);
        svcOutputDebugString(buff, len);
        if (initialized)
        {
            R_ABORT_UNLESS(nn::fs::WriteFile(LogFile, LogOffset, buff, len, nn::fs::WriteOption::CreateOption(nn::fs::WriteOptionFlag_Flush)));
            LogOffset += len;

            nn::fs::CloseFile(LogFile);
        }

        RESTORE_TLS();
    }

    void DebugLog(const char *fmt, ...)
    {
        nn::os::LockMutex(&g_log_lock);

        std::va_list args;
        va_start(args, fmt);
        DebugLogImpl(fmt, args);
        va_end(args);

        nn::os::UnlockMutex(&g_log_lock);
    }

    void DebugDataDumpImpl(const void *data, size_t size)
    {
        if (!initialized)
        {
            return;
        }

        BACKUP_TLS();

        size_t buff_size = 4 * size + 1;
        std::unique_ptr<char[]> buff(new char[buff_size]);

        R_ABORT_UNLESS(nn::fs::OpenFile(&LogFile, LogFilePath, nn::fs::OpenMode_Write | nn::fs::OpenMode_Append));

        int len = 0;
        for (size_t i = 0; i < size; ++i)
        {
            if ((i % 16) == 0)
            {
                len += ams::util::TSNPrintf(buff.get() + len, buff_size - len, " ");
            }

            len += ams::util::TSNPrintf(buff.get() + len, buff_size - len, "%02x%c",
                                        reinterpret_cast<const u8 *>(data)[i],
                                        (i + 1) % 16 ? ' ' : '\n');
        }
        len += ams::util::TSNPrintf(buff.get() + len, buff_size - len, "\n");

        R_ABORT_UNLESS(nn::fs::WriteFile(LogFile, LogOffset, buff.get(), len, nn::fs::WriteOption::CreateOption(nn::fs::WriteOptionFlag_Flush)));
        LogOffset += len;

        nn::fs::CloseFile(LogFile);
        RESTORE_TLS();
    }

    void DebugDataDump(const void *data, size_t size, const char *fmt, ...)
    {
        nn::os::LockMutex(&g_log_lock);

        std::va_list args;
        va_start(args, fmt);
        DebugLogImpl(fmt, args);
        va_end(args);
        DebugDataDumpImpl(data, size);

        nn::os::UnlockMutex(&g_log_lock);
    }

}
