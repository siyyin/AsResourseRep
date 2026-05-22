#ifndef DIAGENT_LOGMANAGER_H
#define DIAGENT_LOGMANAGER_H

#include "DIMutex.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LOGFILE_PATH 1024
#define MAX_LOGFILE_SIZE 20 * 1024 * 1024  // max log file size is 20M
#define MAX_LOGFILE_LINE 1024
typedef enum _LOGMANAGER_LOG_LEVEL {
    LOG_LEVEL_PERFORMANCE = 0,
    LOG_LEVEL_DEBUG,
    LOG_LEVEL_INFO,
    LOG_LEVEL_WARNING,
    LOG_LEVEL_ERROR,
    LOG_LEVEL_FATAL,
} LOGMANAGER_LOG_LEVEL;

class CLogManagerDebugLog
{
  public:
    CLogManagerDebugLog();
    virtual ~CLogManagerDebugLog();
    bool Initialize(const char* szLogFilePath);
    bool ReInitialize(char* szLogFilePath);
    bool UnInitialize();
    LOGMANAGER_LOG_LEVEL GetDebugLevel();
    void SetDebugLevel(LOGMANAGER_LOG_LEVEL debug);
    void PrintDebugLogStr(int level, const char* szFile, int nLine, const char* szMsg);
    void PrintDebugLog(int level, const char* szFile, int nLine, const char* szFormat, ...);
    void PrintDebugLogSync(int level, const char* szFile, int nLine, const char* szFormat, ...);
    void FlushDebugLog() const;

  private:
    char m_szLogPath[MAX_LOGFILE_PATH];
#ifdef _WIN32
    HANDLE m_fpDebug;
#else
    FILE* m_fpDebug;
#endif
    di_rest_client::CDIMutex m_mutex;
    LOGMANAGER_LOG_LEVEL m_debugLevel;
};

extern CLogManagerDebugLog* g_debugLogObj;

#define DI_LOGMANAGER_LOG(level, szFormat, ...) \
    g_debugLogObj->PrintDebugLog((level), __FILE__, __LINE__, (szFormat), ##__VA_ARGS__)
#define DI_LOG(level, szFormat, ...) \
    g_debugLogObj->PrintDebugLogSync((level), __FILE__, __LINE__, (szFormat), ##__VA_ARGS__)

#define DI_LOG_PERF(szFormat, ...) \
    g_debugLogObj->PrintDebugLogSync((LOG_LEVEL_PERFORMANCE), __FILE__, __LINE__, (szFormat), ##__VA_ARGS__)
#define DI_LOG_DEBUG(szFormat, ...) \
    g_debugLogObj->PrintDebugLogSync((LOG_LEVEL_DEBUG), __FILE__, __LINE__, (szFormat), ##__VA_ARGS__)
#define DI_LOG_INFO(szFormat, ...) \
    g_debugLogObj->PrintDebugLogSync((LOG_LEVEL_INFO), __FILE__, __LINE__, (szFormat), ##__VA_ARGS__)
#define DI_LOG_WARN(szFormat, ...) \
    g_debugLogObj->PrintDebugLogSync((LOG_LEVEL_WARNING), __FILE__, __LINE__, (szFormat), ##__VA_ARGS__)
#define DI_LOG_ERROR(szFormat, ...) \
    g_debugLogObj->PrintDebugLogSync((LOG_LEVEL_ERROR), __FILE__, __LINE__, (szFormat), ##__VA_ARGS__)
#define DI_LOG_FATAL(szFormat, ...) \
    g_debugLogObj->PrintDebugLogSync((LOG_LEVEL_FATAL), __FILE__, __LINE__, (szFormat), ##__VA_ARGS__)

//extern int g_debugLevel;
#endif  // DIAGENT_LOG_MANAGER_H
