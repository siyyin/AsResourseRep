#include "LogManager.h"
#include <ctime>

#ifdef _WIN32
#include <share.h>
#else
#include <unistd.h>
#include "port_linux.h"
#include <sys/stat.h>
#endif

CLogManagerDebugLog* g_debugLogObj;
CLogManagerDebugLog::CLogManagerDebugLog()
{
    m_fpDebug = NULL;
    m_debugLevel = LOG_LEVEL_INFO;
    memset(m_szLogPath, 0, sizeof(m_szLogPath));
}
CLogManagerDebugLog::~CLogManagerDebugLog()
{
    m_fpDebug = NULL;
    memset(m_szLogPath, 0, sizeof(m_szLogPath));
}
bool CLogManagerDebugLog::Initialize(const char* szLogFilePath)
{
    if (szLogFilePath == NULL || strlen(szLogFilePath) == 0) {
        return false;
    }
    if (m_fpDebug != NULL) {
        FlushDebugLog();
#ifdef _WIN32
        CloseHandle(m_fpDebug);
#else
        fclose(m_fpDebug);
#endif
        m_fpDebug = NULL;
    }
    memset(m_szLogPath, 0, sizeof(m_szLogPath));
    strncpy_s(m_szLogPath, sizeof(m_szLogPath), szLogFilePath, strlen(szLogFilePath));
#ifdef _WIN32
    //m_fpDebug = _fsopen(m_szLogPath, "a+", _SH_DENYWR);
    SECURITY_ATTRIBUTES securityAttributes = {0};
    securityAttributes.bInheritHandle = FALSE;
    securityAttributes.nLength = sizeof(securityAttributes);
    securityAttributes.lpSecurityDescriptor = NULL;
    m_fpDebug = CreateFileA(m_szLogPath, GENERIC_WRITE, FILE_SHARE_READ, &securityAttributes, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    SetFilePointer(m_fpDebug, 0, 0, FILE_END);
#else
    m_fpDebug = fopen(m_szLogPath, "a+");
	chmod(m_szLogPath, S_IRUSR | S_IWUSR | S_IRGRP);
#endif
    if (m_fpDebug == NULL) {
        return false;
    }
    return true;
}

bool CLogManagerDebugLog::UnInitialize()
{
    if (m_fpDebug) {
        FlushDebugLog();
#ifdef _WIN32
        CloseHandle(m_fpDebug);
#else
        fclose(m_fpDebug);
#endif
        m_fpDebug = NULL;
    }
    memset(m_szLogPath, 0, sizeof(m_szLogPath));
    return true;
}

LOGMANAGER_LOG_LEVEL CLogManagerDebugLog::GetDebugLevel()
{
    return m_debugLevel;
}

void CLogManagerDebugLog::SetDebugLevel(LOGMANAGER_LOG_LEVEL level)
{
    m_debugLevel = level;
}

void CLogManagerDebugLog::PrintDebugLogStr(int level, const char* szFile, int nLine, const char* szMsg)
{
    if (level < m_debugLevel || !m_fpDebug || !szFile || !szMsg) {
        return;
    }
    char strInfoType[128] = {0};

    switch (level) {
        case LOG_LEVEL_PERFORMANCE:
            strncpy_s(strInfoType, sizeof(strInfoType) - 1, "Performance", strlen("Performance"));
            break;
        case LOG_LEVEL_DEBUG:
            strncpy_s(strInfoType, sizeof(strInfoType) - 1, "Debug", strlen("Debug"));
            break;
        case LOG_LEVEL_INFO:
            strncpy_s(strInfoType, sizeof(strInfoType) - 1, "Info", strlen("Info"));
            break;
        case LOG_LEVEL_WARNING:
            strncpy_s(strInfoType, sizeof(strInfoType) - 1, "Warning", strlen("Warning"));
            break;
        case LOG_LEVEL_ERROR:
            strncpy_s(strInfoType, sizeof(strInfoType) - 1, "Error", strlen("Error"));
            break;
        case LOG_LEVEL_FATAL:
            strncpy_s(strInfoType, sizeof(strInfoType) - 1, "Fatal", strlen("Fatal"));
            break;
        default:
            strncpy_s(strInfoType, sizeof(strInfoType) - 1, "Unknown", strlen("Unknown"));
            break;
    }
    // get current time
    time_t rawtime = 0;
    struct tm timeinfo;
    time(&rawtime);
#ifdef _WIN32
    localtime_s(&timeinfo, &rawtime);
#else
    localtime_r(&rawtime, &timeinfo);
#endif

    if (NULL == m_fpDebug) {
        printf("%4d-%02d-%02d %02d:%02d:%02d[line %4d][%s] %s\n", timeinfo.tm_year + 1900, timeinfo.tm_mon + 1,
               timeinfo.tm_mday, timeinfo.tm_hour, timeinfo.tm_min, timeinfo.tm_sec, nLine, strInfoType, szMsg);
        return;
    }

#ifdef _WIN32
    char chBuffer[MAX_LOGFILE_LINE * 2] = {0}; 
    _snprintf_s(chBuffer, sizeof(chBuffer) -1, "%4d-%02d-%02d %02d:%02d:%02d[line %4d][%s]: %s\r\n", timeinfo.tm_year + 1900, timeinfo.tm_mon + 1,
            timeinfo.tm_mday, timeinfo.tm_hour, timeinfo.tm_min, timeinfo.tm_sec, nLine, strInfoType, szMsg);
    DWORD dwWritenSize = 0;
    BOOL bRet = ::WriteFile(m_fpDebug, chBuffer, (DWORD)strlen(chBuffer), &dwWritenSize, NULL);
    if (!bRet){
      OutputDebugString(L"PrintDebugLogStr: Write log to file error");
    }

    LARGE_INTEGER size;
		::GetFileSizeEx(m_fpDebug, &size);
		__int64 nSize1 = size.QuadPart;
    if (nSize1 > MAX_LOGFILE_SIZE){
      CloseHandle(m_fpDebug);
 #else
    fprintf(m_fpDebug, "%4d-%02d-%02d %02d:%02d:%02d[line %4d][%s]: %s\n", timeinfo.tm_year + 1900, timeinfo.tm_mon + 1,
            timeinfo.tm_mday, timeinfo.tm_hour, timeinfo.tm_min, timeinfo.tm_sec, nLine, strInfoType, szMsg);
    fflush(m_fpDebug);

    if (ftell(m_fpDebug) > MAX_LOGFILE_SIZE) {
        fclose(m_fpDebug);
#endif
        remove(m_szLogPath);
#ifdef _WIN32
        Sleep(500);
        //m_fpDebug = _fsopen(m_szLogPath, "a+", _SH_DENYWR);
        SECURITY_ATTRIBUTES securityAttributes = {0};
        securityAttributes.bInheritHandle = FALSE;
        securityAttributes.nLength = sizeof(securityAttributes);
        securityAttributes.lpSecurityDescriptor = NULL;
        m_fpDebug = CreateFileA(m_szLogPath, GENERIC_WRITE, FILE_SHARE_READ, &securityAttributes, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        SetFilePointer(m_fpDebug, 0, 0, FILE_END);
#else
        usleep(500 * 1000);
        m_fpDebug = fopen(m_szLogPath, "a+");
#endif
    }
}

void CLogManagerDebugLog::PrintDebugLog(int level, const char* szFile, int nLine, const char* szFormat, ...)
{
    if (level < m_debugLevel || !szFile || !szFormat) {
        return;
    }
    char szLogBuf[MAX_LOGFILE_LINE] = {0};
    va_list args;
    va_start(args, szFormat);
#ifdef _WIN32
    vsnprintf_s(szLogBuf, MAX_LOGFILE_LINE - 1, szFormat, args);
#else
    snprintf(szLogBuf, MAX_LOGFILE_LINE - 1, szFormat, args);
#endif
    va_end(args);
    PrintDebugLogStr(level, szFile, nLine, szLogBuf);
}

void CLogManagerDebugLog::PrintDebugLogSync(int level, const char* szFile, int nLine, const char* szFormat, ...)
{
    if (level < m_debugLevel || !szFile || !szFormat) {
        return;
    }
    char szLogBuf[MAX_LOGFILE_LINE] = {0};
    char* szLogBufTemp = szLogBuf;
    int logBufSize = MAX_LOGFILE_LINE;
    va_list args;
    va_start(args, szFormat);
#ifdef _WIN32
    int len = vsnprintf_s(szLogBuf, MAX_LOGFILE_LINE - 1, szFormat, args);
	va_end(args);
#else
    int len = vsnprintf(szLogBufTemp, MAX_LOGFILE_LINE - 1, szFormat, args);
    va_end(args);
    if (len > logBufSize - 1) {
        szLogBufTemp = new char[len + 2];
        if (NULL == szLogBufTemp) {
            szLogBufTemp = szLogBuf;
        } else {
          va_start(args, szFormat);
          len = vsnprintf(szLogBufTemp, len + 1, szFormat, args);
          va_end(args);
        }
    }
#endif


    m_mutex.Lock();
    PrintDebugLogStr(level, szFile, nLine, szLogBufTemp);
    m_mutex.Unlock();
#ifndef _WIN32
    if ((unsigned long)szLogBufTemp != (unsigned long)&szLogBuf) {
        delete[] szLogBufTemp;
    }
#endif
}

void CLogManagerDebugLog::FlushDebugLog() const
{
#ifndef _WIN32
  if (m_fpDebug) {
    fflush(m_fpDebug);
  }
#endif
}
