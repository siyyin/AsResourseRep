#pragma once
//#define _CRT_SECURE_NO_WARNINGS

#ifndef _HRA_LOGER_H_
#define _HRA_LOGER_H_

#include "RwLock.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include "comm.h"
#include <windows.h>

#define MAX_LOGFILE_PATH 1024
#define MAX_LOGFILE_SIZE 5 * 1024 * 1024  // max log file size is 5M
#define MAX_LOGFILE_LINE 1024
//#define LOG_FILE_PATH   "debug"    //相对路径
#define LOG_FILE_HEAD   "hra"         //日志文件头
//#define LOG_FILE_DIR_PATH_CMD "IF NOT EXIST .\\debug\\ MD .\\debug\\"
#define MAX_COMD_BUFF_LEN 4096
#define MAX_LOG_FILE_NUM 5

typedef enum _LOG_LEVEL {
	LOG_LEVEL_DEBUG = 0,
	LOG_LEVEL_INFO,
	LOG_LEVEL_WARNING,
	LOG_LEVEL_ERROR,
	LOG_LEVEL_UNKNOWN
} LOG_LEVEL;

class HRA_UTILITY_EXPORT CLoger {
public:
	
	static bool Initialize(const char* szLogPath = NULL, const char* szFileHead = LOG_FILE_HEAD);
	static void UnInitialize();
	//static void SetLogFilePath(char *szLogFilePath);
	static LOG_LEVEL GetLogLevel();
	static void SetLogLevel(LOG_LEVEL debug);

	static bool ready(void);
	static void Log(int level, const char* szFile, const char* szFunc, int nLine, const char* szFormat, ...);
    static void LogW(int level, const char* szFile, const char* szFunc, int nLine, const wchar_t* szFormat, ...);

private:
	CLoger(void);
	virtual ~CLoger(void);
    static std::string getLogDir();
    static std::string getNewLogFileName();
    static void CleanLogFile();
    static std::string m_logPath;
    static std::string m_strLogFileHead;
};

HRA_UTILITY_EXPORT extern bool ExecuteCmd(std::string* result, const char* szFormat, ...);

#define LOGW_DEBUG(szFormat, ...) \
    CLoger::LogW((LOG_LEVEL_DEBUG), __FILE__, __FUNCTION__, __LINE__, (szFormat), ##__VA_ARGS__)
#define LOGW_INFO(szFormat, ...) \
    CLoger::LogW((LOG_LEVEL_INFO), __FILE__, __FUNCTION__, __LINE__, (szFormat), ##__VA_ARGS__)
#define LOGW_WARN(szFormat, ...) \
    CLoger::LogW((LOG_LEVEL_WARNING), __FILE__, __FUNCTION__, __LINE__, (szFormat), ##__VA_ARGS__)
#define LOGW_ERROR(szFormat, ...) \
    CLoger::LogW((LOG_LEVEL_ERROR), __FILE__, __FUNCTION__, __LINE__, (szFormat), ##__VA_ARGS__)

#define LOG_DEBUG(szFormat, ...) \
	CLoger::Log((LOG_LEVEL_DEBUG), __FILE__, __FUNCTION__ , __LINE__, (szFormat), ##__VA_ARGS__)
#define LOG_INFO(szFormat, ...) \
	CLoger::Log((LOG_LEVEL_INFO), __FILE__, __FUNCTION__ , __LINE__, (szFormat), ##__VA_ARGS__)
#define LOG_WARN(szFormat, ...) \
	CLoger::Log((LOG_LEVEL_WARNING), __FILE__, __FUNCTION__ , __LINE__, (szFormat), ##__VA_ARGS__)
#define LOG_ERROR(szFormat, ...) \
	CLoger::Log((LOG_LEVEL_ERROR), __FILE__, __FUNCTION__ , __LINE__, (szFormat), ##__VA_ARGS__)

#define ASSERT(expr, szFormat, ...)                                                        \
	do {                                                                                   \
	if (!(expr)) {                                                                     \
	CLoger::Log((LOG_LEVEL_ERROR), __FILE__, __FUNCTION__ , __LINE__, (szFormat), ##__VA_ARGS__); \
	return false;                                                                  \
	}                                                                                  \
	} while (0)
#define ASSERT_INFO(expr, szFormat, ...)                                                   \
	do {                                                                                   \
	if (!(expr)) {                                                                     \
	CLoger::Log((LOG_LEVEL_ERROR), __FILE__, __FUNCTION__, __LINE__, (szFormat), ##__VA_ARGS__); \
	}                                                                                  \
	} while (0)


#ifdef __cplusplus
extern "C"
{
#endif

    typedef void (*EngineLogFun)(int level, const char* filepath, const char* func, int line, const char* pszLogLine);
    HRA_UTILITY_EXPORT void EngineLogFunEntry(int level, const char* filepath, const char* func, int line,
                                              const char* pszLogLine);
#ifdef __cplusplus
}
#endif

#endif  // _HRA_LOGER_H_
