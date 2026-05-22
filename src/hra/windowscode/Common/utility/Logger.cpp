#include "Logger.h"
#include "HraAppDef.h"
#include "HraUtils.h"
#include <ctime>
#include <regex>
#include <vector>
#include <io.h>
#include <errno.h>
#include <atomic>
#include <DbgHelp.h>

static std::string m_LogFilePath;
static std::atomic<LOG_LEVEL> m_LogLevel = LOG_LEVEL_INFO;
static FILE* m_Logfp =NULL;
CDIMutex m_RwLock;
std::string CLoger::m_logPath = "";
std::string CLoger::m_strLogFileHead = "";

bool ExecuteCmd(std::string* result, const char* szFormat, ...)
{
    char szCmd[MAX_COMD_BUFF_LEN];
    memset(szCmd, 0, sizeof(szCmd));
    va_list args;
    va_start(args, szFormat);
    int len = vsnprintf_s(szCmd, MAX_COMD_BUFF_LEN-1, szFormat, args);
    va_end(args);

    FILE* fp = _popen(szCmd, "r");
    if (!fp)
    {
        if (CLoger::ready())
        {
            char errMsg[MAX_PATH] = {0};
            strerror_s(errMsg, MAX_PATH, errno);
            LOG_ERROR("windows cmd \"%s\" failed, errno:%s.", szCmd, errMsg);
         }
        return false;
    }

    if (NULL == result)
    {
        _pclose(fp);
        return true;
    }

    result->clear();
    char line[MAX_LOGFILE_LINE];
    memset(line, 0, sizeof(line));
	while (NULL != fgets(line, sizeof(line), fp))
    {
        // if (!result->empty())
        // {
        //     *result += "\n";
        // }
        *result += line;
    }

    _pclose(fp);
    return true;
}

LOG_LEVEL CLoger::GetLogLevel()
{
    return m_LogLevel;
}

void CLoger::SetLogLevel(LOG_LEVEL level)
{
    if (level >= LOG_LEVEL_UNKNOWN)
        level = LOG_LEVEL_INFO;
    m_LogLevel = level;
}

void CLoger::Log(int level, const char* filepath, const char* func, int line, const char* format, ...)
{
    if (level < m_LogLevel || !filepath || !func || !format)
    {
        return;
    }

    char* logBuf = NULL;
    va_list args;
    va_start(args, format);
    size_t logLen = _vscprintf(format, args);
    if (logLen <= 0)
    {
        va_end(args);
        return;
    }

    logBuf = (char*)malloc(logLen+1);
    if (logBuf == NULL)
    {
        va_end(args);
        return;
    }
    memset(logBuf, 0, logLen+1);

    int len = _vsnprintf(logBuf, logLen, format, args);
    va_end(args);

    static const char* infoType[LOG_LEVEL_UNKNOWN] = {
        "Debug",
        "Info",
        "Warning",
        "Error"};

    //系统时间
    SYSTEMTIME sys;
    ::GetLocalTime(&sys);
    //线程ID
    DWORD dwThreadID = ::GetCurrentThreadId();

    m_RwLock.Lock();
    if (NULL == m_Logfp)
    {
        printf("[%4d-%02d-%02d %02d:%02d:%02d.%03d][%s][%d][%s:%d][%s] %s\n", 
               sys.wYear, sys.wMonth, sys.wDay, sys.wHour, sys.wMinute, sys.wSecond, sys.wMilliseconds,
               infoType[level], dwThreadID, filepath, line, func, logBuf);
    }
    else
    {
        fprintf(m_Logfp, "[%4d-%02d-%02d %02d:%02d:%02d.%03d][%s][%d][%s:%d][%s] %s\n",
                sys.wYear, sys.wMonth, sys.wDay, sys.wHour, sys.wMinute, sys.wSecond, sys.wMilliseconds,
                infoType[level], dwThreadID, filepath, line, func, logBuf);
        fflush(m_Logfp);
        fseek(m_Logfp, 0L, SEEK_END);
        long lSize = ftell(m_Logfp);
        if (lSize > MAX_LOGFILE_SIZE)
        {
            fclose(m_Logfp);
            m_Logfp = NULL;

            std::string strNewName = getNewLogFileName();
            int ret = ::rename(m_LogFilePath.c_str(), strNewName.c_str());
            int errorno222 = errno;
            //Sleep(500);				//0.5s
            //清理过期文件
            CleanLogFile();

            m_Logfp = fopen(m_LogFilePath.c_str(), "a+");
            //int iRet = fopen_s(&m_Logfp, m_LogFilePath.c_str(), "a+");
            //if (iRet != 0 || m_Logfp == NULL)
            if (m_Logfp == NULL)
            {
                int errorno = errno;
                //char* strerrort = strerror(errno);
            }
        }
    }
    m_RwLock.UnLock();

    if (logBuf != NULL)
    {
        free(logBuf);
        logBuf = NULL;
    }
}

void CLoger::LogW(int level, const char* szFile, const char* szFunc, int nLine, const wchar_t* format, ...)
{
    wchar_t* logBufW = NULL;
    char* logBufA    = NULL;
    va_list args;
    va_start(args, format);
    size_t logLen = _vscwprintf(format, args);
    if (logLen <= 0)
    {
        va_end(args);
        return;
    }

    logBufW = (wchar_t*)malloc((logLen + 1) * sizeof(wchar_t));
    if (logBufW == NULL)
    {
        va_end(args);
        return;
    }
    memset(logBufW, 0, (logLen + 1) * sizeof(wchar_t));

    int len = _vsnwprintf(logBufW, logLen, format, args);
    va_end(args);

    int iTextLen = WideCharToMultiByte(CP_UTF8, 0, logBufW, -1, NULL, 0, NULL, NULL);
    logBufA      = (char*)malloc(iTextLen + 1);
    if (!logBufA)
    {
        if (logBufW)
        {
            free(logBufW);
            logBufW = NULL;
        }
        return;
    }
    memset(logBufA, 0, sizeof(char) * (iTextLen + 1));
    ::WideCharToMultiByte(CP_UTF8, 0, logBufW, -1, logBufA, iTextLen, NULL, NULL);
    CLoger::Log(level, szFile, szFunc, nLine, logBufA);

    if (logBufW)
    {
        free(logBufW);
        logBufW = NULL;
    }
    if (logBufA)
    {
        free(logBufA);
        logBufA = NULL;
    }
}

CLoger::CLoger()
{
}

CLoger::~CLoger()
{
}

bool CLoger::ready(void)
{
    return (m_Logfp != NULL);
}

bool CLoger::Initialize(const char* szLogPath, const char* szFileHead)
{
    m_RwLock.Lock();
    if (m_Logfp != NULL)
    {
        fflush(m_Logfp);
        fclose(m_Logfp);
        m_Logfp = NULL;
    }

    if (szLogPath != NULL && _stricmp(szLogPath, "") != 0)
    {
        CLoger::m_logPath = szLogPath;
    }

    if (szFileHead != NULL && _stricmp(szFileHead, "") != 0)
    {
        m_strLogFileHead = szFileHead;
    }
    else
    {
        m_strLogFileHead = LOG_FILE_HEAD;
    }

    DWORD dwAttributes = ::GetFileAttributesA(getLogDir().c_str());
    bool bDirExists    = (0xffffffff != dwAttributes) && (FILE_ATTRIBUTE_DIRECTORY & dwAttributes);
    if (!bDirExists)
    {
        std::string strPath = getLogDir();
        strPath             = strPath.append("\\");
        if(!MakeSureDirectoryPathExists(strPath.c_str()))
        {
            LOG_ERROR("Failed to create dir! Code:%lu, Path:%s", GetLastError(), getLogDir().c_str());
            m_RwLock.UnLock();
            return false;
        }
    }

    m_LogFilePath = getLogDir() + "\\" + m_strLogFileHead + ".log";
    m_Logfp = fopen(m_LogFilePath.c_str(), "a+");
    //int iRet = fopen_s(&m_Logfp, m_LogFilePath.c_str(), "a+");
    //if (iRet != 0 || m_Logfp == NULL)
    if (m_Logfp == NULL)
    {
        char errMsg[MAX_PATH] = {0};
        strerror_s(errMsg, MAX_PATH, errno);
        LOG_ERROR("Failed to open file : %s : %s", m_LogFilePath.c_str(), errMsg);
        m_RwLock.UnLock();
        return false;
    }
    m_RwLock.UnLock();
    return true;
}

void CLoger::UnInitialize()
{
    m_RwLock.Lock();
	if (m_Logfp != NULL)
	{
		fflush(m_Logfp);
		fclose(m_Logfp);
		m_Logfp = NULL;
	}
	m_Logfp = NULL;
	m_LogFilePath.clear();
    m_logPath.clear();
    m_RwLock.UnLock();
}

//清理过期文件
void CLoger::CleanLogFile()
{
    char szFind[MAX_PATH];
    _snprintf_s(szFind, sizeof(szFind), "%s\\%s_*.log", getLogDir().c_str(), m_strLogFileHead.c_str());
    struct _finddata_t fileinfo;
    intptr_t handle = _findfirst(szFind, &fileinfo);
    if (-1 == handle)
    {
        return;
    }

    std::vector<std::string> vctFile;
    do
    {
        //文件名规则匹配
        char szReg[MAX_PATH];
        _snprintf_s(szReg, sizeof(szReg), "%s_[0-9]{8}_[0-9]{6}\\.log", m_strLogFileHead.c_str());
        std::regex reg(szReg);
        if (!std::regex_match(fileinfo.name, reg))
        {
            continue;
        }
        vctFile.push_back(fileinfo.name);
    } while (0 == _findnext(handle, &fileinfo));

    _findclose(handle);

    //排序//删除过期文件
    std::sort(vctFile.begin(), vctFile.end());
    while (vctFile.size() > MAX_LOG_FILE_NUM)
    {
        char szDelPath[MAX_PATH];
        _snprintf_s(szDelPath, sizeof(szDelPath), "%s\\%s", getLogDir().c_str(), vctFile.begin()->c_str());
        ::remove(szDelPath);
        vctFile.erase(vctFile.begin());
    }
}

std::string CLoger::getLogDir()
{
    WCHAR szPath[MAX_PATH];
    memset(szPath, 0, sizeof(szPath));
    DWORD dwLen = GetCurrentDirectory(MAX_PATH, szPath);
    int iTextLen = WideCharToMultiByte(CP_UTF8, 0, szPath, -1, NULL, 0, NULL, NULL);
    char* pElementText = new char[iTextLen + 1];
    memset((void*)pElementText, 0, sizeof(char) * (iTextLen + 1));
    ::WideCharToMultiByte(CP_UTF8, 0, szPath, -1, pElementText, iTextLen, NULL, NULL);
    char szDir[MAX_PATH];
    _snprintf_s(szDir, sizeof(szDir), sizeof(szDir)-1, "%s\\%s", pElementText, LOG_FILE_PATH);
    delete[] pElementText;

    // 现在日志存放在产品端指定的路径下 
    if (m_logPath.empty())
    {   // 只有跑UT的时候会覆盖到此分支,正常流程不会跑此分支  
        return szDir;
    }
    char szBuffer[MAX_PATH] = {0};
    _snprintf_s(szBuffer, MAX_PATH, "%s\\%s", m_logPath.c_str(), LOG_FILE_PATH);
    return szBuffer;
}

std::string CLoger::getNewLogFileName()
{
    //系统时间
    SYSTEMTIME sys;
    ::GetLocalTime(&sys);
    //新文件名
    char szNewFile[MAX_PATH];
    memset(szNewFile, 0, sizeof(szNewFile));
    _snprintf_s(szNewFile, sizeof(szNewFile), "%s\\%s_%4d%02d%02d_%02d%02d%02d.log", getLogDir().c_str(),
                m_strLogFileHead.c_str(), sys.wYear, sys.wMonth, sys.wDay, sys.wHour, sys.wMinute, sys.wSecond);
    return std::string(szNewFile);
}

/// <summary>
/// 引擎相关模块注册函数
/// </summary>
/// <param name="level"></param>
/// <param name="filepath"></param>
/// <param name="func"></param>
/// <param name="line"></param>
/// <param name="pszLogLine"></param>
void EngineLogFunEntry(int level, const char* filepath, const char* func, int line, const char* pszLogLine)
{
    int nLevel = level;
    if (nLevel < LOG_LEVEL_DEBUG)
    {
        nLevel = LOG_LEVEL_DEBUG;
    }
    else if (nLevel > LOG_LEVEL_ERROR)
    {
        nLevel = LOG_LEVEL_ERROR;
    }

    std::string strLogLine = pszLogLine == NULL ? "" : pszLogLine;
    std::regex percentRegex("%");
    strLogLine = std::regex_replace(strLogLine, percentRegex, "%%");
    CLoger::Log(nLevel, filepath == NULL ? "" : filepath, func == NULL ? "" : func, line, strLogLine.c_str());
}
