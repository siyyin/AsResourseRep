#include "LibConfigSave.h"
#include <DbgHelp.h>
#include <string>


#ifndef FIELDSIZE
#define FIELDSIZE 128
#endif
#ifndef CONFIGSQLSIZE
#define CONFIGSQLSIZE (FIELDSIZE * 5)
#endif

//#pragma comment(lib, "sqlite3.lib")
// key、value不检查，从初始版本就一直有，只检查后续添加的
const char* table_columns[]         = {"key", "value", "update_time"};
const char* table_column_types[]    = {"varchar(128)", "text", "TimeStamp"};
const char* table_column_property[] = {"", "", ""};

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	查询数据表中是否有key值，为sqlite3_exec()的回调函数 </summary>
///
/// <remarks>	2021/12/17. </remarks>
///
/// <param name="pOutNum">   	[in,out] If non-null, the out number. </param>
/// <param name="argc">		 	The argc. </param>
/// <param name="argv">		 	[in,out] If non-null, the argv. </param>
/// <param name="columnName">	[in,out] If non-null, name of the column. </param>
///
/// <returns>	0 -- 成功</returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
int KeyIsExist(void* pOutNum, int argc, char** argv, char** columnName)
{
    int* plNum = (int*)pOutNum;
    *plNum     = atoi(argv[0]);

    return ERROR_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	ConfigSaveGetValue() 中 sqlite3_exec()的回调函数. </summary>
///
/// <remarks>	2021/12/17. </remarks>
///
/// <param name="pOutData">  	[in,out] If non-null, information describing the out. </param>
/// <param name="argc">		 	The argc. </param>
/// <param name="argv">		 	[in,out] If non-null, the argv. </param>
/// <param name="columnName">	[in,out] If non-null, name of the column. </param>
///
/// <returns>	0 -- 成功 </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
int GetValue(void* pOutData, int argc, char** argv, char** columnName)
{
    unsigned long ulSize = strlen(argv[0]);
    char* pszBuffer      = (char*)malloc(ulSize + 1);
    strncpy_s(pszBuffer, ulSize + 1, argv[0], ulSize);
    char** pPTR = (char**)pOutData;
    *pPTR       = pszBuffer;

    return ERROR_SUCCESS;
}

CLibConfigSave::CLibConfigSave()
    : m_strDatabasePath(/*DBPATH*/ "")
    , m_psqilteDbHandle(NULL)
{
}

CLibConfigSave::~CLibConfigSave()
{
    if (m_psqilteDbHandle != NULL)
    {
        CleanUpWAL();
        sqlite3_close(m_psqilteDbHandle);
        m_psqilteDbHandle = NULL;
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	判断pcTableName是否存在，如果保存在则创建. </summary>
///
/// <remarks>	, 2021/12/17. </remarks>
///
/// <param name="pcTableName">	数据库表名. </param>
///
/// <returns>	0 -- 成功 , 1 -- 失败. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
int CLibConfigSave::InitDBTable(const char* pcTableName)
{
    char* errmsg            = NULL;
    char sql[CONFIGSQLSIZE] = {0};

    _snprintf_s(sql, CONFIGSQLSIZE,
                " CREATE TABLE IF NOT EXISTS %s (key varchar(%d) primary key, value text, update_time TimeStamp "
                "default(datetime('now', 'localtime'))); ",
                pcTableName, FIELDSIZE);
    int lRet = sqlite3_exec(m_psqilteDbHandle, sql, NULL, NULL, &errmsg);
    if (lRet != SQLITE_OK)
    {
        //LOG_ERROR("Failed to execute statement \"%s\":%s", sql, errmsg);
        sqlite3_free(errmsg);
        return ERROR_INVALID_FUNCTION;
    }

    sqlite3_free(errmsg);
    return ERROR_SUCCESS;
}

/// <summary>
/// 检查表结构是否符合要求，缺字段则加字段
/// </summary>
/// <param name="pscTableName"></param>
/// <returns></returns>
int CLibConfigSave::CheckTableStructure(const char* pscTableName)
{
    int nRet                  = ERROR_INVALID_FUNCTION;
    char szSql[CONFIGSQLSIZE] = {0};
    sqlite3_stmt* stmt        = NULL;
    int nColumnCount          = sizeof(table_columns) / sizeof(table_columns[0]);
    int* pKeyStat             = NULL;
    int rc                    = SQLITE_OK;
    bool bTableExists         = false;

    if (pscTableName == NULL || strlen(pscTableName) <= 0)
    {
        //LOG_ERROR("The parameter cannot be empty and stringlength has to be greater than 0");
        goto _exit;
    }

    if (!m_psqilteDbHandle)
    {
        if (ConfigSaveInit(m_strDatabasePath.c_str()) != ERROR_SUCCESS)
        {
            //LOG_ERROR("ConfigSaveInit error! %s", m_strDatabasePath.c_str());
            goto _exit;
        }
    }

    //判断表是否存在
    _snprintf_s(szSql, CONFIGSQLSIZE, "SELECT name FROM sqlite_master WHERE type='table' AND name='%s';", pscTableName);
    rc = sqlite3_prepare_v2(m_psqilteDbHandle, szSql, -1, &stmt, 0);
    if (rc != SQLITE_OK)
    {
        //LOG_ERROR("Failed to prepare statement! %d, %s", rc, szSql);
        goto _exit;
    }
    //LOG_INFO("SQL:%s succeed!", szSql);
    while (sqlite3_step(stmt) == SQLITE_ROW)
    {
        if (stricmp((const char*)sqlite3_column_text(stmt, 0), pscTableName) == 0)
        {
            bTableExists = true;
            //LOG_INFO("Table:%s exists!", pscTableName);
            break;
        }
    }
    if (!bTableExists)
    {
        nRet = ERROR_SUCCESS;
        //LOG_INFO("Table:%s not exists!", pscTableName);
        goto _exit;
    }

    //获得表信息
    if (stmt)
    {
        sqlite3_finalize(stmt);
        stmt = NULL;
    }
    _snprintf_s(szSql, CONFIGSQLSIZE, "PRAGMA table_info(%s); ", pscTableName);
    rc = sqlite3_prepare_v2(m_psqilteDbHandle, szSql, -1, &stmt, 0);
    if (rc != SQLITE_OK)
    {
        //LOG_ERROR("Failed to prepare statement! %d, %s", rc, szSql);
        goto _exit;
    }

    pKeyStat = (int*)malloc(nColumnCount * sizeof(int));
    if (!pKeyStat)
    {
        //LOG_ERROR("malloc error!");
        goto _exit;
    }
    memset(pKeyStat, 0, nColumnCount * sizeof(int));
    //判断列是否存在
    while (sqlite3_step(stmt) == SQLITE_ROW)
    {
        //LOG_INFO("Check column:%s!", (const char*)sqlite3_column_text(stmt, 1));
        for (int i = 0; i < nColumnCount; ++i)
        {
            // 只判断列名就行
            if (stricmp((const char*)sqlite3_column_text(stmt, 1), table_columns[i]) == 0)
            {
                pKeyStat[i] = TRUE;
                //LOG_INFO("Column:%s exists!", table_columns[i]);
            }
        }
    }

    //创建不存在的列名
    for (int i = 0; i < nColumnCount; ++i)
    {
        if (pKeyStat[i] == TRUE)
        {
            continue;
        }

        if (stmt)
        {
            sqlite3_finalize(stmt);
            stmt = NULL;
        }
        _snprintf_s(szSql, CONFIGSQLSIZE, "ALTER TABLE %s ADD COLUMN %s %s %s; ", pscTableName, table_columns[i],
                    table_column_types[i], table_column_property[i]);
        rc = sqlite3_prepare_v2(m_psqilteDbHandle, szSql, -1, &stmt, 0);
        if (rc != SQLITE_OK)
        {
            //LOG_ERROR("Failed to prepare statement! %d, %s", rc, szSql);
            goto _exit;
        }
        rc = sqlite3_step(stmt);
        if (rc != SQLITE_DONE)
        {
            //LOG_ERROR("Failed to prepare statement! %d, %s", rc, szSql);
            goto _exit;
        }
        //LOG_INFO("SQL:%s succeed!", szSql);
    }
    nRet = ERROR_SUCCESS;

_exit:
    if (stmt)
    {
        sqlite3_finalize(stmt);
        stmt = NULL;
    }
    if (pKeyStat)
    {
        free(pKeyStat);
        pKeyStat = NULL;
    }
    return nRet;
}

/// <summary>
/// 定期清理WAL文件,防止WAL文件过大
/// </summary>
/// <returns></returns>
int CLibConfigSave::CleanUpWAL()
{
    if (!m_psqilteDbHandle)
    {
        return ERROR_INVALID_HANDLE;
    }

    char* pszErrMsg = NULL;
    if (sqlite3_exec(m_psqilteDbHandle, "PRAGMA wal_checkpoint(TRUNCATE);", NULL, NULL, &pszErrMsg) != SQLITE_OK)
    {
        sqlite3_free(pszErrMsg);
        pszErrMsg = NULL;
        return ERROR_INVALID_FUNCTION;
    }

    sqlite3_free(pszErrMsg);
    pszErrMsg = NULL;
    return ERROR_SUCCESS;
}


////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	根据key查询表pcTableName中的value值. </summary>
///
/// <remarks>	, 2021/12/17. </remarks>
///
/// <param name="strTableName">	[in] Name of the table. </param>
/// <param name="strKey">	   	[in] The key. </param>
///
/// <returns>	A std::string. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
std::string CLibConfigSave::ConfigSaveGetValue(const string& strTableName, const string& strKey)
{
    char* errmsg                  = NULL;
    char sql[CONFIGSQLSIZE]       = {0};
    char* pszValue = NULL;

    if (strTableName.empty() || strKey.empty())
    {
        //LOG_ERROR("The parameter cannot be empty and bufflen has to be greater than 0 \n");
        return "";
    }

    if (!m_psqilteDbHandle)
    {
        if (ConfigSaveInit(m_strDatabasePath.c_str()) != ERROR_SUCCESS)
        {
            //LOG_ERROR("ConfigSaveInit error! %s", m_strDatabasePath.c_str());
            return "";
        }
    }

    _snprintf_s(sql, CONFIGSQLSIZE, "select value from %s where key = \"%s\" ", strTableName.c_str(), strKey.c_str());
    int rc = sqlite3_exec(m_psqilteDbHandle, sql, GetValue, (void*)&pszValue, &errmsg);
    if (rc != SQLITE_OK)
    {
        //LOG_WARN("Failed to execute statement \"%s\": %s", sql, errmsg);
        sqlite3_free(errmsg);
        return "";
    }

    std::string strBackValue;
    // pszValue存在,数据库中有值
    if (pszValue)
    {
        strBackValue.assign(pszValue, strlen(pszValue));
        free(pszValue);
        pszValue = NULL;
    }
    sqlite3_free(errmsg);
    //LOG_DEBUG("Query (%s=%s) from the table(%s) success", strKey.c_str(), strBackValue.c_str(), strTableName.c_str());

    return strBackValue;
}

std::string CLibConfigSave::ConfigSaveGetValue(const char* pscTableName, const char* pscKey)
{
    std::string strTableName = pscTableName;
    std::string strKey       = pscKey;

    return ConfigSaveGetValue(strTableName, strKey);
}

int CLibConfigSave::ConfigSaveGetIntegerValue(const string& strTableName, const string& strKey)
{
    return atoi(ConfigSaveGetValue(strTableName, strKey).c_str());
}

int CLibConfigSave::ConfigSaveGetIntegerValue(const char* pscTableName, const char* pscKey)
{
    std::string strTableName = pscTableName;
    std::string strKey       = pscKey;

    return ConfigSaveGetIntegerValue(strTableName, strKey);
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	将配置文件中的key与value保存到数据库表pcTableName中,如果pcTableName不存在则创建. </summary>
///
/// <remarks>	, 2021/12/18. </remarks>
///
/// <param name="strTableName">	Name of the table. </param>
/// <param name="strKey">	   	The key. </param>
/// <param name="strValue">	   	The value. </param>
///
/// <returns>	A int. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
int CLibConfigSave::ConfigSaveSetValue(const std::string& strTableName, const std::string& strKey,
                                    const std::string& strValue)
{
    char* errmsg            = NULL;
    char* sqlStr            = NULL;
    int lSqilte3Ret         = SQLITE_OK;
    int lRet                = ERROR_SUCCESS;

    if (strTableName.empty() || strKey.empty())
    {
        //LOG_ERROR("The parameter cannot be empty.");
        return ERROR_INVALID_PARAMETER;
    }

    // 现在不限制value值,在资产中,安装大量的Java软件(webloigc,jboss,jetty等,基本全覆盖)
    // 经过测试,扫描出近2000+的jar包,大小将近1MB,已经无法使用栈来存储;
    if (FIELDSIZE <= strKey.size())
    {
        //LOG_ERROR("KEY too long");
        return ERROR_OUTOFMEMORY;
    }

    m_mutex.lock(); // 加锁

    if (!m_psqilteDbHandle)
    {
        if (ConfigSaveInit(m_strDatabasePath.c_str()) != ERROR_SUCCESS)
        {
            m_mutex.unlock(); // 解锁
            //LOG_ERROR("ConfigSaveInit error! %s", m_strDatabasePath.c_str());
            return ERROR_INVALID_FUNCTION;
        }
    }

    // Check whether the table exists. If it does not exist, create the table
    int iRet = ERROR_INVALID_FUNCTION;
    iRet = InitDBTable(strTableName.c_str());
    if (ERROR_SUCCESS != iRet)
    {
        //LOG_ERROR("Check whether the list has failed;");
        lRet = ERROR_INVALID_FUNCTION;
        goto err;
    }

    // 插入数据改成事务;
    const char* szTransaction = "begin transaction;";
    lSqilte3Ret               = sqlite3_exec(m_psqilteDbHandle, szTransaction, NULL, NULL, &errmsg);
    if (lSqilte3Ret != SQLITE_OK)
    {
        lRet = ERROR_INVALID_FUNCTION;
        goto err;
    }

    sqlStr = sqlite3_mprintf(
        "replace into %s (key, value, update_time) values('%s', '%q', datetime('now', 'localtime'))",
        strTableName.c_str(), strKey.c_str(), strValue.c_str());
    lSqilte3Ret = sqlite3_exec(m_psqilteDbHandle, sqlStr, NULL, NULL, &errmsg);
    if (lSqilte3Ret != SQLITE_OK)
    {
        lRet = ERROR_INVALID_FUNCTION;
        goto err;
    }

err:
    if (ERROR_SUCCESS != lRet)
    {
        //LOG_ERROR("Failed to execute statement %s: %s, errorCode:%d.", sqlStr, errmsg, lSqilte3Ret);
        const char* szTransaction = "rollback transaction;";
        lSqilte3Ret               = sqlite3_exec(m_psqilteDbHandle, szTransaction, NULL, NULL, &errmsg);
        if (lSqilte3Ret != SQLITE_OK)
        {
            lRet = ERROR_INVALID_FUNCTION;
        }
    }
    else
    {
        //LOG_DEBUG("save config (key=%s, value=%s) to database (table=%s) success;", strKey.c_str(), strValue.c_str(), strTableName.c_str());
        const char* szTransaction = "commit transaction;";
        lSqilte3Ret               = sqlite3_exec(m_psqilteDbHandle, szTransaction, NULL, NULL, &errmsg);
        if (lSqilte3Ret != SQLITE_OK)
        {
            lRet = ERROR_INVALID_FUNCTION;
        }
    }

    m_mutex.unlock(); // 解锁

    if (sqlStr != NULL)
    {
        sqlite3_free(sqlStr);
        sqlStr = NULL;
    }

    if (errmsg != NULL)
    {
        sqlite3_free(errmsg);
        errmsg = NULL;
    }

    return lRet;
}

int CLibConfigSave::ConfigSaveSetIntegerValue(const string& strTableName, const string& strKey, int lValue)
{
    char astring[25];

    _snprintf_s(astring, 25, "%d", lValue);
    string AAstring = astring;
    return ConfigSaveSetValue(strTableName, strKey, AAstring);
}

int CLibConfigSave::ConfigSaveSetValue(const char* pscTableName, const char* pscKey, const char* pscValue)
{
    std::string strTableName = pscTableName;
    std::string strKey       = pscKey;
    std::string strValue     = pscValue;

    return ConfigSaveSetValue(strTableName, strKey, strValue);
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	打开数据库. </summary>
///
/// <remarks>	, 2021/12/18. </remarks>
///
/// <param name="pscDatabasePath">	Full pathname of the psc database file. </param>
///
/// <returns>	A int. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
int CLibConfigSave::ConfigSaveInit(const char* pscDatabasePath)
{
    if (pscDatabasePath)
    {
        m_strDatabasePath = pscDatabasePath;
    }

    if (m_psqilteDbHandle)
    {
        sqlite3_close(m_psqilteDbHandle);
        m_psqilteDbHandle = NULL;
    }

    // 如果该目录不存在则创建
    int lIndex = m_strDatabasePath.rfind('\\');
    if (lIndex != std::string::npos)
    {
        std::string strDir = m_strDatabasePath.substr(0, lIndex);
        struct stat stFileStat;
        if (stat(strDir.c_str(), &stFileStat) < 0 || !(S_IFDIR & stFileStat.st_mode))
        {
            strDir.append("\\");
            if (!MakeSureDirectoryPathExists(strDir.c_str()))
            {
                //LOG_ERROR("MakeSureDirectory:%s error!, Code:%lu", strDir.c_str(), GetLastError());
                return ERROR_INVALID_FUNCTION;
            }
        }
    }

    if (sqlite3_open(m_strDatabasePath.c_str(), &m_psqilteDbHandle) != SQLITE_OK)
    {
        //LOG_ERROR("sqlite3 open err,%s: %s\n", m_strDatabasePath.c_str(), sqlite3_errmsg(m_psqilteDbHandle));
        return ERROR_OPEN_FAILED;
    }

    char* pszErrMsg = NULL;
    if (sqlite3_exec(m_psqilteDbHandle, "PRAGMA journal_mode=WAL;", NULL, NULL, &pszErrMsg) != SQLITE_OK)
    {
        sqlite3_free(pszErrMsg);
        pszErrMsg = NULL;
        return ERROR_INVALID_FUNCTION;
    }

    sqlite3_free(pszErrMsg);
    pszErrMsg = NULL;
    return ERROR_SUCCESS;
}


//CLibConfigSave g_ConfigSave;
//CLibConfigSave g_AssetDataDB;