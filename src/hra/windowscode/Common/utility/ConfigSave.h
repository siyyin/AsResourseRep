#ifndef __CONFIGSAVE_H__
#define __CONFIGSAVE_H__
//#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <mutex>
#include <sys/stat.h>
#include "Logger.h"
#include "sqlite3/sqlite3.h"
#include "comm.h"

using namespace std;

#ifndef FIELDSIZE
#define FIELDSIZE 128
#endif
#ifndef CONFIGSQLSIZE
#define CONFIGSQLSIZE (FIELDSIZE*5)
#endif

#define DBPATH ".\\config.db" 
#ifndef CONFIGDB
#define CONFIGDB "configdb"
#endif // !CONFIGDB
#ifndef ASSETDB
#define ASSETDB "assetdb"
#endif // !ASSETDB



class HRA_UTILITY_EXPORT CConfigSave
{
private:
	sqlite3 *m_psqilteDbHandle;
	std::string m_strDatabasePath;
    std::mutex m_mutex;
    int InitDBTable(const char* pcTableName);

public:
	CConfigSave();
	~CConfigSave();
    std::string ConfigSaveGetValue(const string& strTableName, const string& strKey);
    std::string ConfigSaveGetValue(const char* pscTableName, const char* pscKey);
	int ConfigSaveGetIntegerValue(const string &strTableName, const string &strKey);
	int ConfigSaveGetIntegerValue(const char *pscTableName, const char *pscKey);
    int ConfigSaveSetValue(const std::string& strTableName, const std::string& strKey, const std::string& strValue);
    int ConfigSaveSetValue(const char* strTableName, const char* strKey, const char* strValue);
	int ConfigSaveSetIntegerValue(const string& strTableName, const string& strKey, int lValue);
    int ConfigSaveInit(const char* pscDatabasePath);
    int CheckTableStructure(const char* pscTableName);
    int CleanUpWAL();
};

HRA_UTILITY_EXPORT extern CConfigSave g_ConfigSave;
HRA_UTILITY_EXPORT extern CConfigSave g_AssetDataDB;

int KeyIsExist(void *pOutNum, int argc, char **argv, char **columnName);
int GetValue(void* pOutData, int argc, char** argv, char** columnName);

#endif