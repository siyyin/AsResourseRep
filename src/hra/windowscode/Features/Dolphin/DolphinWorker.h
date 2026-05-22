#pragma once
#include "json/json.h"
#include <set>
#include <map>
#include <string>

typedef enum _WPAPP_TYPE
{
    WPAPP_TYPE_SYSTEM = 1,
    WPAPP_TYPE_MYSQL = 2,
    WPAPP_TYPE_PGSQL = 3,
    WPAPP_TYPE_UNKNOW = 4
}WPAPP_TYPE;

typedef enum _PASSWD_TYPE
{
    PASSWD_TYPE_PLAIN = 0,
    PASSWD_TYPE_FUZZ = 1,
    PASSWD_TYPE_UNKNOW = 2
}PASSWD_TYPE;

/// <summary>
/// 弱口令分类
/// </summary>
typedef enum _PASSWD_CLASS
{
    PASSWD_CLASS_EMPTY = 1,//空口零
    PASSWD_CLASS_EQUAL_NAME = 2,//用户名密码相等
    PASSWD_CLASS_COMMON = 3//常见弱口令
} PASSWD_CLASS;

struct DolphinCategroy
{
    int iType;
    std::set<std::string> setUser;
    std::set<std::string> setOnlinePasswd;
    std::set<std::string> setPasswdFile;
    std::set<int> setPort;

    void clear()
    {
        iType = (int)WPAPP_TYPE_UNKNOW;
        setUser.clear();
        setOnlinePasswd.clear();
        setPasswdFile.clear();
        setPort.clear();
    }

    DolphinCategroy()
    {
        clear();
    }
};

struct DolphinWorkEntry
{
    std::string task_id;        //任务id，结束后在结果中返回给到manager
    //int iScanType;//0.预设任务 1.手动扫描 -1.初始化，不上报
    int iPasswdType;//密码处理类型，0：明文，1模糊化
    std::map<int, DolphinCategroy> mapScanCategroy;

    DolphinWorkEntry()
    {
        clear();
    }

    void clear()
    {
        task_id.clear();
        //iScanType = -1;
        iPasswdType = 1;
        for (std::map<int, DolphinCategroy>::iterator it = mapScanCategroy.begin();
             mapScanCategroy.end() != it; ++it)
        {
            it->second.clear();
        }
        mapScanCategroy.clear();
    }
};

struct DolphinResult
{
    int iAppType;
    std::string strUserName;
    std::string strPasswd;
    int iPasswdClass;
    int iPort;

    void clear()
    {
        iAppType = (int)WPAPP_TYPE_UNKNOW;
        strUserName.clear();
        strPasswd.clear();
        iPort = -1;
        iPasswdClass = (int)PASSWD_CLASS_COMMON;
    }

    DolphinResult()
    {
        clear();
    }
};

void DolphinSetModuleWorkStatus(int iStat);
int DolphinGetModuleWorkStatus();

int DolphinPreparePattern();
int DolphinCfgParse(DolphinWorkEntry& stEntry, const Json::Value& jsContect);
int DolphinCfgApply(const DolphinWorkEntry& stEntry, const Json::Value& jsContect);

int DolphinEngineCopyPatternFromDsa(std::string& strTmpDir, const std::string& strPatternFile);
int DolphinEnginePatternUpdate(const std::string& strPatternFile, const std::string& strTempDir);

int DolphinEngineInit(const DolphinWorkEntry& stEntry);
int DolphinEngineDoScan(const DolphinWorkEntry& stEntry);
int DolphinEngineDestory(const DolphinWorkEntry& stEntry);
int DolphinEngineReport(const DolphinWorkEntry& stEntry, int iRet, const std::string& strResult);

int DolphinEngineDoScanSystem(const DolphinWorkEntry& stEntry);
int DolphinEngineGenerateResultString(const DolphinWorkEntry& stEntry, std::string& strResult);

//bool IsInHrmUserList(const DolphinWorkEntry& stEntry, int iAppType, const std::string& strUserName);