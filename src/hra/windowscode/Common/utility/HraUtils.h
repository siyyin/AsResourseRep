//#define _CRT_SECURE_NO_WARNINGS
#ifndef __HRA_UTILS_H__
#define __HRA_UTILS_H__

#include <string> 
#include <vector>
#include <list>
#include <sys/types.h>
#include "comm.h"
#include <Windows.h>
#include <stdint.h>

#define ASSETSCAN_CFG_TABLE             "AssetScanCfgTable"
#define GLOBAL_CONFIG_TABLE             "GlobalConfigTable"

#define PATTERN_DIR                     "patterns\\"
#define OSSACN_PATTERN_DIR              "patterns\\OsScan\\"
#define BASELINE_PATTERN_DIR            "patterns\\BaseLine\\"
#define DOLPHIN_PATTERN_DIR             "patterns\\WPScan\\"
#define VULNPOC_PATTERN_DIR             "patterns\\VulnPoc\\"
#define ASSET_PATTERN_DIR               "patterns\\Asset\\"

#define _INET6_ADDRSTRLEN				65

#ifndef PATTERN_INFORMATION
#define PATTERN_INFORMATION             "meta_info.json"
#endif

#ifndef PATTERN_DATA_DIR
#define PATTERN_DATA_DIR "data"
#endif

//enum OS_TYPE {
//	OS_TYPE_UBUNTU,
//	OS_TYPE_REDHAT,
//	OS_TYPE_SUSE,
//	OS_TYPE_NEOKYLIN,
//	OS_TYPE_YHKYLIN,
//	OS_TYPE_UOS,
//	OS_TYPE_INVALID
//};

enum CompressionMode{
	NO_COMPRESSION,
	NEED_COMPRESSION
};

#define HRA_VERSION_LEN     128
#define HRA_STRING_MAX_LEN  256

std::string HRA_UTILITY_EXPORT UtilsGetUUID(void);
std::string HRA_UTILITY_EXPORT UtilsGetProIpcName(void);
std::string HRA_UTILITY_EXPORT UtilsGetHraIpcName(void);
int HRA_UTILITY_EXPORT UtilsGetRunTime(void);
//int HRA_UTILITY_EXPORT UtilsGetOsType(void);
std::string HRA_UTILITY_EXPORT UtilsGetOsReleaseName();

std::string HRA_UTILITY_EXPORT UtilsGetAppVersion(void);
std::string HRA_UTILITY_EXPORT UtilsGetOSscanPatternVersion(void);
std::string HRA_UTILITY_EXPORT UtilsGetBaselinePatternVersion(void);
std::string HRA_UTILITY_EXPORT UtilsGetDolphinPatternVersion(void);
std::string HRA_UTILITY_EXPORT UtilsGetVulnPocPatternVersion(void);
std::string HRA_UTILITY_EXPORT UtilsGetAssetPatternVersion(void);

std::string HRA_UTILITY_EXPORT UtilsGetOSscanPatternVersionPath(void);
std::string HRA_UTILITY_EXPORT UtilsGetKbCveOsScanPatternVerisionPath(void);
std::string HRA_UTILITY_EXPORT UtilsGetMultiOsScanPatternVersionPath(void);
std::string HRA_UTILITY_EXPORT UtilsGetBaselinePatternVersionPath(void);
std::string HRA_UTILITY_EXPORT UtilsGetDolphinPatternVersionPath(void);
std::string HRA_UTILITY_EXPORT UtilsGetVulnPocPatternVersionPath(void);
std::string HRA_UTILITY_EXPORT UtilsGetAssetPatternVersionPath(void);

std::string HRA_UTILITY_EXPORT UtilsByteToHexStr(unsigned char *pucByteArr, int lArrLen);
int HRA_UTILITY_EXPORT UtilsHexStrToByte(const char *pscInputHexStr, unsigned int ulInputHexStrLen, unsigned char *pucOutBits, unsigned int ulOutBitsLen);

std::string HRA_UTILITY_EXPORT UtilsGetWorkPath(void);

//获取pattern文件路径
std::string HRA_UTILITY_EXPORT UtilsGetPatternPath(const std::string &strPatternPath, const std::string& strPattenNameKey);

std::string HRA_UTILITY_EXPORT UtilsGetMetaInfoDir(const std::string &strPatternPath);

std::string HRA_UTILITY_EXPORT UtilsGetBaselineTypePattenName(void);
std::string HRA_UTILITY_EXPORT UtilsGetOsScanTypePattenName(void);
std::string HRA_UTILITY_EXPORT UtilsGetDolphinTypePattenName(void);
std::string HRA_UTILITY_EXPORT UtilsGetVulnPocTypePattenName(void);
std::string HRA_UTILITY_EXPORT UtilsGetAssetTypePattenName(void);

void HRA_UTILITY_EXPORT UtilsStoreOSscanPatternVersionFromFile(bool bUpdate = false);
void HRA_UTILITY_EXPORT UtilsStoreBaselinePatternVersionFromFile(bool bUpdate = false);
void HRA_UTILITY_EXPORT UtilsStoreDolphinPatternVersionFromFile(bool bUpdate = false);
void HRA_UTILITY_EXPORT UtilsStoreVulnPocPatternVersionFromFile(bool bUpdate = false);
void HRA_UTILITY_EXPORT UtilsStoreAssetPatternVersionFromFile(bool bUpdate = false);

//json文件解密
std::string HRA_UTILITY_EXPORT UtilsFileDecryption(const std::string &strFilePath);
std::string HRA_UTILITY_EXPORT UtilsDecryptDesEcb(const unsigned char* pData, size_t nSize);
//json文件加密，用完需要主动释放ppEncryptData
int HRA_UTILITY_EXPORT UtilsFileEncryption(unsigned char** ppEncryptData, uint64_t& nDataLen, const char* pszFilePath);
int HRA_UTILITY_EXPORT UtilsEncryptDesEcb(unsigned char** ppEncryptData, uint64_t& nDataLen, const char* pFileContent,
                                          uint64_t nContentLen);

std::vector<std::string> HRA_UTILITY_EXPORT UtilsStringSplit(const std::string &strData, const std::string &strDelimiter);
std::vector<std::wstring> HRA_UTILITY_EXPORT UtilsStringSplit(const std::wstring& strData,
                                                              const std::wstring& strDelimiter);

//sha256
std::string HRA_UTILITY_EXPORT UtilsGetBuffSHA256(const unsigned char* pDataBuff, size_t nSize);
std::string HRA_UTILITY_EXPORT UtilsGetFileSHA256(const std::string &strFile);

//解压
int HRA_UTILITY_EXPORT UtilsUnzip(std::string strZipFilePath);

std::string HRA_UTILITY_EXPORT UtilsFindNewestPattPack(const std::string &strPatternDir);

/// <summary>
/// 删除目录下老的pattern包
/// </summary>
/// <param name="strPatternDir"></param>
/// <returns></returns>
int HRA_UTILITY_EXPORT UtilsRemoveOldPattPack(const std::string& strPatternDir);

std::string HRA_UTILITY_EXPORT UtilsGetTimestamp(void);
std::string HRA_UTILITY_EXPORT UtilsGetMicroTimestamp(void);
std::string HRA_UTILITY_EXPORT UtilsGetNanoTimestamp(void);
std::string HRA_UTILITY_EXPORT UtilsGetLocalTime(void);


//std::string HRA_UTILITY_EXPORT UtilsGetServerIp(void);

//int HRA_UTILITY_EXPORT UtilsGetServerAddr(char(*arrIP)[_INET6_ADDRSTRLEN], char(*arrPort)[6], const int iMax = 2);

void HRA_UTILITY_EXPORT UtilsPasswdFuzz(std::string& strPasswd);

bool HRA_UTILITY_EXPORT UtilsRemoveDirectory(const wchar_t* pszDirName);
bool HRA_UTILITY_EXPORT UtilsCopyDirFiles(const wchar_t* pszSrcDir, const wchar_t* pszDesDir);
bool HRA_UTILITY_EXPORT IsDirExist(const wchar_t* pszDirectory);
bool HRA_UTILITY_EXPORT UtilsIsFileExist(const wchar_t* pszFilePath);
std::wstring HRA_UTILITY_EXPORT UtilsAppendFilePath(std::wstring path1, const WCHAR* path2);
void HRA_UTILITY_EXPORT UtilsGetSubFileInDir(std::wstring dir, std::list<std::wstring>& subFiles);

/// <summary>
/// 去除首尾字符串
/// </summary>
/// <param name="strString"></param>
/// <param name="pszTrim"></param>
/// <returns></returns>
HRA_UTILITY_EXPORT std::string& UtilsLTrim(std::string& strString, const char* pszTrim = NULL);
HRA_UTILITY_EXPORT std::string& UtilsRTrim(std::string& strString, const char* pszTrim = NULL);
HRA_UTILITY_EXPORT std::string& UtilsTrim(std::string& strString, const char* pszTrim = NULL);

HRA_UTILITY_EXPORT std::string& UtilsToUpper(std::string& strString);
HRA_UTILITY_EXPORT std::string& UtilsToLower(std::string& strString);

bool HRA_UTILITY_EXPORT UtilsGetParam(std::string& strValue, const std::string& strKey, const std::string& strCmd);

/// <summary>
/// 获取ProgramData系统路径
/// </summary>
/// <returns></returns>
int HRA_UTILITY_EXPORT UtilsGetProgramDataDir(char* pDirBuff, size_t nBuffSize);

/// <summary>
/// 判断并创建目录，可创建多级目录
/// </summary>
/// <param name="strDir"></param>
/// <returns></returns>
int HRA_UTILITY_EXPORT UtilsCheckCreateDir(const std::string& strDir);

/// <summary>
/// 获取INI文件的配置值
/// </summary>
/// <param name="strValue"></param>
/// <param name="strFilePath"></param>
/// <param name="strSection"></param>
/// <param name="strKey"></param>
/// <returns></returns>
std::string HRA_UTILITY_EXPORT UtilsGetIniValue(const std::string& strFilePath, const std::string& strSection,
                                                const std::string& strKey);

bool HRA_UTILITY_EXPORT UtilsMatchRegex(const char* rx, const char* pszContext);

/// <summary>
/// 注册表root key转string
/// </summary>
/// <param name="hRoot"></param>
/// <returns></returns>
HRA_UTILITY_EXPORT std::wstring GetRegRootKeyString(HKEY hRoot);

// 函数声明
std::string HRA_UTILITY_EXPORT UtilsUnicodeToString(const std::wstring& src, unsigned int iCodePage = CP_UTF8);
std::string HRA_UTILITY_EXPORT UtilsUnicodeToString(const wchar_t* src, unsigned int iCodePage = CP_UTF8);
std::wstring HRA_UTILITY_EXPORT UtilsStringToUnicode(const std::string& src, unsigned int iCodePage = CP_UTF8);
std::wstring HRA_UTILITY_EXPORT UtilsStringToUnicode(const char* src, unsigned int iCodePage = CP_UTF8);
std::string HRA_UTILITY_EXPORT UtilsAiiscToUtf8(const char* strAnsiA);
std::string HRA_UTILITY_EXPORT UtilsUtf8ToAiisc(const char* strUtf8A);

/// <summary>
/// 获得文件属性
/// </summary>
struct HRA_UTILITY_EXPORT UtilsFileProperty
{
    std::wstring strFilePath;
    std::wstring strFileVersion;
    std::wstring strProductName;
    std::wstring strProductVersion;
    std::wstring strCompanyName;
    std::wstring strFileDescription;

    void clear()
    {
        strFilePath.clear();
        strFileVersion.clear();
        strProductName.clear();
        strProductVersion.clear();
        strCompanyName.clear();
        strFileDescription.clear();
    }

    UtilsFileProperty()
    {
        clear();
    }
};
/// <summary>
/// 获得文件属性
/// 返回具体的key的属性
/// </summary>
/// <param name="strFilePath"></param>
/// <returns></returns>
HRA_UTILITY_EXPORT int UtilsGetFileProperty(UtilsFileProperty& stProperty, const std::wstring& strFilePath);
HRA_UTILITY_EXPORT std::wstring UtilsGetFileProperty(const std::wstring& strPropertyKey,
                                                    const std::wstring& strFilePath);
HRA_UTILITY_EXPORT std::wstring UtilsGetFilePropertySub(LPCVOID pBuff, LPCWSTR pKeyName, DWORD dwLangCodePage);
//将字符串中的趋势相关信息替换成亚信安全
HRA_UTILITY_EXPORT std::wstring& UtilsReplaceTrendInfo(std::wstring& strString);

/// <summary>
/// 字符替换
/// </summary>
/// <param name="strString"></param>
/// <param name="strOld"></param>
/// <param name="strNew"></param>
/// <param name="bCaseSensitive"></param>
/// <returns></returns>
HRA_UTILITY_EXPORT std::wstring& UtilsReplaceString(std::wstring& strString, const std::wstring& strOld,
                                                    const std::wstring& strNew, bool bCaseSensitive = true);


HRA_UTILITY_EXPORT std::string UtilsReplaceAll(std::string srcStr, const std::string& oldStr, const std::string& newStr);

HRA_UTILITY_EXPORT std::string UtilsGetRegDataPath(const std::string& strSrvName);

// 通过匿名管道执行命令, （uStdType=1 管道写入端绑定标准输出), (uStdType=2 管道写入端绑定标准错误)
HRA_UTILITY_EXPORT bool ExecuteCommand(std::string& strResult, unsigned int uStdType, const char* szFormat, ...);

// 刷新当前进程的 environment block; 会增加或更新环境变量,不会删除 
HRA_UTILITY_EXPORT bool RefreshProcessEnvBlock();

// 拷贝指定文件到指定路径下
HRA_UTILITY_EXPORT std::string UtilsCopyFileToDir(const std::string& strFilePath, const std::string& strDirPath);

// 拼接path1+path2
HRA_UTILITY_EXPORT std::string UtilsPathAppend(const std::string& path1, const char* path2);

// 从strDir目录下获取包含strKey的第一个文件路径
HRA_UTILITY_EXPORT std::string UtilsGetFileFromDir(const std::string& strDir, const std::string& strKey, int maxLevel = 1);

// 从strDir目录下获取所有包含strkey的文件路径
HRA_UTILITY_EXPORT void UtilsGetAllMatchFileInDir(const std::string& strDir, const std::string& strKey,
                                                  std::vector<std::string>& files, int maxLevel = 1);

// 从给定的Zip包中获取指定的strTarget文件
HRA_UTILITY_EXPORT int UtilsUnzipWithTarget(const std::string& strZipFilePath, const std::string& strTarget);

HRA_UTILITY_EXPORT std::string UtilsGetVulnZipPathFromZips(const std::vector<std::string>& vecFiles,
                                                           const std::string& strZipTemp);

// 给定一个Key值,查找所有包含该Key值的进程PID;  
HRA_UTILITY_EXPORT std::vector<DWORD> GetPidByRegexName(const wchar_t* wszKey);

// 从meta_info.json中获取su version字段值并转成点号分割模式
HRA_UTILITY_EXPORT bool ReadSUVersionFromMetaInfo(const std::string& strPatternDir, std::string& strDotStyleVersion);

#endif /* __HRA_UTILS_H__ */