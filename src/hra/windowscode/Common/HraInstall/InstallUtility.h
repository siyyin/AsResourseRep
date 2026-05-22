#pragma once
#include <Windows.h>
#include <string>
#include "HraInstallDef.h"
#include "json/json.h"

#ifdef __cplusplus
extern "C"
{
#endif

/// <summary>
/// 删除目录，包括目录下的所有文件
/// </summary>
/// <param name="DirName"></param>
/// <returns></returns>
HRA_INSTALL_API DWORD HraInst_RemoveDirectory(const wchar_t* pszDir);

/// <summary>
/// 删除目录，包括目录下的所有文件，包含例外，例外的不删除，例外文件通过文件名正则匹配
/// </summary>
/// <param name="bHasException"></param>
/// <param name="szExceptionRegex"></param>
/// <param name="pszDir"></param>
/// <returns></returns>
HRA_INSTALL_API DWORD HraInst_RemoveDirectory_WithException(BOOL& bSubHasException, const wchar_t* szExceptionRegex,
                                                            const wchar_t* pszDir);

/// <summary>
/// 拷贝文件夹下的所有文件，目标目录不存在会自动创建
/// </summary>
/// <param name="pszSrcDir"></param>
/// <param name="pszDesDir"></param>
/// <returns></returns>
HRA_INSTALL_API DWORD HraInst_CopyDirectory(const wchar_t* pszSrcDir, const wchar_t* pszDesDir);

/// <summary>
/// 判断文件夹是否存在
/// </summary>
/// <param name="pszDirectory"></param>
/// <returns></returns>
HRA_INSTALL_API BOOL HraInst_IsDirExists(const wchar_t* pszDirectory);

/// <summary>
/// 去除首字符串
/// </summary>
/// <param name="strString"></param>
/// <param name="pszTrim"></param>
/// <returns></returns>
HRA_INSTALL_API DWORD HraInst_LTrim(wchar_t* pszString, size_t nSizeCount, const wchar_t* pszTrim = NULL);

/// <summary>
/// 去除尾字符串
/// </summary>
/// <param name="strString"></param>
/// <param name="pszTrim"></param>
/// <returns></returns>
HRA_INSTALL_API DWORD HraInst_RTrim(wchar_t* pszString, size_t nSizeCount, const wchar_t* pszTrim = NULL);

/// <summary>
/// 去除首尾字符串
/// </summary>
/// <param name="pszString"></param>
/// <param name="pszTrim"></param>
/// <returns></returns>
HRA_INSTALL_API DWORD HraInst_Trim(wchar_t* pszString, size_t nSizeCount, const wchar_t* pszTrim = NULL);

/// <summary>
/// 获取programData目录路径
/// </summary>
/// <param name="pszDirBuff"></param>
/// <param name="nBuffSize"></param>
/// <returns></returns>
HRA_INSTALL_API DWORD HraInst_GetProgramDataDir(wchar_t* pszDirBuff, size_t nBuffSize);

/// <summary>
/// 权限判断
/// </summary>
/// <param name="_bIsTokenMembership"></param>
/// <param name="_enumWellKnownSidType"></param>
/// <param name="pWin32ErrorCode"></param>
/// <returns></returns>
HRA_INSTALL_API DWORD HraInst_CheckTokenMembership(BOOL& IsTokenMembership,
                                                   const WELL_KNOWN_SID_TYPE emWellKnownSidType);

/// <summary>
/// 判断是否admin权限
/// </summary>
/// <param name="pWin32ErrorCode"></param>
/// <returns></returns>
HRA_INSTALL_API BOOL HraInst_IsAdmin();

/// <summary>
/// Unicode转String
/// </summary>
/// <param name="src"></param>
/// <param name="iCodePage"></param>
/// <returns></returns>
HRA_INSTALL_API DWORD HraInst_UnicodeToString(char* pszDest, size_t nSizeCount, const wchar_t* src,
                                              unsigned int iCodePage = CP_UTF8);

/// <summary>
/// String转Unicode
/// </summary>
/// <param name="src"></param>
/// <param name="iCodePage"></param>
/// <returns></returns>
HRA_INSTALL_API DWORD HraInst_StringToUnicode(wchar_t* pszDest, size_t nSizeCount, const char* src,
                                              unsigned int iCodePage = CP_UTF8);

/// <summary>
/// 解压zip包
/// </summary>
/// <param name="pszZipPath"></param>
/// <param name="pszUnzipPath"></param>
/// <param name="pWin32ErrorCode"></param>
/// <returns></returns>
HRA_INSTALL_API DWORD HraInst_Unzip(const wchar_t* pszZipPath, const wchar_t* pszUnzipPath);

/// <summary>
/// 获得字符串中的指定参数
/// </summary>
/// <param name="pszValue"></param>
/// <param name="nSizeCount"></param>
/// <param name="strKey"></param>
/// <param name="strCmd"></param>
/// <returns></returns>
HRA_INSTALL_API DWORD HraInst_GetParam(wchar_t* pszValue, size_t nSizeCount, const wchar_t* pszKey, const wchar_t* pszCmd);

/// <summary>
/// 从指定的注册表路径获取数据
/// </summary>
/// <param name="pszValue">结果</param>
/// <param name="pszSubKey">注册表项</param>
/// <param name="pszValueName">键名称</param>
/// <param name="hRoot">注册表Root</param>
/// <returns></returns>
HRA_INSTALL_API DWORD HraInst_GetRegValue(wchar_t* pszValue, const wchar_t* pszSubKey, const wchar_t* pszValueName,
                                          HKEY hRoot);

/// <summary>
/// json数据转成字符串
/// </summary>
/// <returns></returns>
HRA_INSTALL_API DWORD HraInst_JsontoWString(wchar_t* pwszValue, size_t nSizeCount,const Json::Value& jsObj);

/// <summary>
/// 字符串转成json
/// </summary>
/// <returns></returns>
HRA_INSTALL_API DWORD HraInst_WStringtoJson(Json::Value& jsObj, const wchar_t* wszValue);



#ifdef __cplusplus
}
#endif