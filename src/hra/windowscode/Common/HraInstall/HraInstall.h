#pragma once
#include <Windows.h>
#include "HraInstallDef.h"

#ifdef __cplusplus
extern "C"
{
#endif
    /// <summary>
    /// 获得服务的Config文件信息
    /// </summary>
    /// <param name="pszParamBuff"></param>
    /// <param name="nSizeCount"></param>
    /// <param name="pszServiceName"></param>
    /// <param name="pszParam"></param>
    /// <param name="pWin32ErrorCode"></param>
    /// <returns></returns>
    HRA_INSTALL_API DWORD GetHraIniValue(wchar_t* pszParamBuff, size_t nSizeCount, const wchar_t* pszServiceName,
                                         const wchar_t* pszKey);

    /// <summary>
    /// 获得当前安装的HRA版本
    /// </summary>
    /// <param name="szHraVersion">版本号</param>
    /// <param name="nBuffSize">buff大小，szHraVersion字符个数+1</param>
    /// <returns></returns>
    HRA_INSTALL_API DWORD GetHraInstalledVersion(unsigned __int64& nVersion, const wchar_t* pszServiceName);

    /// <summary>
    /// 获得当前安装的HRA接口版本
    /// </summary>
    /// <param name="szHraVersion">版本号</param>
    /// <param name="nBuffSize">buff大小，szHraVersion字符个数+1</param>
    /// <returns></returns>
    HRA_INSTALL_API DWORD GetHraInstalledIpcInterfaceVersion(unsigned __int64& nVersion, const wchar_t* pszServiceName);

    /// <summary>
    /// 获得hra zip包的Config文件信息
    /// </summary>
    /// <param name="pszParamBuff"></param>
    /// <param name="nSizeCount"></param>
    /// <param name="pszServiceName"></param>
    /// <param name="pszParam"></param>
    /// <param name="pWin32ErrorCode"></param>
    /// <returns></returns>
    HRA_INSTALL_API DWORD GetHraZipIniValue(wchar_t* pszParamBuff, size_t nSizeCount, const wchar_t* pszZipPath,
                                              const wchar_t* pszKey);

    /// <summary>
    /// 获得zip包的HRA版本
    /// </summary>
    /// <param name="szHraVersion">版本号</param>
    /// <param name="nBuffSize">buff大小，szHraVersion字符个数+1</param>
    /// <returns></returns>
    HRA_INSTALL_API DWORD GetHraZipVersion(unsigned __int64& nVersion, const wchar_t* pszZipPath);

    /// <summary>
    /// 获得zip包的HRA接口版本
    /// </summary>
    /// <param name="szHraVersion">版本号</param>
    /// <param name="nBuffSize">buff大小，szHraVersion字符个数+1</param>
    /// <returns></returns>
    HRA_INSTALL_API DWORD GetHraZipIpcInterfaceVersion(unsigned __int64& nVersion, const wchar_t* pszZipPath);

    /// <summary>
    /// 通过hra服务名获得安装路径
    /// </summary>
    /// <param name="pszInstallPath"></param>
    /// <param name="nSizeCount"></param>
    /// <param name="pszServiceName"></param>
    /// <param name="pWin32ErrorCode"></param>
    /// <returns></returns>
    HRA_INSTALL_API DWORD GetHraInstallPathByServiceName(wchar_t* pszInstallPath, size_t nSizeCount,
                                                        const wchar_t* pszServiceName);

    /// <summary>
    /// 通过hra安装路径获得服务名
    /// </summary>
    /// <param name="pszServiceName"></param>
    /// <param name="nSizeCount"></param>
    /// <param name="pszInstallPath"></param>
    /// <param name="pWin32ErrorCode"></param>
    /// <returns></returns>
    //HRA_INSTALL_API BOOL GetHraServiceNameByInstallPath(wchar_t* pszServiceName, size_t nSizeCount,
    //                                                    const wchar_t* pszInstallPath, DWORD* pWin32ErrorCode = NULL);

    /// <summary>
    /// 查询Hra是否已安装
    /// </summary>
    /// <param name="pszServiceName"></param>
    /// <returns></returns>
    HRA_INSTALL_API BOOL IsHraInstalled(const wchar_t* pszServiceName);

    /// <summary>
    /// HRA服务状态
    /// </summary>
    /// <param name="pszServiceName"></param>
    /// <param name="sStatus"></param>
    /// <param name="pWin32ErrorCode"></param>
    /// <returns></returns>
    HRA_INSTALL_API DWORD GetHraServiceStatus(const wchar_t* pszServiceName, SERVICE_STATUS& sStatus);

    /// <summary>
    /// 启动hra服务
    /// </summary>
    /// <param name="szServiceName">服务名称</param>
    /// <param name="szUUID">UUID</param>
    /// <param name="szProCommName">产品侧通信IPC名称</param>
    /// <param name="szHraCommName">HRA侧通信IPC名称</param>
    /// <returns></returns>
    HRA_INSTALL_API DWORD HraStart(const wchar_t* pszServiceName, const wchar_t* pszUUID, const wchar_t* pszProIpcName,
                                  const wchar_t* pszHraIpcName);

    /// <summary>
    /// 停止hra服务
    /// </summary>
    /// <param name="szServiceName"></param>
    /// <returns></returns>
    HRA_INSTALL_API DWORD HraStop(const wchar_t* pszServiceName);

    /// <summary>
    /// 创建服务
    /// </summary>
    /// <param name="szServiceName">服务名称</param>
    /// <param name="szInstallPath">安装目录</param>
    /// <returns></returns>
    HRA_INSTALL_API DWORD HraCreateService(const wchar_t* pszServiceName, const wchar_t* pszInstallPath);
    HRA_INSTALL_API DWORD HraCreateServiceEX(const wchar_t* pszServiceName, const wchar_t* pszInstallPath,
                                           const wchar_t* pszDataPath);

    /// <summary>
    /// 安装hra服务
    /// </summary>
    /// <param name="pszServiceName"></param>
    /// <param name="pszInstallPath"></param>
    /// <param name="pszZipPath"></param>
    /// <param name="pWin32ErrorCode"></param>
    /// <returns></returns>
    HRA_INSTALL_API DWORD HraInstall(const wchar_t* pszServiceName, const wchar_t* pszZipPath,
                                     const wchar_t* pszInstallPath);
    HRA_INSTALL_API DWORD HraInstallEX(const wchar_t* pszServiceName, const wchar_t* pszZipPath,
                                       const wchar_t* pszInstallPath, const wchar_t* pszDataPath);

    /// <summary>
    /// 卸载hra服务
    /// </summary>
    /// <param name="pszServiceName">服务名称</param>
    /// <param name="szInstallPath">安装目录</param>
    /// <returns></returns>
    HRA_INSTALL_API DWORD HraUninstall(const wchar_t* pszServiceName);
    HRA_INSTALL_API DWORD HraUninstallEX(const wchar_t* pszServiceName, int nUninstallAction);

    /// <summary>
    /// 安装hra服务
    /// </summary>
    /// <param name="szServiceName">服务名称</param>
    /// <param name="pszZipPath">安装包路径</param>
    /// <param name="szServiceName">安装路径</param>
    /// <param name="emType">安装方式，0：随产品安装，1：独立升级</param>
    /// <param name="emAction">安装后动作，0：无动作，1：启动服务</param>
    /// <returns></returns>
    HRA_INSTALL_API DWORD HraAutoInstall(const wchar_t* pszServiceName, const wchar_t* pszZipPath,
                                         const wchar_t* pszInstallPath, int nInstallType, int nInstallAction,
                                         const wchar_t* pszUUID, const wchar_t* pszProIpcName,
                                         const wchar_t* pszHraIpcName);
    HRA_INSTALL_API DWORD HraAutoInstallEX(const wchar_t* pszServiceName, const wchar_t* pszZipPath,
                                           const wchar_t* pszInstallPath, int nInstallType, int nInstallAction,
                                           const wchar_t* pszUUID, const wchar_t* pszProIpcName,
                                           const wchar_t* pszHraIpcName, const wchar_t* pszDataPath,
                                           int nUninstallAction);

    /// <summary>
    /// 获取HRA指定模块Pattern的版本号
    /// </summary>
    /// <param name="pwszValue"></param>
    /// <param name="nSizeCount"></param>
    /// <param name="pwszServiceName"></param>
    /// <returns></returns>
    HRA_INSTALL_API DWORD GetHraLoadedPatternVersion(wchar_t* pwszValue, size_t nSizeCount,
                                                        const wchar_t* pwszServiceName);

#ifdef __cplusplus
}
#endif