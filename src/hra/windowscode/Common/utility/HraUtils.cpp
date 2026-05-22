#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <wbemidl.h>
#include <windows.h>
#include <string.h>
#include <comdef.h>
#include <tchar.h>
#include <TlHelp32.h>

#include "ConfigSave.h"
#include "HraUtils.h"
#include "version.hpp"
#include "HraPatternUpdateUtils.h"
#include "HraJson.h"
#include "openssl/des.h"
#include "openssl/sha.h"
#include "zlib/unzip.h"
#include "zlib/zconf.h"
#include "zlib/zlib.h"
#include "zlib/zip.h"
#include <time.h>
#include <direct.h>
#include <iostream>
#include <io.h>
#include <algorithm>
#include <mutex>
#include <regex>
#include <shlobj.h>
#include <imagehlp.h>
#include <Shlwapi.h>

#include "HraAppDef.h"

#define PATTERN_VERSION_LEN 32
#define PATTERN_PATH_LEN 128
#define PATTERN_FILE_RESERVE_NUM 3 //pattern文件保留数目

#define DECRYPTION_KEY "P@ssw0rd"

using namespace std;

#pragma comment(lib,"Winmm.lib")
#pragma comment(lib,"wbemuuid.lib")

#ifdef _WIN32
#ifdef _WIN64
#pragma comment(lib,"libcrypto64MT.lib")
#pragma comment(lib,"libssl64MT.lib")
#else
#pragma comment(lib,"libcrypto32MT.lib")
#pragma comment(lib,"libssl32MT.lib")
#endif 
#endif

//发现openssl存在线程不安全的情况
std::mutex g_openssl_mutex;


////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	获取uuid 信息. </summary>
///
/// <remarks>	, 2021/12/18. </remarks>
///
/// <param name="parameter1">	The first parameter. </param>
///
/// <returns>	A std::string. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
std::string UtilsGetUUID(void)
{
    return g_ConfigSave.ConfigSaveGetValue(GLOBAL_CONFIG_TABLE, HRA_PARAM_UUID);
}

/// <summary>
/// 从config.db中获取PRO_IPC_NAME
/// </summary>
/// <param name=""></param>
/// <returns></returns>
std::string UtilsGetProIpcName(void)
{
    return g_ConfigSave.ConfigSaveGetValue(GLOBAL_CONFIG_TABLE, HRA_PARAM_PRO_IPC_NAME);
}

/// <summary>
/// 从config.db中获取HRA_IPC_NAME
/// </summary>
/// <param name=""></param>
/// <returns></returns>
std::string UtilsGetHraIpcName(void)
{
    return g_ConfigSave.ConfigSaveGetValue(GLOBAL_CONFIG_TABLE, HRA_PARAM_HRA_IPC_NAME);
}


////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	获取当前运行时间. </summary>
///
/// <remarks>	, 2021/12/18. </remarks>
///
/// <param name="parameter1">	The first parameter. </param>
///
/// <returns>	A int. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
int UtilsGetRunTime(void)
{
	time_t stRecordTime = time(NULL);
	return (int)stRecordTime;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	Utilities get operating system type. </summary>
///
/// <remarks>	, 2021/12/18. </remarks>
///
/// <param name="parameter1">	The first parameter. </param>
///
/// <returns>	A int. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
//int UtilsGetOsType(void)
//{
	//   char *line = NULL;
	//   int lineLen;
	//   size_t lineSize = 0;
	//   std::string osName;
//	OS_TYPE osType = OS_TYPE_INVALID;

	//   FILE *fp = fopen("/proc/version", "r");
	//   if (NULL == fp) 
	//   {
	//       return OS_TYPE_INVALID;
	//   }

	//while(NULL != fgets(line, lineSize, fp))
	//{

	//}
	//   if (lineLen <= 0) 
	//   {
	//       fclose(fp);
	//       if (line)
	//       {
	//           free(line);
	//       }

	//       return OS_TYPE_INVALID;
	//   }
	//   fclose(fp);

	//   if (line[lineLen - 1] == '\n')
	//   {
	//       lineLen = lineLen - 1;
	//   }

	//   line[lineLen] = 0;

	//   osName = std::string(line);
	//   free(line);

//	return osType;
//

std::string UtilsGetOsReleaseName()
{
    std::string strRet = "Microsoft Windows";

    HRESULT hres = 0;
    IWbemLocator *pLoc = NULL;
    IWbemServices *pSvc = NULL;

    ////////////////////初始化尝试3次
    bool bInit = false;
    int iTryCount = 0;
    while (true)
    {
        if (bInit)
        {
            break;
        }
        else if(!bInit && iTryCount>=3)
        {
            return strRet;
        }

        hres = CoInitializeEx(0, COINIT_MULTITHREADED);
        if (FAILED(hres)) 
        {
		    LOG_ERROR("InitWmi: CoInitializeEx failed: %x", hres);
            iTryCount++;
            continue;
        }

        hres = CoInitializeSecurity(NULL,-1,NULL,NULL,
            RPC_C_AUTHN_LEVEL_DEFAULT,RPC_C_IMP_LEVEL_IMPERSONATE,NULL,EOAC_NONE,NULL);
        if (FAILED(hres) && hres != RPC_E_TOO_LATE) 
        {
		    LOG_ERROR("InitWmi: CoInitializeSecurity failed: %x", hres);
            CoUninitialize();
            iTryCount++;
            continue;
        }

        hres = CoCreateInstance(CLSID_WbemLocator,0,CLSCTX_INPROC_SERVER,IID_IWbemLocator,(LPVOID *)&pLoc);
        if (FAILED(hres)) 
        {
            LOG_ERROR("InitWmi: CoCreateInstance failed: %x", hres);
            CoUninitialize();
            iTryCount++;
            continue;
        }

        hres = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"),NULL,NULL,0,NULL,0,0,&pSvc);
        if (FAILED(hres)) 
        {
		    LOG_ERROR("InitWmi: ConnectServer failed: %x", hres);
            pLoc->Release();
            CoUninitialize();
            iTryCount++;
            continue;
        }

        hres = CoSetProxyBlanket(pSvc,RPC_C_AUTHN_WINNT,RPC_C_AUTHZ_NONE,NULL,
            RPC_C_AUTHN_LEVEL_CALL,RPC_C_IMP_LEVEL_IMPERSONATE,NULL,EOAC_NONE);
        if (FAILED(hres)) 
        {
		    LOG_ERROR("InitWmi: CoSetProxyBlanket failed: %x", hres);
            pSvc->Release();
            pLoc->Release();
            CoUninitialize();
            iTryCount++;
            continue;
        }
        bInit = true;
    }
    ////////////初始化完成

    ////////////查询结果
    std::string info;
    IEnumWbemClassObject *pEnumerator = NULL;
    std::string wql = "SELECT Caption FROM Win32_OperatingSystem";
    hres = pSvc->ExecQuery(bstr_t("WQL"),bstr_t(wql.c_str()),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,NULL,&pEnumerator);
    if (FAILED(hres)) 
    {
		LOG_ERROR("InitWmi: ExecQuery failed: %x", hres);
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return strRet;
    }

    IWbemClassObject *pclsObj = NULL;
    ULONG uReturn = 0;
    while (pEnumerator) 
    {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
        if (0 == uReturn) 
        {
            break;
        }
        if (FAILED(hr))
        {
            LOG_WARN("pEnumerator->Next failed, errorCode:%x", hr);
            if (pclsObj)
            {
                pclsObj->Release();
                pclsObj = NULL;
            }
            break;
        }

        VARIANT vtProp;
        hr = pclsObj->Get(L"Caption", 0, &vtProp, 0, 0);
        if (FAILED(hr))
        {
            LOG_WARN("pclsObj->Get failed, errorCode:%x", hr);
            if (pclsObj)
            {
                pclsObj->Release();
                pclsObj = NULL;
            }
            break;
        }
        if (vtProp.bstrVal != NULL)
        {
            strRet = UtilsUnicodeToString(vtProp.bstrVal);
        }
        VariantClear(&vtProp);
        pclsObj->Release();
        pclsObj = NULL;
    }
    if (pEnumerator)
    {
        pEnumerator->Release();
    }

    ////////////释放
    pSvc->Release();
    pLoc->Release();
    CoUninitialize();

    return strRet;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	Utilities get application version. </summary>
///
/// <remarks>	, 2021/12/18. </remarks>
///
/// <param name="parameter1">	The first parameter. </param>
///
/// <returns>	A std::string. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
std::string UtilsGetAppVersion(void)
{
	std::string strHraVersion;
	char ascHraVersion[HRA_VERSION_LEN] = {0};
	_snprintf_s(ascHraVersion, HRA_VERSION_LEN, "V%d.%d.%d-%d",
		HRA_VER_MAJOR, 
		HRA_VER_MINOR,
		HRA_VER_PATCH,
		HRA_VER_BUILD);
	strHraVersion = ascHraVersion;

	return strHraVersion;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	Utilities get osscan pattern version. </summary>
///
/// <remarks>	, 2021/12/18. </remarks>
///
/// <param name="parameter1">	The first parameter. </param>
///
/// <returns>	A std::string. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
std::string UtilsGetOSscanPatternVersion(void)
{
	return g_ConfigSave.ConfigSaveGetValue(GLOBAL_CONFIG_TABLE, "OsscanPatternVersion");
}



////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	获取系统扫描pattern版本全路径. </summary>
///
/// <remarks>	, 2021/12/18. </remarks>
///
/// <param name="parameter1">	The first parameter. </param>
///
/// <returns>	系统扫描pattern版本全路径字符串. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
std::string UtilsGetOSscanPatternVersionPath(void)
{
	return g_ConfigSave.ConfigSaveGetValue(GLOBAL_CONFIG_TABLE, "OsscanPatternVersionPath");
}

std::string UtilsGetMultiOsScanPatternVersionPath(void)
{
    return g_ConfigSave.ConfigSaveGetValue(GLOBAL_CONFIG_TABLE, "MultiOsscanPatternVersionPath");
}

std::string UtilsGetKbCveOsScanPatternVerisionPath(void)
{
	return g_ConfigSave.ConfigSaveGetValue(GLOBAL_CONFIG_TABLE, "KbCveOsscanPatternVersionPath");
}


////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	获取基线扫描pattern版本全路径. </summary>
///
/// <remarks>	, 2021/12/18. </remarks>
///
/// <param name="parameter1">	The first parameter. </param>
///
/// <returns>	基线扫描pattern版本全路径字符串. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
std::string UtilsGetBaselinePatternVersionPath(void)
{
	return g_ConfigSave.ConfigSaveGetValue(GLOBAL_CONFIG_TABLE, "BaselinePatternVersionPath");
}


////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	获取基线扫描pattern版本信息. </summary>
///
/// <remarks>	, 2021/12/18. </remarks>
///
/// <param name="parameter1">	The first parameter. </param>
///
/// <returns>	基线扫描pattern版本信息字符串. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
std::string UtilsGetBaselinePatternVersion(void)
{
	return g_ConfigSave.ConfigSaveGetValue(GLOBAL_CONFIG_TABLE, "BaselinePatternVersion");
}


std::string UtilsGetDolphinPatternVersionPath(void)
{
    return g_ConfigSave.ConfigSaveGetValue(GLOBAL_CONFIG_TABLE, "WpscanPatternVersionPath");
}

std::string UtilsGetDolphinPatternVersion(void)
{
    return g_ConfigSave.ConfigSaveGetValue(GLOBAL_CONFIG_TABLE, "WpscanPatternVersion");
}

/// <summary>
/// VulnPoc pattern配置信息读取
/// </summary>
/// <param name=""></param>
/// <returns></returns>
std::string UtilsGetVulnPocPatternVersionPath(void)
{
    return g_ConfigSave.ConfigSaveGetValue(GLOBAL_CONFIG_TABLE, "VulnPocPatternVersionPath");
}
std::string UtilsGetVulnPocPatternVersion(void)
{
    return g_ConfigSave.ConfigSaveGetValue(GLOBAL_CONFIG_TABLE, "VulnPocPatternVersion");
}

/// <summary>
/// 资产pattern配置信息读取
/// </summary>
/// <param name=""></param>
/// <returns></returns>
std::string UtilsGetAssetPatternVersion(void)
{
    return g_ConfigSave.ConfigSaveGetValue(GLOBAL_CONFIG_TABLE, "AssetPatternVersion");
}
std::string UtilsGetAssetPatternVersionPath(void)
{
    return g_ConfigSave.ConfigSaveGetValue(GLOBAL_CONFIG_TABLE, "AssetPatternVersionPath");
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	二进制转十六进制字符串. </summary>
///
/// <remarks>	, 2021/12/18. </remarks>
///
/// <param name="pucByteArr">	[in] If non-null, array of puc bytes. </param>
/// <param name="lArrLen">   	[in] Length of the array. </param>
///
/// <returns>	十六进制字符串. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
std::string UtilsByteToHexStr(unsigned char *pucByteArr, int lArrLen)
{
	std::string strHexstr;

	for (int i = 0; NULL != pucByteArr && i < lArrLen; ++i)
	{
		char scHexTmp;
		char scHexTmp2;

		//借助C++支持的unsigned和int的强制转换，把unsigned char赋值给int的值，那么系统就会自动完成强制转换
		int value = pucByteArr[i];
		int S = value / 16;
		int Y = value % 16;

		//将C++中unsigned char和int的强制转换得到的商转成字母
		if (S >= 0 && S <= 9)
		{
			scHexTmp = (char)(48 + S);
		}
		else
		{
			scHexTmp = (char)(55 + S);
		}

		//将C++中unsigned char和int的强制转换得到的余数转成字母
		if (Y >= 0 && Y <= 9)
		{
			scHexTmp2 = (char)(48 + Y);
		}
		else
		{
			scHexTmp2 = (char)(55 + Y);
		}

		//最后一步的代码实现，将所得到的两个字母连接成字符串达到目的
		strHexstr = strHexstr + scHexTmp + scHexTmp2;
	}

	return strHexstr;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	十六进制字符串转二进制. </summary>
///
/// <remarks>	, 2021/12/18. </remarks>
///
/// <param name="pscInputHexStr">  	[in] The psc input hexadecimal string. </param>
/// <param name="ulInputHexStrLen">	[in] Length of the ul input hexadecimal string. </param>
/// <param name="pucOutBits">	   	[out] If non-null, the puc out bits. </param>
/// <param name="ulOutBitsLen">	   	[out] Length of the ul out bits. </param>
///
/// <returns>	二进制长度. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
int UtilsHexStrToByte(const char *pscInputHexStr, unsigned int ulInputHexStrLen, unsigned char *pucOutBits, unsigned int ulOutBitsLen)
{
	int i, n = 0;

	for (i = 0; i < ulInputHexStrLen && pscInputHexStr[i] && n < ulOutBitsLen; i += 2,++n)
	{
		if (pscInputHexStr[i] >= 'A' && pscInputHexStr[i] <= 'F')
		{
			pucOutBits[n] = pscInputHexStr[i] - 'A' + 10;
		}
		else 
		{
			pucOutBits[n] = pscInputHexStr[i] - '0';
		}

		if (pscInputHexStr[i + 1] >= 'A' && pscInputHexStr[i + 1] <= 'F')
		{
			pucOutBits[n] = (pucOutBits[n] << 4) | (pscInputHexStr[i + 1] - 'A' + 10);
		}
		else 
		{
			pucOutBits[n] = (pucOutBits[n] << 4) | (pscInputHexStr[i + 1] - '0');
		}

	}

	return n;
}

std::string UtilsGetWorkPath(void)
{
	std::string strPath;

	strPath = g_ConfigSave.ConfigSaveGetValue(GLOBAL_CONFIG_TABLE, HRA_PARAM_WORK_DIR);

	if(strPath.size()==0)
	{
		strPath = ".\\";
	}

	return strPath;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	拼接对应模块的pattern存放路径. </summary>
///
/// <remarks>	, 2021/12/22. </remarks>
///
/// <param name="strPatternPath">	Full pathname of the pattern file. </param>
///
/// <returns>	pattern 文件名. </returns>
/// CAUTIONS:
///      strPatternPath : 模块pattern的相对路径
///	     #define APPSACN_PATTERN_DIR   "..\\patterns\\appscan\\"
///	     #define OSSACN_PATTERN_DIR    "..\\patterns\\ossscan\\"
///	     #define BASELINE_PATTERN_DIR  "..\\patterns\\baseline\\"
////////////////////////////////////////////////////////////////////////////////////////////////////

std::string UtilsGetMetaInfoDir(const std::string &strPatternPath)
{
	std::string strMetaInfoPath;

	std::string strWorkDir =  UtilsGetWorkPath();

	strMetaInfoPath = strWorkDir + strPatternPath;

	return strMetaInfoPath;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	从components.json 中获取pattern 文件名. </summary>
///
/// <remarks>	, 2021/12/22. </remarks>
///
/// <param name="pscPatternPath">	Full pathname of the psc pattern file. </param>
/// <param name="pscKey">		 	The psc key. </param>
///
/// <returns>	pattern 文件名. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
static std::string UtilsGetPatternPathFromInfoFilePath(const char *pscPatternPath, const char *pscKey)
{
	std::string strPatternPath;
	std::string strTemp;
	std::string strPatternName;
    std::string strPatternVersion;
    std::string strPathFind;
	Json::Value jsRoot;
	Json::Value jsPatternName;
	struct stat stFileStat;
	Json::Value jsHash;
    if (!pscPatternPath || strlen(pscPatternPath) <= 0 || !pscKey || strlen(pscKey) <= 0)
	{
		LOG_ERROR("Parameter is null.");
		return "";
	}

	strPatternPath = pscPatternPath;
	strTemp = strPatternPath + PATTERN_INFORMATION;
    LOG_DEBUG("meta_info path:%s", strTemp.c_str());

	jsRoot = FileToJson(strTemp.c_str());
    if (!jsRoot.isMember("pattern_version") || !jsRoot["pattern_version"].isString())
    {
        LOG_ERROR("Json pattern_version not found or error! file:%s", strTemp.c_str());
        return "";
    }
    strPatternVersion = jsRoot["pattern_version"].asString();
    strPathFind += pscKey;
    strPathFind += "$";
    strPathFind += strPatternVersion;
    LOG_DEBUG("PathFind:%s", strPathFind.c_str());

	if (!jsRoot.isMember("sha256") || !jsRoot["sha256"].isArray())
	{
		LOG_ERROR("Json sha256 not found or error! file:%s",strTemp.c_str());
		return "";
	}
	jsHash = jsRoot["sha256"];
	for (int i = 0; i < jsHash.size(); i++)
	{
		if (jsHash[i].isMember("path") && jsHash[i]["path"].isString())
		{
			std::string strPath = jsHash[i]["path"].asCString();
            if (strPath.find(strPathFind) != std::string::npos)
            {
                // 找到想要的版本
                strPatternName = strPath;
                break;
            }
            else
            {
                continue;
            }
		}
		else
		{
            LOG_ERROR("Json path not found or error! file:%s", strTemp.c_str());
			return "";
		}
	}

    if (strPatternName.empty())
    {
        LOG_ERROR("Pattern file:%s not found in meta_info file:%s", strPathFind.c_str(), strTemp.c_str());
        return "";
    }

	strTemp = strPatternPath + "data\\" + strPatternName;
	//if (stat(strTemp.c_str(), &stFileStat) < 0)
    if (!UtilsIsFileExist(UtilsStringToUnicode(strTemp).c_str()))
	{
		LOG_ERROR("pattern file File does not exist: %s", strTemp.c_str());
		return "";
	}

	return strTemp;
}

//cppcheck-suppress unusedFunction
//static std::string UtilsGetPatternPathFromInfoFileName(const char *pscPatternPath, const char *pscKey)
//{
//	std::string strPatternPath = UtilsGetPatternPathFromInfoFilePath(pscPatternPath, pscKey);
//	int lIndex = strPatternPath.rfind("$");
//	if (lIndex == std::string::npos)
//	{
//		LOG_ERROR("The desired string was not found.");
//		return "";
//	}
//	std::string strPatternVersion= strPatternPath.substr(lIndex);
//	return strPatternVersion;
//}

//获取pattern文件路径
std::string UtilsGetPatternPath(const std::string &strPatternPath, const std::string& strPattenNameKey)
{
	std::string strPatternVersionPath;
	std::string strMetaInfoPath;

	strMetaInfoPath = UtilsGetMetaInfoDir(strPatternPath);
	LOG_DEBUG("strMetaInfoPath(%s), PattenNameKey(%s)",strMetaInfoPath.c_str(), strPattenNameKey.c_str());
	strPatternVersionPath = UtilsGetPatternPathFromInfoFilePath(strMetaInfoPath.c_str(), strPattenNameKey.c_str());
	if(strPatternVersionPath.size() == 0)
	{
		LOG_ERROR("Failed to obtain the pattern folder path.  Procedure");
		return "";
	}

	return strPatternVersionPath;
}

//void UtilsRemoveSpecialLetter(std::string& raw)
//{
//	for (size_t i = 0; i < raw.size();) 
//	{
//		if (raw[i] == '\"') 
//		{
//			raw.erase(i, 1);
//		}
//		else 
//		{
//			i++;
//		}
//	}
//}

std::string UtilsGetBaselineTypePattenName(void)
{
	return "cust_blp";
}

std::string UtilsGetOsScanTypePattenName(void)
{
	return "vawinp";
}

std::string UtilsGetDolphinTypePattenName(void)
{
    return "wpp";
}

std::string UtilsGetVulnPocTypePattenName(void)
{
    return "vuln_poc";
}

std::string UtilsGetMultiOsScanTypePatternDirName(void)
{
    return "os_scan_separated";
}

std::string UtilsGetKbCveOsScanTypePatternName(void)
{
	return "kb_cve";
}

std::string UtilsGetAssetTypePattenName(void)
{
    return "asset";
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	从mete_info.json文件获取appscan的pattern版本,并存储. </summary>
///
/// <remarks>	, 2021/12/18. </remarks>
///
/// <param name="parameter1">	The first parameter. </param>
///
/// <returns>	A void. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
void UtilsStoreOSscanPatternVersionFromFile(bool bUpdate)
{
	std::string strPatternversionPath;
	std::string strPatternVersion;
	std::string strOsScanTypePattenName = UtilsGetOsScanTypePattenName();
	std::string strKbCverOsScanTypePattenName = UtilsGetKbCveOsScanTypePatternName();

	LOG_INFO("Get and store OsScan pattern version. %s ", strOsScanTypePattenName.c_str());
	strPatternversionPath = UtilsGetPatternPath(OSSACN_PATTERN_DIR, strOsScanTypePattenName);
	int lIndex = strPatternversionPath.rfind("$");
	if (std::string::npos != strPatternversionPath.rfind("$"))
	{
		strPatternVersion = strPatternversionPath.substr(lIndex+1);
	}
	else
	{
		strPatternVersion = "0";
	}

	if(strPatternversionPath.size() == 0)
	{
		strPatternVersion = "0";
	}
	LOG_INFO("get Osscan pattern version %s, path : %s", strPatternVersion.c_str(), strPatternversionPath.c_str());
    std::string multiPatternPath = strPatternversionPath.substr(0, strPatternversionPath.rfind("\\")) + "\\" + UtilsGetMultiOsScanTypePatternDirName();
    LOG_INFO("get Osscan multi pattern version %s, path : %s", strPatternVersion.c_str(), multiPatternPath.c_str());

	std::string strKbCvePatternVersionPath = UtilsGetPatternPath(OSSACN_PATTERN_DIR, strKbCverOsScanTypePattenName);
	LOG_INFO("get Osscan CveKb pattern version %s, path : %s", strPatternVersion.c_str(), strKbCvePatternVersionPath.c_str());

    if (bUpdate)
    {
        std::string strLocalTime = UtilsGetLocalTime();
        g_ConfigSave.ConfigSaveSetValue(GLOBAL_CONFIG_TABLE, "OsscanPatternUpdateTime", strLocalTime);
    }

	g_ConfigSave.ConfigSaveSetValue(GLOBAL_CONFIG_TABLE, "OsscanPatternVersion", strPatternVersion);
	g_ConfigSave.ConfigSaveSetValue(GLOBAL_CONFIG_TABLE, "OsscanPatternVersionPath", strPatternversionPath);
	g_ConfigSave.ConfigSaveSetValue(GLOBAL_CONFIG_TABLE, "KbCveOsscanPatternVersionPath", strKbCvePatternVersionPath);
    g_ConfigSave.ConfigSaveSetValue(GLOBAL_CONFIG_TABLE, "MultiOsscanPatternVersionPath", multiPatternPath);

    // read os scan su version and save
    std::string strOsScanVerDotStyle = "";
    std::string strWorkDir =  UtilsGetWorkPath();

    std::string strOsScanPatternPath = UtilsPathAppend(strWorkDir, OSSACN_PATTERN_DIR);
    if(ReadSUVersionFromMetaInfo(strOsScanPatternPath, strOsScanVerDotStyle))
    {
        g_ConfigSave.ConfigSaveSetValue(GLOBAL_CONFIG_TABLE, "OsscanDisplayVersion", strOsScanVerDotStyle);
        LOG_INFO("os scan display version: %s", strOsScanVerDotStyle.c_str());
    }
    else
    {
        g_ConfigSave.ConfigSaveSetValue(GLOBAL_CONFIG_TABLE, "OsscanDisplayVersion", strOsScanVerDotStyle);
        LOG_INFO("get os scan display version failed, set OsscanDisplayVersion with empty string");
    }

    g_ConfigSave.CleanUpWAL();
	return;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	从mete_info.json文件获取appscan的pattern版本,并存储. </summary>
///
/// <remarks>	, 2021/12/18. </remarks>
///
/// <param name="parameter1">	The first parameter. </param>
///
/// <returns>	A void. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
void UtilsStoreBaselinePatternVersionFromFile(bool bUpdate)
{
	std::string strPatternversionPath;
	std::string strPatternVersion;

	strPatternversionPath = UtilsGetPatternPath(BASELINE_PATTERN_DIR, UtilsGetBaselineTypePattenName());
	int lIndex = strPatternversionPath.rfind("$");
	if (std::string::npos != strPatternversionPath.rfind("$"))
	{
		strPatternVersion = strPatternversionPath.substr(lIndex+1);
	}
	else
	{
		strPatternVersion = "0";
	}

	if(strPatternversionPath.size() == 0)
	{
		strPatternVersion = "0";
	}
	LOG_INFO("get baseline pattern version %s, path : %s", strPatternVersion.c_str(), strPatternversionPath.c_str());

    if (bUpdate)
    {
        std::string strLocalTime = UtilsGetLocalTime();
        g_ConfigSave.ConfigSaveSetValue(GLOBAL_CONFIG_TABLE, "BaselinePatternUpdateTime", strLocalTime);
    }
    
    g_ConfigSave.ConfigSaveSetValue(GLOBAL_CONFIG_TABLE, "BaselinePatternVersion", strPatternVersion);
    g_ConfigSave.ConfigSaveSetValue(GLOBAL_CONFIG_TABLE, "BaselinePatternVersionPath", strPatternversionPath);
    g_ConfigSave.CleanUpWAL();
}

/// <summary>
/// 
/// </summary>
/// <param name=""></param>
void UtilsStoreDolphinPatternVersionFromFile(bool bUpdate)
{
    std::string strPatternversionPath;
    std::string strPatternVersion;
    std::string strDolphinTypePattenName = UtilsGetDolphinTypePattenName();

    LOG_INFO("Get and store Dolphin pattern version. %s ", strDolphinTypePattenName.c_str());
    strPatternversionPath = UtilsGetPatternPath(DOLPHIN_PATTERN_DIR, strDolphinTypePattenName);
    int lIndex = strPatternversionPath.rfind("$");
    if (std::string::npos != strPatternversionPath.rfind("$"))
    {
        strPatternVersion = strPatternversionPath.substr(lIndex + 1);
    }
    else
    {
        strPatternVersion = "0";
    }

    if (strPatternversionPath.size() == 0)
    {
        strPatternVersion = "0";
    }
    LOG_INFO("get Dolphin pattern version %s, path : %s", strPatternVersion.c_str(), strPatternversionPath.c_str());

    if (bUpdate)
    {
        std::string strLocalTime = UtilsGetLocalTime();
        g_ConfigSave.ConfigSaveSetValue(GLOBAL_CONFIG_TABLE, "WpscanPatternUpdateTime", strLocalTime);
    }

    g_ConfigSave.ConfigSaveSetValue(GLOBAL_CONFIG_TABLE, "WpscanPatternVersion", strPatternVersion);
    g_ConfigSave.ConfigSaveSetValue(GLOBAL_CONFIG_TABLE, "WpscanPatternVersionPath", strPatternversionPath);
    g_ConfigSave.CleanUpWAL();

    return;
}

/// <summary>
/// 存储pattern版本
/// </summary>
/// <param name=""></param>
void UtilsStoreVulnPocPatternVersionFromFile(bool bUpdate)
{
    std::string strPatternversionPath;
    std::string strPatternVersion;
    std::string strVulnPocTypePattenName = UtilsGetVulnPocTypePattenName();

    LOG_INFO("Get and store VulnPoc pattern version. %s ", strVulnPocTypePattenName.c_str());
    strPatternversionPath = UtilsGetPatternPath(VULNPOC_PATTERN_DIR, strVulnPocTypePattenName);
    int lIndex            = strPatternversionPath.rfind("$");
    if (std::string::npos != strPatternversionPath.rfind("$"))
    {
        strPatternVersion = strPatternversionPath.substr(lIndex + 1);
    }
    else
    {
        strPatternVersion = "0";
    }

    if (strPatternversionPath.size() == 0)
    {
        strPatternVersion = "0";
    }
    LOG_INFO("get VulnPoc pattern version %s, path : %s", strPatternVersion.c_str(), strPatternversionPath.c_str());

    if (bUpdate)
    {
        std::string strLocalTime = UtilsGetLocalTime();
        g_ConfigSave.ConfigSaveSetValue(GLOBAL_CONFIG_TABLE, "VulnPocPatternUpdateTime", strLocalTime);
    }

    g_ConfigSave.ConfigSaveSetValue(GLOBAL_CONFIG_TABLE, "VulnPocPatternVersion", strPatternVersion);
    g_ConfigSave.ConfigSaveSetValue(GLOBAL_CONFIG_TABLE, "VulnPocPatternVersionPath", strPatternversionPath);
    g_ConfigSave.CleanUpWAL();
}

/// <summary>
/// 存储pattern版本
/// </summary>
/// <param name=""></param>
void UtilsStoreAssetPatternVersionFromFile(bool bUpdate)
{
    std::string strPatternversionPath;
    std::string strPatternVersion;
    std::string strAssetTypePattenName = UtilsGetAssetTypePattenName();

    LOG_INFO("Get and store Asset pattern version. %s ", strAssetTypePattenName.c_str());
    strPatternversionPath = UtilsGetPatternPath(ASSET_PATTERN_DIR, strAssetTypePattenName);
    int lIndex            = strPatternversionPath.rfind("$");
    if (std::string::npos != strPatternversionPath.rfind("$"))
    {
        strPatternVersion = strPatternversionPath.substr(lIndex + 1);
    }
    else
    {
        strPatternVersion = "0";
    }

    if (strPatternversionPath.size() == 0)
    {
        strPatternVersion = "0";
    }
    LOG_INFO("get Asset pattern version %s, path : %s", strPatternVersion.c_str(), strPatternversionPath.c_str());

    if (bUpdate)
    {
        std::string strLocalTime = UtilsGetLocalTime();
        g_ConfigSave.ConfigSaveSetValue(GLOBAL_CONFIG_TABLE, "AssetPatternUpdateTime", strLocalTime);
    }

    g_ConfigSave.ConfigSaveSetValue(GLOBAL_CONFIG_TABLE, "AssetPatternVersion", strPatternVersion);
    g_ConfigSave.ConfigSaveSetValue(GLOBAL_CONFIG_TABLE, "AssetPatternVersionPath", strPatternversionPath);
    g_ConfigSave.CleanUpWAL();
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	去除PKCS5Padding填充方式. </summary>
///
/// <remarks>	, 2021/12/18. </remarks>
///
/// <param name="pstrParams">	[in] 需要去除PKCS5Padding的字符串. </param>
///
/// <returns>	A void. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
void utilsCancelPKCS5Padding(std::string &pstrParams)
{
	if (pstrParams.size() == 0)
	{
		LOG_ERROR("Parameter is null.");
		return ;
	}
	int lStrLen = pstrParams.size();
	unsigned char ucLastChar = pstrParams.at(lStrLen-1);

	if (ucLastChar > sizeof(DES_cblock) || 0 != (pstrParams.size() % sizeof(DES_cblock)))    // 不符合PKCS5 的填充方式
	{
		LOG_WARN("This decrypted content does not use PKCS5Padding.");
		return ;
	}

	BOOL bFlag = TRUE;  // 判断最后几个字符是否都是填充字符
	for(int i = lStrLen-1; i >= lStrLen-ucLastChar; i--)
	{
		if(ucLastChar != pstrParams.at(i))
		{
			bFlag = FALSE;
			break;
		}
	}

	if(TRUE == bFlag)
	{
		pstrParams.erase(lStrLen - ucLastChar);  // 删除最后几个填充的字符串
	}

	return ;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	读取文件全部内容，返回文件内容. 注意：内部会malloc， 使用完需要在调用处手工释放 </summary>
///
/// <remarks>	, 2021/12/18. </remarks>
///
/// <param name="strFilePath">	Full pathname of the file. </param>
///
/// <returns>	A std::string. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
int utilsReadFileAllContent(unsigned char** ppFileData, size_t& nFileSize, const char* szFilePath)
{
    if (ppFileData == NULL || *ppFileData != NULL || szFilePath == NULL)
    {
        LOG_ERROR("Param error!");
        return HRA_BAD_PARAM;
    }

    LOG_DEBUG("Read File:%s start!", szFilePath);
	ifstream inFile;
	//unsigned char *pucFileBuff = NULL;
	//std::string strFileData;;

	inFile.open(szFilePath, ios::binary);
	if (!inFile.is_open())
	{
		LOG_ERROR("Failed to open file:%s ", szFilePath);
		return HRA_OPEN_FAIL;
	}

	inFile.seekg(0, ios::end);
    nFileSize = inFile.tellg();  //获取文件长度
	inFile.seekg(0, ios::beg); //设置读取位置为起始位置

	*ppFileData = (unsigned char *)malloc(nFileSize + 1);
	if (NULL == *ppFileData)
	{
		LOG_ERROR("Failed to allocate memory.");
		inFile.close();
		return HRA_MALLOC_FAIL;
	}

	//将文件内容拷贝到buff
    memset(*ppFileData, 0, nFileSize + 1);
	inFile.read((char *)*ppFileData, nFileSize);
	inFile.close();

	//转化为string返回
	//strFileData.assign((char *)pucFileBuff, lFileLen);
	//free(pucFileBuff);
	//pucFileBuff = NULL;
    LOG_DEBUG("Read File:%s succeed! size:%u", szFilePath, (unsigned int)nFileSize);

	return HRA_OK;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	针对于使用ECD模式，PKCS5Padding填充方式进行加密的字符串进行解密. </summary>
///
/// <remarks>	, 2021/12/18. </remarks>
///
/// <param name="strEncryData">	Information describing the encry. </param>
///
/// <returns>	解密后的字符串. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
std::string UtilsDecryptDesEcb(const unsigned char* pData, size_t nSize)
{
	DES_cblock desKey;
	DES_key_schedule desSchedule;
	const_DES_cblock desSubEncryData;  // 存储加密的数据块
	DES_cblock desSubDecryRet;         // 存储解密后的数据块
	std::string strDecryData;

	if(pData == NULL || nSize <= 0)
	{
		LOG_ERROR("Parameter is null.");
		return "";
	}

    LOG_INFO("Began to decrypt.");
    g_openssl_mutex.lock();
	memcpy(desKey, DECRYPTION_KEY, sizeof(DES_cblock)); // 设置密匙    
	DES_set_key_unchecked(&desKey, &desSchedule);      //转换成schedule

	//循环解密
	for(int i=0; i < nSize /sizeof(const_DES_cblock); i++)
	{
		memset(desSubEncryData, 0, sizeof(const_DES_cblock));
		memset(desSubDecryRet, 0, sizeof(DES_cblock));

		//将数据块解密后拷贝到数组中
		memcpy(desSubEncryData, pData + i * sizeof(const_DES_cblock), sizeof(const_DES_cblock));
		DES_ecb_encrypt(&desSubEncryData, &desSubDecryRet, &desSchedule, DES_DECRYPT);

		strDecryData.append((char *)desSubDecryRet, sizeof(desSubDecryRet));
	}

	//加密使用了PKCS5Padding方法填充，所以将填充字符串去掉
	utilsCancelPKCS5Padding(strDecryData);
    g_openssl_mutex.unlock();
    LOG_INFO("Enf of decrypt.");

	return strDecryData;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	针对于使用ECD模式，PKCS5Padding填充方式进行加密的文件进行解密. </summary>
///
/// <remarks>	, 2021/12/18. </remarks>
///
/// <param name="strFilePath">	Full pathname of the file. </param>
///
/// <returns>	解密后的文件内容字符串. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
std::string UtilsFileDecryption(const std::string &strFilePath)
{
	//std::string strFileContent;
	std::string strDecryData;

	if (0 == strFilePath.size())
	{
		LOG_ERROR("Parameter is null.");
		return "";
	}

	//先将加密的文件读出来
    LOG_INFO("Start reading file:%s contents", strFilePath.c_str());
    unsigned char* pFileData = NULL;
    size_t nFileSize = 0;
    if (HRA_OK != utilsReadFileAllContent(&pFileData, nFileSize, strFilePath.c_str()))
    {
        if (pFileData)
        {
            free(pFileData);
            pFileData = NULL;
        }
        return "";
    }
	if (nFileSize <= 0)
	{
		LOG_ERROR("Failed to read the file: %s, size:%u",strFilePath.c_str(), (unsigned int)nFileSize);
        if (pFileData)
        {
            free(pFileData);
            pFileData = NULL;
        }
		return "";
	}

	strDecryData = UtilsDecryptDesEcb(pFileData, nFileSize);
	if(0 == strDecryData.size())
	{
		LOG_ERROR("Decryption failure . file:%s", strFilePath.c_str());
        if (pFileData)
        {
            free(pFileData);
            pFileData = NULL;
        }
		return "";
	}

    LOG_INFO("Decrypt file:%s succeed!", strFilePath.c_str());
    if (pFileData)
    {
        free(pFileData);
        pFileData = NULL;
    }
	return strDecryData;
}

/// <summary>
/// json文件读取并加密
/// </summary>
/// <param name="strFilePath"></param>
/// <param name="strFileContent"></param>
/// <returns></returns>
int UtilsFileEncryption(unsigned char** ppEncryptData, uint64_t& nDataLen, const char* pszFilePath)
{
    int nRet                 = HRA_OK;
    unsigned char* pFileData = NULL;
    size_t nFileSize         = 0;

    if (pszFilePath == NULL || strlen(pszFilePath) <= 0)
    {
        LOG_ERROR("pszFilePath error!");
        return HRA_BAD_PARAM;
    }

    if (ppEncryptData == NULL || *ppEncryptData != NULL)
    {
        LOG_ERROR("ppEncryptData error!");
        return HRA_BAD_PARAM;
    }

    LOG_INFO("Start reading file:%s contents", pszFilePath);
    //读取文件内容
    nRet = utilsReadFileAllContent(&pFileData, nFileSize, pszFilePath);
    if (HRA_OK != nRet)
    {
        LOG_ERROR("Reading file:%s contents error!", pszFilePath);
        goto _exit;
    }
    //加密
    nRet = UtilsEncryptDesEcb(ppEncryptData, nDataLen, (const char*)pFileData, nFileSize);
    if (HRA_OK != nRet)
    {
        LOG_ERROR("Encrypt file contents error! file:%s ", pszFilePath);
        goto _exit;
    }

_exit:
    if (pFileData != NULL)
    {
        free(pFileData);
        pFileData = NULL;
    }

    if (HRA_OK != nRet && *ppEncryptData != NULL)
    {
        free(*ppEncryptData);
        *ppEncryptData = NULL;
    }

    return nRet;
}

/// <summary>
/// 对明文进行PKCS5填充
/// </summary>
/// <param name="data"></param>
/// <returns></returns>
bool UtilsPadPkcs5(unsigned char** ppPadData, uint64_t& nPadDatLen, const char* pContentData, uint64_t nContentLen)
{
    if (pContentData == NULL || nContentLen <= 0)
    {
        return false;
    }

    if (ppPadData == NULL || *ppPadData != NULL)
    {
        return false;
    }

    uint64_t nStrLen        = nContentLen;
    int nPadLen             = 8 - (nStrLen % 8);                   // 计算需要填充的字节数
    unsigned char pad_char  = static_cast<unsigned char>(nPadLen); // 转换为字符
    uint64_t nDatLen        = nStrLen + nPadLen;
    *ppPadData              = (unsigned char*)malloc(nDatLen + 1);
    if (*ppPadData == NULL)
    {
        return false;
    }
    memset(*ppPadData, 0, nDatLen + 1);
    memcpy(*ppPadData, pContentData, nStrLen);
    for (int i = 0; i < nPadLen; ++i)
    {
        (*ppPadData)[nStrLen + i] = pad_char;
    }
    nPadDatLen = nDatLen;
    return true;
}

/// <summary>
/// DES ecb模式加密
/// </summary>
/// <param name="vctEncryptData"></param>
/// <param name="strFileContent"></param>
/// <returns></returns>
int UtilsEncryptDesEcb(unsigned char** ppEncryptData, uint64_t& nDataLen, const char* pFileContent,
                       uint64_t nContentLen)
{
    if (pFileContent == NULL || strlen(pFileContent) <= 0)
    {
        LOG_ERROR("FileContent empty!");
        return HRA_BAD_PARAM;
    }

    if (ppEncryptData == NULL || *ppEncryptData != NULL)
    {
        LOG_ERROR("ppEncryptData error!");
        return HRA_BAD_PARAM;
    }

    g_openssl_mutex.lock();
    DES_cblock key_cblock;
    memcpy(key_cblock, DECRYPTION_KEY, 8);
    DES_key_schedule key_schedule;
    DES_set_key_unchecked(&key_cblock, &key_schedule);
    // 对明文进行PKCS5填充
    if (!UtilsPadPkcs5(ppEncryptData, nDataLen, pFileContent, nContentLen))
    {
        LOG_ERROR("UtilsPadPkcs5 error!");
        if (*ppEncryptData)
        {
            free(*ppEncryptData);
            *ppEncryptData = NULL;
        }
        g_openssl_mutex.unlock();
        return HRA_FAILED;
    }

    const_DES_cblock desInput;
    DES_cblock desOutput;
    //循环加密
    for (int i = 0; i < nDataLen / sizeof(const_DES_cblock); i++)
    {
        memset(desInput, 0, sizeof(const_DES_cblock));
        memset(desOutput, 0, sizeof(DES_cblock));
        //将数据块解密后拷贝到数组中
        memcpy(desInput, *ppEncryptData + i * sizeof(const_DES_cblock), sizeof(const_DES_cblock));
        DES_ecb_encrypt(&desInput, &desOutput, &key_schedule, DES_ENCRYPT);
        memcpy(*ppEncryptData + i * sizeof(DES_cblock), desOutput, sizeof(DES_cblock));
    }
    g_openssl_mutex.unlock();
    return HRA_OK;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	字符串分割. </summary>
///
/// <remarks>	, 2021/12/18. </remarks>
///
/// <param name="strData">	   	The data. </param>
/// <param name="strDelimiter">	The delimiter. </param>
///
/// <returns>	分割后的字符串数组; </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
std::vector<std::string> UtilsStringSplit(const std::string &strData, const std::string &strDelimiter)
{
	std::vector<std::string> vStringLines;
	std::string strTemp;

	if (strData.size() == 0 || strDelimiter.size() == 0)
	{
		LOG_WARN("strData or strDelimiter is NULL.");
		return vStringLines;
	}

	int lPrePos = 0;
	int lBackPos;
	while(1)
	{
		lBackPos = strData.find(strDelimiter, lPrePos);
		if(std::string::npos == lBackPos)
		{
			break;
		}
		strTemp = strData.substr(lPrePos, lBackPos-lPrePos);
		if (strTemp.size() != 0)
		{
			vStringLines.push_back(strTemp);
		}
		lPrePos = lBackPos + strDelimiter.size();
	}
	if(lPrePos <= strData.size()-1)
	{
		vStringLines.push_back(strData.substr(lPrePos));
	}

	return vStringLines;
} 
std::vector<std::wstring> UtilsStringSplit(const std::wstring& strData, const std::wstring& strDelimiter)
{
    std::vector<std::wstring> vStringLines;
    std::wstring strTemp;

    if (strData.size() == 0 || strDelimiter.size() == 0)
    {
        LOG_WARN("strData or strDelimiter is NULL.");
        return vStringLines;
    }

    int lPrePos = 0;
    int lBackPos;
    while (1)
    {
        lBackPos = strData.find(strDelimiter, lPrePos);
        if (std::string::npos == lBackPos)
        {
            break;
        }
        strTemp = strData.substr(lPrePos, lBackPos - lPrePos);
        if (strTemp.size() != 0)
        {
            vStringLines.push_back(strTemp);
        }
        lPrePos = lBackPos + strDelimiter.size();
    }
    if (lPrePos <= strData.size() - 1)
    {
        vStringLines.push_back(strData.substr(lPrePos));
    }

    return vStringLines;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	计算文件的Sha256值. </summary>
///
/// <remarks>	, 2021/12/23. </remarks>
///
/// <param name="strFile">	The file. </param>
///
/// <returns>	A std::string. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
std::string UtilsGetFileSHA256(const std::string &strFile)
{
	//std::string strFileContent = utilsReadFileAllContent(strFile);
    unsigned char* pFileData = NULL;
    size_t nFizeSize = 0;
    if (HRA_OK != utilsReadFileAllContent(&pFileData, nFizeSize, strFile.c_str()))
    {
        if (pFileData)
        {
            free(pFileData);
            pFileData = NULL;
        }
        return "";
    }

	std::string strHash = UtilsGetBuffSHA256(pFileData, nFizeSize);
    if (pFileData)
    {
        free(pFileData);
        pFileData = NULL;
    }

    return strHash;
}


////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	计算二进制串的Sha256值. </summary>
///
/// <remarks>	, 2021/12/23. </remarks>
///
/// <param name="strInput">	The input. </param>
///
/// <returns>	A std::string. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
std::string UtilsGetBuffSHA256(const unsigned char* pDataBuff, size_t nSize)
{
    if (pDataBuff == NULL || nSize <= 0)
    {
        LOG_ERROR("PARAM NULL!");
        return "";
    }

    LOG_DEBUG("SHA256 start!");
	std::string strOutput;
	unsigned char szSHA256[32];
    g_openssl_mutex.lock();
	SHA256(pDataBuff, nSize, szSHA256);
    g_openssl_mutex.unlock();
	for (int i = 0; i < 32; i++)
	{
		char szBuf[32] = {0};
		sprintf_s(szBuf, "%02x", szSHA256[i]);
		strOutput += szBuf;
	}
    LOG_DEBUG("SHA256 end! hex:%s", strOutput.c_str());

	return strOutput;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	调用接口解压pattern压缩包. </summary>
///
/// <remarks>	, 2021/12/18. </remarks>
///
/// <param name="strZipFilePath">	Full pathname of the zip file. </param>
///
/// <returns>	解压到strZipFilePath同级目录. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
int UtilsUnzip(std::string strZipFilePath)
{
    int lRet = HRA_OK;
    unzFile pvZipFile = NULL;
    unz_global_info zGlobalInfo;
    memset(&zGlobalInfo, 0, sizeof(zGlobalInfo));
    unz_file_info zFileInfo;
    memset(&zFileInfo, 0, sizeof(zFileInfo));
    std::string strUnzipPath;
    char szSubFileName[MAX_PATH];
    memset(szSubFileName, 0, sizeof(szSubFileName));

    LOG_INFO("Zip file path:%s", strZipFilePath.c_str());

    int lIndex = strZipFilePath.rfind("\\");
    if (lIndex != std::string::npos)
    {
        strUnzipPath = strZipFilePath.substr(0, lIndex + 1); // 解压路径
    }
    else
    {
        strUnzipPath = ".";
    }

    //打开zip文件
    pvZipFile = unzOpen(strZipFilePath.c_str());
    if (NULL == pvZipFile)
    {
        char errMsg[MAX_PATH] = {0};
        strerror_s(errMsg, MAX_PATH, errno);
        LOG_ERROR("The file is not a compressed file. %d, %s", errno, errMsg);
        lRet = HRA_FAILED; // 可能不是压缩文件，不处理
        goto err;
    }

    //获取压缩文件的全局信息
    if (unzGetGlobalInfo(pvZipFile, &zGlobalInfo) != UNZ_OK)
    {
        LOG_ERROR(" Failed to obtain global information about compressed files. ");
        lRet = HRA_FAILED;
        goto err;
    }

    for (int i = 0; i < zGlobalInfo.number_entry; ++i)
    {
        //从压缩包循环获得子文件信息：文件名， 文件大小
        if (UNZ_OK != unzGetCurrentFileInfo(pvZipFile, &zFileInfo, szSubFileName, sizeof(szSubFileName), NULL, 0, NULL, 0))
        {
            LOG_ERROR(" Failed to get child file information .");
            lRet = HRA_FAILED;
            goto err;
        }

        LOG_DEBUG("Sub file name:%s", szSubFileName);
        std::string strSubFileName = szSubFileName;
        replace(strSubFileName.begin(), strSubFileName.end(), '/', '\\');
        std::string strSubFilePath = strUnzipPath + strSubFileName; // 拼接子文件路径与解压路径
        if (strSubFileName.empty())
        {
            LOG_ERROR("Sub file name empty!");
            lRet = HRA_FAILED;
            goto err;
        }

        if (strSubFileName == "." || strSubFileName == ".\\" || strSubFileName == ".." || strSubFileName == "..\\")
        {
            unzGoToNextFile(pvZipFile);
            continue;
        }
        
        // 是个文件夹
        if (strSubFileName.rfind("\\") == strSubFileName.size() - 1) 
        {
            std::string strPathTmp = strSubFilePath.substr(0, strSubFilePath.rfind("\\"));
            //判断路径是否存在，不存在则创建
            if (IsDirExist(UtilsStringToUnicode(strPathTmp).c_str()))
            {
                LOG_DEBUG("Sub dir exists! %s", strPathTmp.c_str());
                unzGoToNextFile(pvZipFile);
                continue;
            }

            if (HRA_OK != UtilsCheckCreateDir(strPathTmp.c_str()))
            {
                LOG_ERROR("CreateDirectory:%s error!, Code:%lu", strPathTmp.c_str(), GetLastError());
                lRet = HRA_FAILED;
                goto err;
            }

            LOG_DEBUG("Create sub dir succeed! %s", strPathTmp.c_str());
            unzGoToNextFile(pvZipFile);
            continue;
        }
        //是个文件
        else
        {
            std::string strPathTmp = strSubFilePath.substr(0, strSubFilePath.rfind("\\"));
            //判断父路径是否存在，不存在则创建
            if (!IsDirExist(UtilsStringToUnicode(strPathTmp).c_str()))
            {
                if (HRA_OK != UtilsCheckCreateDir(strPathTmp.c_str()))
                {
                    LOG_ERROR("CreateDirectory:%s error!, Code:%lu", strPathTmp.c_str(), GetLastError());
                    lRet = HRA_FAILED;
                    goto err;
                }
                LOG_DEBUG("Create subdir succeed! %s", strPathTmp.c_str());
            }
        }

        if (UNZ_OK != unzOpenCurrentFile(pvZipFile))
        {
            LOG_ERROR(" Failed to open the subfile. ");
            lRet = HRA_FAILED;
            goto err;
        }

        //申请内存
        int lFileLength   = zFileInfo.uncompressed_size; // 子文件长度
        char* pscFileData = (char*)malloc(lFileLength + 1);
        if (pscFileData == NULL) 
        {
            LOG_ERROR("Failed to malloc memory.");
            lRet = HRA_FAILED;
            goto err;
        }
        memset(pscFileData, 0, lFileLength + 1);

        //解压子文件
        int lUnzSubfileLen          = unzReadCurrentFile(pvZipFile, (voidp)pscFileData, lFileLength);
        if (pscFileData != NULL)
        {
            pscFileData[lUnzSubfileLen] = '\0';
        }
        LOG_DEBUG("Sub file size:%lu, unzip size:%d", zFileInfo.compressed_size, lUnzSubfileLen);

        //写入文件
        std::ofstream file(strSubFilePath.c_str(), std::ios::out | std::ios::binary);
        //if (!file.good() && errno == 2)//目录不存在
        //{
        //    std::string strSubFileParePath = strSubFilePath.substr(0, strSubFilePath.rfind("\\"));
        //    if (!IsDirExist(StringToUnicode(strSubFileParePath).c_str()))
        //    {
        //        if (!CreateDirectoryA(strSubFileParePath.c_str(), NULL))
        //        {
        //            LOG_ERROR("Failed to create sub dir. errno:%lu, %s", GetLastError(), strSubFileParePath.c_str());
        //            lRet = HRA_FAILED;
        //            unzCloseCurrentFile(pvZipFile);
        //            if (pscFileData)
        //            {
        //                free(pscFileData);
        //                pscFileData = NULL;
        //            }
        //            goto err;
        //        }
        //        LOG_DEBUG("Create subdir succeed! %s", strSubFileParePath.c_str());
        //    }
        //    //重新打开文件
        //    file.open(strSubFilePath.c_str(), std::ios::out | std::ios::binary);
        //}

        if (!file.good())
        {
            LOG_ERROR(" Failed to create sub file. errno:%d,  %s", errno, strSubFilePath.c_str());
            lRet = HRA_FAILED;
            unzCloseCurrentFile(pvZipFile);
            if (pscFileData)
            {
                free(pscFileData);
                pscFileData = NULL;
            }
            goto err;
        }
        file.seekp(0, std::ios::beg);
        if (pscFileData != NULL)
        {
            file.write(pscFileData, lUnzSubfileLen);
        }
        size_t nFileSize = file.tellp();
        file.close();
        LOG_DEBUG("Write sub file succeed! size:%llu %s", (uint64_t)nFileSize, strSubFilePath.c_str());
        unzCloseCurrentFile(pvZipFile);
        unzGoToNextFile(pvZipFile);
        if (pscFileData)
        {
            free(pscFileData);
            pscFileData = NULL;
        }
    }

    LOG_INFO("Unzip file succeed:%s", strZipFilePath.c_str());

err:
    if (pvZipFile)
    {
        unzClose(pvZipFile);
    }
    return lRet;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	寻找pattern目录下最新的压缩包. </summary>
///
/// <remarks>	, 2021/12/18. </remarks>
///
/// <param name="strPatternDir">	The pattern dir. </param>
///
/// <returns>	解压到strZipFilePath同级目录. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
std::string UtilsFindNewestPattPack(const std::string &strPatternDir)
{
	int lNewestPackNum = 0;
	std::string strNewestPackName;
	std::string strSeparator = "-b";
	_finddata_t fileinfo;
    memset(&fileinfo, 0, sizeof(fileinfo));
	std::string strFindZipFile = strPatternDir + "\\*.zip";

	intptr_t lHandle = _findfirst(strFindZipFile.c_str(), &fileinfo); //查找所有.zip文件

	if (-1 == lHandle)
	{
		printf("Cannot open the desired directory. %s", strFindZipFile.c_str());
		return "";
	}

	do
	{
		std::string strFileName = fileinfo.name;
		printf("str File Name is %s\n",strFileName.c_str());
		int lBackIndex = strFileName.rfind(".zip");
		if (std::string::npos == lBackIndex)
		{
			continue;
		}
		// 从压缩包名中提取压缩包号 如：vuln_app_p-b1.zip
		int lFront = strFileName.find(strSeparator);
		if (std::string::npos == lFront || lFront >= lBackIndex)
		{
			continue;
		}

		int lTempNum = atoi(strFileName.substr(lFront + strSeparator.size(), lBackIndex-lFront).c_str());
		if (lTempNum > lNewestPackNum)
		{
			lNewestPackNum = lTempNum;
			strNewestPackName = strFileName;
		}
	} while(0 == _findnext(lHandle, &fileinfo));
	_findclose(lHandle);
	return strNewestPackName;
}

/// <summary>
/// 删除目录下老的pattern包
/// </summary>
/// <param name="strPatternDir"></param>
/// <returns></returns>
int UtilsRemoveOldPattPack(const std::string& strPatternDir)
{
    //扫描目录下所有符合条件的文件
    WIN32_FIND_DATAA FindFileData;
    ZeroMemory(&FindFileData, sizeof(WIN32_FIND_DATAA));
    HANDLE hFind = NULL;
    int nRet     = HRA_FAILED;
    std::map<int, std::string> mapPatternFiles;
    std::string strFileFilter = strPatternDir + "\\*.zip";
    std::string strFullPath;
    std::string strVersion;
    int nVersion = 0;
    int nDeleteCount = 0;

    hFind = FindFirstFileA(strFileFilter.c_str(), &FindFileData);
    if (INVALID_HANDLE_VALUE == hFind)
    {
        LOG_ERROR("hFind INVALID! Path:%s", strFileFilter.c_str());
        goto _exit;
    }

    do
    {
        if (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            continue;
        }

        //判断文件名规则
        if (!UtilsMatchRegex("^.+-b[0-9]+\\.[Z|z][I|i][P|p]$", FindFileData.cFileName))
        {
            continue;
        }
        strVersion = FindFileData.cFileName;
        strVersion = strVersion.erase(0, strVersion.rfind("-b") + 2);//删除-b以及前面的
        strVersion = strVersion.substr(0, strVersion.length() - 4);//截取.zip前面的
        nVersion   = std::atoi(strVersion.c_str());
        strFullPath = strPatternDir + "\\" + FindFileData.cFileName;
        mapPatternFiles.insert(std::map<int, std::string>::value_type(nVersion, strFullPath));
        LOG_DEBUG("Find pattern file! version:%d, path:%s", nVersion, strFullPath.c_str());
    } while (FindNextFileA(hFind, &FindFileData) != 0);

    //删除老文件
    nDeleteCount = 0;
    for (std::map<int, std::string>::const_iterator it = mapPatternFiles.begin(); mapPatternFiles.end() != it; ++it)
    {
        if ((mapPatternFiles.size() - nDeleteCount) <= PATTERN_FILE_RESERVE_NUM)
        {
            break;
        }
        
        if (!DeleteFileA(it->second.c_str()))
        {
            LOG_ERROR("Delete file error! code:%lu, path:%s", GetLastError(), it->second.c_str());
        }
        else
        {
            LOG_INFO("Delete file succeed! path:%s", it->second.c_str());
        }
        ++nDeleteCount;
    }
    nRet = HRA_OK;

_exit:
    if (hFind && INVALID_HANDLE_VALUE != hFind)
    {
        FindClose(hFind);
        hFind = NULL;
    }

    return nRet;
}


////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	获取当前时间戳. </summary>
///
/// <remarks>	, 2022/1/5. </remarks>
///
/// <param name="parameter1">	The first parameter. </param>
///
/// <returns>	A std::string. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
std::string UtilsGetTimestamp(void)
{
	time_t t;
	char scBuff[HRA_STRING_MAX_LEN] = {0};
	std::string strTimestamp;

	t = time(NULL);
	sprintf(scBuff, "%lld", time(&t));
	strTimestamp = scBuff;

	return strTimestamp;
}

/// <summary>
/// 获取当前时间的微秒级时间戳
/// </summary>
/// <param name=""></param>
/// <returns></returns>
std::string UtilsGetMicroTimestamp(void)
{
    auto now                               = std::chrono::system_clock::now();
    auto duration                          = now.time_since_epoch();
    std::chrono::microseconds microseconds = std::chrono::duration_cast<std::chrono::microseconds>(duration);
    long long Microtimestamp               = microseconds.count();
    std::string strMicroSeconds            = std::to_string(Microtimestamp);
    return strMicroSeconds;
}

/// <summary>
/// 获取当前时间的纳秒级时间戳
/// </summary>
/// <param name=""></param>
/// <returns></returns>
std::string UtilsGetNanoTimestamp(void)
{
    auto now                             = std::chrono::system_clock::now();
    auto duration                        = now.time_since_epoch();
    std::chrono::nanoseconds nanoSeconds = std::chrono::duration_cast<std::chrono::nanoseconds>(duration);
    long long Nanotimestamp              = nanoSeconds.count();
    std::string strNanoSeconds           = std::to_string(Nanotimestamp);
    return strNanoSeconds;
}

std::string UtilsGetLocalTime(void)
{
    SYSTEMTIME st;
    GetLocalTime(&st);
    char formattedTime[20] = {0}; // 20 characters for "XXXX-XX-XX XX:XX:XX" format
    _snprintf_s(formattedTime, sizeof(formattedTime), _TRUNCATE, "%04d-%02d-%02d %02d:%02d:%02d", st.wYear, st.wMonth,
                st.wDay, st.wHour, st.wMinute, st.wSecond);
    return formattedTime;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	Utilities get server IP. </summary>
///
/// <remarks>	, 2022/2/14. </remarks>
///
/// <returns>	A std::string. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
//std::string  UtilsGetServerIp(void)
//{
//	std::string strServerIp;
//	std::string strBuff;
//	std::string strCmdResult;
//	WCHAR scCurrentPath[MAX_PATH];
//	int lIndex = 0;
//
//	//获取当前目录
//	memset(scCurrentPath, 0, sizeof(scCurrentPath));
//	DWORD dwLen = GetCurrentDirectory(MAX_PATH,scCurrentPath);
//    std::string strCurrentPath = UtilsUnicodeToString(scCurrentPath);
//    LOG_DEBUG("Current Path is :%s\n", strCurrentPath.c_str());
//
//    std::string strDsaPath = strCurrentPath + "\\..\\";
//	//切换目录到HRA的上一级，即dsa_query.cmd所在目录
//	//int _index = strDsaPath.find("HRA");
//    //strDsaPath = strDsaPath.substr(0, _index - 1);
//	LOG_DEBUG("DSA Path is :%s\n", strDsaPath.c_str());
//	chdir(strDsaPath.c_str());
//	
//	//执行命令行
//    if (ExecuteCmd(&strCmdResult , "dsa_query.cmd -c GetAgentStatus | find \"https\""))
//	{
//		//Sleep(2000);	//等待WinExec执行完成
//		//std::ifstream in_file;
//		//in_file.open("test.txt");
//
//		//while (getline(in_file, strBuff)) {
//		//	std::cout << "read file"<<strBuff<<std::endl;
//		//	strCmdResult = strBuff;}
//		//in_file.close();
//	}
//	else
//	{
//		LOG_ERROR("find no dsm url info.");
//        //system("if exist \"test.txt\" del \"test.txt\"");
//        chdir(strCurrentPath.c_str());
//		return "";
//	}
//
//	//Sleep(2000);	//等待文件操作结束
// //   system("if exist \"test.txt\" del \"test.txt\"");
//	chdir(strCurrentPath.c_str());
//	LOG_DEBUG("dsa_query.cmd result is :%s\n", strCmdResult.c_str());
//
//	//cmd执行结果为AgentStatus.dsmUrl:https://192.168.100.48:4120/
//	lIndex = strCmdResult.find_last_of(":");
//	strServerIp = strCmdResult.substr(0, lIndex);
//
//	lIndex = strServerIp.find_last_of("//");
//	strServerIp = strServerIp.substr(lIndex + 1);
//
//	return strServerIp;
//}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	Utilities get server IP. </summary>
///
/// <remarks>	 2022/9/1. </remarks>
///
/// <param name="arrIP">	[in,out] array of ip. </param>
/// <param name="arrPort">	[in,out] array of port. </param>
/// <param name="iMax">	    [in] max array length. </param>
///  
/// <returns>	int, count of IP. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
//int UtilsGetServerAddr(char (*arrIP)[_INET6_ADDRSTRLEN],char (*arrPort)[6],const int iMax)
//{
//	std::string strServerIp;
//	std::string strBuff;
//	std::string strCmdResult;
//	WCHAR scCurrentPath[MAX_PATH];
//	int lIndex = 0;
//
//	//获取当前目录
//	memset(scCurrentPath, 0, sizeof(scCurrentPath));
//	DWORD dwLen = GetCurrentDirectory(MAX_PATH, scCurrentPath);
//    std::string strCurrentPath = UtilsUnicodeToString(scCurrentPath);
//	LOG_DEBUG("Current Path is :%s\n", strCurrentPath.c_str());
//
//	std::string strDsaPath = strCurrentPath + "\\..\\";
//	//切换目录到HRA的上一级，即dsa_query.cmd所在目录
//	//int _index = strDsaPath.find("HRA");
//	//strDsaPath = strDsaPath.substr(0, _index - 1);
//	LOG_DEBUG("DSA Path is :%s\n", strDsaPath.c_str());
//	//chdir(strDsaPath.c_str());
//    std::string strCmd = strDsaPath + "dsa_query.cmd -c GetAgentStatus | find \"https\"";
//
//	//执行命令行
//    if (ExecuteCmd(&strCmdResult , strCmd.c_str()))
//	{
//		//Sleep(2000);	//等待WinExec执行完成
//		//std::ifstream in_file;
//		//in_file.open("test.txt");
//
//		//while (getline(in_file, strBuff)) {
//		//	std::cout << "read file" << strBuff << std::endl;
//		//	strCmdResult = strBuff;
//		//}
//		//in_file.close();
//	}
//	else
//	{
//		LOG_ERROR("find no dsm url info.");
//		//system("if exist \"test.txt\" del \"test.txt\"");
//		//chdir(strCurrentPath.c_str());
//		return lIndex;
//	}
//
//	//Sleep(2000);	//等待文件操作结束
//	//system("if exist \"test.txt\" del \"test.txt\"");
//	//chdir(strCurrentPath.c_str());
//	LOG_INFO("dsa_query.cmd result is :%s\n", strCmdResult.c_str());
//
//	// cmd执行结果为AgentStatus.dsmUrl:https://192.168.100.48:4120/   以逗号隔开
//	// IPv6 https://[fc00:168:100::48]:4120/
//	// ip域名 https://www.xxx.com:4120/
//
//	std::vector<std::string> vecIpPort;
//
//	if (strCmdResult.find("AgentStatus.dsmUrl:") != std::string::npos)
//	{
//		int iStatusLen = strlen("AgentStatus.dsmUrl:");
//		strCmdResult = strCmdResult.substr(iStatusLen);
//	}
//
//	vecIpPort = UtilsStringSplit(strCmdResult,  ",");
//
//	int iHeadlen = strlen("https://");
//	for (std::vector<std::string>::iterator it = vecIpPort.begin(); it != vecIpPort.end(); ++it) {
//		int iIpLen = it->length();
//		if (iIpLen > iHeadlen) {
//			if (it->find("https://") != std::string::npos)
//			{
//				std::string strServerUrl = it->substr(it->find("https://") + iHeadlen);
//				int iColIndexEnd = strServerUrl.find_last_of(':');
//				int iSlashIndexEnd = strServerUrl.find_last_of('/');
//				std::string strServerIp = strServerUrl.substr(0, iColIndexEnd);  //通过“：”分割字符串
//				// ipv6有“[]”,则去除[]
//				if (strServerIp.find_first_of('[') != std::string::npos&& strServerIp.find_first_of(']') != std::string::npos) {
//					strServerIp = strServerIp.substr(strServerIp.find_first_of('[')+ 1);
//					strServerIp = strServerIp.substr(0, strServerIp.find_first_of(']'));
//				}
//				std::string strServerPort = strServerUrl.substr(iColIndexEnd + 1, iSlashIndexEnd - 1 - iColIndexEnd);
//				strncpy_s((char*)(arrIP + lIndex), _INET6_ADDRSTRLEN, strServerIp.c_str(), strServerIp.length());
//				strncpy_s((char*)(arrPort + lIndex), 6, strServerPort.c_str(), strServerPort.length());
//				lIndex++;
//				LOG_INFO("the value of ServerIp and Port is : %s,%s", strServerIp.c_str(), strServerPort.c_str());
//
//				// 最长读取个数，数组访问安全
//				if (lIndex == iMax)
//				{
//					break;
//				}
//			}
//		}
//	}
//
//	return lIndex;
//}


void UtilsPasswdFuzz(std::string& strPasswd)
{
    if (strPasswd.empty())
    {
        strPasswd = "******";
        return;
    }

    //为了防止密码中有中文，所以转换wstring
    std::wstring strTmp = UtilsStringToUnicode(strPasswd);
    if (strTmp.empty())
    {
        strPasswd = "******";
        return;
    }
    wchar_t cHead  = strTmp.at(0);
    wchar_t cTail  = strTmp.at(strTmp.length() - 1);
    strTmp = cHead;
    strTmp += L"****";
    strTmp += cTail;
    strPasswd = UtilsUnicodeToString(strTmp);
}

/// <summary>
/// 删除目录，包括目录下的所有文件
/// </summary>
/// <param name="DirName"></param>
/// <returns></returns>
bool UtilsRemoveDirectory(const wchar_t* DirName)
{
    if (DirName == NULL)
    {
        LOG_ERROR("DirName NULL!");
        return false;
    }

    std::wstring strFileFilter;
    strFileFilter = DirName;
    strFileFilter += L"\\*";

    WIN32_FIND_DATA FindFileData;
    ZeroMemory(&FindFileData, sizeof(WIN32_FIND_DATA));

    HANDLE hFind = FindFirstFile(strFileFilter.c_str(), &FindFileData);
    if (INVALID_HANDLE_VALUE == hFind)
    {
        LOG_ERROR("hFind INVALID! Path:%s", UtilsUnicodeToString(strFileFilter).c_str());
        return false;
    }

    do
    {
        std::wstring strFileName = L"";
        strFileName              = strFileName + DirName + L"\\" + FindFileData.cFileName;
        if (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            if ((wcscmp(FindFileData.cFileName, L".") != 0) &&
                (wcscmp(FindFileData.cFileName, L"..") != 0)) //如果不是"." ".."目录
            {
                UtilsRemoveDirectory(strFileName.c_str());
            }
        }
        else
        {
            if (!DeleteFile(strFileName.c_str()))
            {
                LOG_ERROR("DeleteFile:%s error! Code:%lu", UtilsUnicodeToString(strFileName).c_str(), GetLastError());
                return false;
            }
            LOG_DEBUG("DeleteFile:%s succeed!", UtilsUnicodeToString(strFileName).c_str());
        }

    } while (FindNextFile(hFind, &FindFileData) != 0);

    FindClose(hFind);

    if (!RemoveDirectory(DirName)) //删除目录
    {
        LOG_ERROR("RemoveDirectory:%s error! Code:%lu", UtilsUnicodeToString(DirName).c_str(), GetLastError());
        return false;
    }

    LOG_DEBUG("RemoveDirectory:%s succeed!", UtilsUnicodeToString(DirName).c_str());
    return true;
}

/// <summary>
/// 拷贝文件夹下的所有文件，目标目录不存在会自动创建
/// </summary>
/// <param name="pszSrcDir"></param>
/// <param name="pszDesDir"></param>
/// <returns></returns>
bool UtilsCopyDirFiles(const wchar_t* pszSrcDir, const wchar_t* pszDesDir)
{
    if (pszSrcDir == NULL || pszDesDir == NULL)
    {
        LOG_ERROR("Param NULL!");
        return false;
    }

    if (!IsDirExist(pszDesDir))
    {
        if (!CreateDirectory(pszDesDir, NULL))
        {
            LOG_ERROR("Create dir:%s error! Code:%lu", UtilsUnicodeToString(pszDesDir).c_str(), GetLastError());
            return false;
        }
    }

    std::wstring strFileFilter;
    strFileFilter = pszSrcDir;
    strFileFilter += L"\\*";

    WIN32_FIND_DATA FindFileData;
    ZeroMemory(&FindFileData, sizeof(WIN32_FIND_DATA));

    HANDLE hFind = FindFirstFile(strFileFilter.c_str(), &FindFileData);
    if (INVALID_HANDLE_VALUE == hFind)
    {
        LOG_ERROR("hFind INVALID! Path:%s", UtilsUnicodeToString(strFileFilter).c_str());
        return false;
    }

    bool bret = true;
    do
    {
        std::wstring strFileName = L"";
        strFileName              = strFileName + pszSrcDir + L"\\" + FindFileData.cFileName;
        wchar_t szDesSub[MAX_PATH];
        ZeroMemory(szDesSub, sizeof(szDesSub));
        _snwprintf_s(szDesSub, sizeof(szDesSub) / sizeof(wchar_t), L"%ls\\%ls", pszDesDir, FindFileData.cFileName);

        if (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            if ((wcscmp(FindFileData.cFileName, L".") != 0) &&
                (wcscmp(FindFileData.cFileName, L"..") != 0)) //如果不是"." ".."目录
            {
                bret = UtilsCopyDirFiles(strFileName.c_str(), szDesSub);
                if (!bret)
                {
                    break;
                }
            }
        }
        else
        {
            if (!CopyFile(strFileName.c_str(), szDesSub, FALSE))
            {
                LOG_ERROR("CopyFile:%s-->%s error! Code:%lu", UtilsUnicodeToString(strFileName).c_str(),
                          UtilsUnicodeToString(szDesSub).c_str(), GetLastError());
                bret = false;
                break;
            }
            LOG_DEBUG("CopyFile:%s-->%s succeed!", UtilsUnicodeToString(strFileName).c_str(),
                     UtilsUnicodeToString(szDesSub).c_str());
        }
    } while (FindNextFile(hFind, &FindFileData) != 0);

    FindClose(hFind);
    if (bret)
    {
        LOG_INFO("Copy dir succeed! %s-->%s", UtilsUnicodeToString(pszSrcDir).c_str(),
                 UtilsUnicodeToString(pszDesDir).c_str());
    }
    else
    {
        LOG_ERROR("Copy dir failed! %s-->%s", UtilsUnicodeToString(pszSrcDir).c_str(),
                 UtilsUnicodeToString(pszDesDir).c_str());
    }
    return bret;
}

/// <summary>
/// 判断文件夹是否存在
/// </summary>
/// <param name="pszDirectory"></param>
/// <returns></returns>
bool IsDirExist(const wchar_t* pszDirectory)
{
    DWORD dwAttributes = ::GetFileAttributes(pszDirectory);
    bool f             = (0xffffffff != dwAttributes) && (FILE_ATTRIBUTE_DIRECTORY & dwAttributes);
    return f;
}

/// <summary>
/// 判断文件是否存在
/// </summary>
/// <param name="pszFilePath"></param>
/// <returns></returns>
bool UtilsIsFileExist(const wchar_t* pszFilePath)
{
    DWORD dwAttributes = ::GetFileAttributes(pszFilePath);
    bool f             = (INVALID_FILE_ATTRIBUTES != dwAttributes) && !(FILE_ATTRIBUTE_DIRECTORY & dwAttributes);
    return f;
}

/// <summary>
/// 拼接文件路径
/// </summary>
/// <param name="path1"></param>
/// <param name="path2"></param>
/// <returns></returns>
std::wstring UtilsAppendFilePath(std::wstring path1, const WCHAR* path2)
{
    WCHAR tmpPath[MAX_PATH] = { 0 };
    memcpy_s(tmpPath, MAX_PATH * sizeof(WCHAR), path1.c_str(), path1.length() * sizeof(WCHAR));
    PathAppendW(tmpPath, path2);
    return tmpPath;
}

/// <summary>
/// 获取目录里的所有子文件
/// </summary>
/// <param name="dir"></param>
/// <param name="key"></param>
/// <param name="subDir"></param>
/// <param name="maxLevel"></param>
/// <returns></returns>
void UtilsGetSubFileInDir(std::wstring dir, std::list<std::wstring>& subFiles)
{
    WIN32_FIND_DATAW wfd;
    ::ZeroMemory(&wfd, sizeof(wfd));
    HANDLE hFile = ::FindFirstFileW(UtilsAppendFilePath(dir, L"*.*").c_str(), &wfd);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        return;
    }

    do
    {
        if (wfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            continue;
        }
        if (_tcscmp(wfd.cFileName, _T(".")) == 0 || _tcscmp(wfd.cFileName, _T("..")) == 0)
        {
            continue;
        }

        std::wstring wstrFileName = wfd.cFileName;
        subFiles.push_back(UtilsAppendFilePath(dir, wfd.cFileName));
    } while (::FindNextFileW(hFile, &wfd));
    ::FindClose(hFile);
    return;
}

/// <summary>
/// 去除首字符串
/// </summary>
/// <param name="strString"></param>
/// <param name="pszTrim"></param>
/// <returns></returns>
std::string& UtilsLTrim(std::string& strString, const char* pszTrim)
{
    if (pszTrim == NULL || strlen(pszTrim) <= 0)
    {
        while (!strString.empty())
        {
            if (!isspace(strString.at(0)))
            {
                break;
            }
            strString = strString.erase(0, 1);
        }
    }
    else
    {
        while (!strString.empty())
        {
            size_t nPos = strString.find(pszTrim);
            if (nPos != 0 || nPos == std::string::npos)
            {
                break;
            }
            strString = strString.erase(nPos, strlen(pszTrim));
        }
    }

    return strString;
}

/// <summary>
/// 去除尾字符串
/// </summary>
/// <param name="strString"></param>
/// <param name="pszTrim"></param>
/// <returns></returns>
std::string& UtilsRTrim(std::string& strString, const char* pszTrim)
{
    if (pszTrim == NULL || strlen(pszTrim) <= 0)
    {
        while (!strString.empty())
        {
            if (!isspace(strString.at(strString.length() - 1)))
            {
                break;
            }
            strString = strString.erase(strString.length() - 1, 1);
        }
    }
    else
    {
        while (!strString.empty())
        {
            size_t nPos = strString.rfind(pszTrim);
            if (nPos != (strString.length() - strlen(pszTrim)) || nPos == std::string::npos)
            {
                break;
            }
            strString = strString.erase(nPos, strlen(pszTrim));
        }
    }

    return strString;
}

/// <summary>
/// 去除首尾字符串
/// </summary>
/// <param name="pszString"></param>
/// <param name="pszTrim"></param>
/// <returns></returns>
std::string& UtilsTrim(std::string& strString, const char* pszTrim)
{
    UtilsLTrim(strString, pszTrim);
    UtilsRTrim(strString, pszTrim);
    return strString;
}

/// <summary>
/// 转大写
/// </summary>
/// <param name="strString"></param>
/// <returns></returns>
std::string& UtilsToUpper(std::string& strString)
{
    for (std::string::size_type i = 0; i < strString.size(); ++i)
    {
        strString[i] = toupper(strString[i]);
    }
    return strString;
}

/// <summary>
/// 转小写
/// </summary>
/// <param name="strString"></param>
/// <returns></returns>
std::string& UtilsToLower(std::string& strString)
{
    for (std::string::size_type i = 0; i < strString.size(); ++i)
    {
        strString[i] = tolower(strString[i]);
    }
    return strString;
}

/// <summary>
/// 从参数字符串中获取指定key的参数
/// </summary>
/// <param name="strValue"></param>
/// <param name="strKey"></param>
/// <param name="strCmd"></param>
/// <returns></returns>
bool UtilsGetParam(std::string& strValue, const std::string& strKey, const std::string& strCmd)
{
    std::string strCmdTmp = strCmd;
    std::string strFind   = HRA_PARAM_START + strKey + " ";
    size_t nPos           = strCmdTmp.find(strFind);
    if (nPos == std::string::npos)
    {
        return false;
    }

    strValue.clear();
    strCmdTmp = strCmdTmp.erase(0, nPos + strFind.length());
    nPos      = strCmdTmp.find(HRA_PARAM_START);
    if (nPos != std::string::npos)
    {
        strValue = strCmdTmp.substr(0, nPos);
    }
    else
    {
        strValue = strCmdTmp;
    }
    UtilsTrim(strValue);

    return true;
}

/// <summary>
/// 获取ProgramData系统路径
/// </summary>
/// <returns></returns>
int UtilsGetProgramDataDir(char* pDirBuff, size_t nBuffSize)
{
    if (!pDirBuff || nBuffSize <= 0)
    {
        return HRA_BAD_PARAM;
    }
    char szDirTmp[MAX_PATH];
    memset(szDirTmp, 0, sizeof(szDirTmp));
    HRESULT hr  = SHGetFolderPathA(NULL, CSIDL_COMMON_APPDATA, NULL, 0, szDirTmp);
    if (hr != S_OK)
    {
        return HRA_FAILED;
    }

    _snprintf_s(pDirBuff, nBuffSize, nBuffSize - 1, "%s", szDirTmp);
    return HRA_OK;
}

/// <summary>
/// 判断并创建目录，可创建多级目录
/// </summary>
/// <param name="strDir"></param>
/// <returns></returns>
int UtilsCheckCreateDir(const std::string& strDir)
{
    if (strDir.empty())
    {
        return HRA_BAD_PARAM;
    }

    int ret            = HRA_OK;
    std::string strTmp = strDir;
    if (strTmp.at(strTmp.length() - 1) != '\\')
    {
        strTmp += '\\';
    }

    if (!MakeSureDirectoryPathExists(strTmp.c_str()))
    {
        ret = HRA_FAILED;
    }

    return ret;
}

/// <summary>
/// 获取INI文件的配置值
/// </summary>
/// <param name="strValue"></param>
/// <param name="strFilePath"></param>
/// <param name="strSection"></param>
/// <param name="strKey"></param>
/// <returns></returns>
std::string UtilsGetIniValue(const std::string& strFilePath, const std::string& strSection, const std::string& strKey)
{
    if (strFilePath.empty() || strSection.empty() || strKey.empty())
    {
        return "";
    }

    char szValue[2048];
    memset(szValue, 0, sizeof(szValue));
    DWORD nRet = GetPrivateProfileStringA(strSection.c_str(), strKey.c_str(), "", szValue, sizeof(szValue),
                                          strFilePath.c_str());
    return szValue;
}

bool UtilsMatchRegex(const char* rx, const char* pszContext)
{
    bool bRet = false;
    std::regex regPattern(rx);
    std::cmatch match_res;

    bRet = std::regex_search(pszContext, match_res, regPattern);
    return bRet;
}

std::wstring GetRegRootKeyString(HKEY hRoot)
{
    if (hRoot == HKEY_CLASSES_ROOT)
    {
        return L"HKEY_CLASSES_ROOT";
    }
    else if (hRoot == HKEY_CURRENT_USER)
    {
        return L"HKEY_CURRENT_USER";
    }
    else if (hRoot == HKEY_LOCAL_MACHINE)
    {
        return L"HKEY_LOCAL_MACHINE";
    }
    else if (hRoot == HKEY_USERS)
    {
        return L"HKEY_USERS";
    }
    else if (hRoot == HKEY_PERFORMANCE_DATA)
    {
        return L"HKEY_PERFORMANCE_DATA";
    }
    else if (hRoot == HKEY_PERFORMANCE_TEXT)
    {
        return L"HKEY_PERFORMANCE_TEXT";
    }
    else if (hRoot == HKEY_PERFORMANCE_NLSTEXT)
    {
        return L"HKEY_PERFORMANCE_NLSTEXT";
    }
    else if (hRoot == HKEY_CURRENT_CONFIG)
    {
        return L"HKEY_CURRENT_CONFIG";
    }
    else if (hRoot == HKEY_DYN_DATA)
    {
        return L"HKEY_DYN_DATA";
    }
    else if (hRoot == HKEY_CURRENT_USER_LOCAL_SETTINGS)
    {
        return L"HKEY_CURRENT_USER_LOCAL_SETTINGS";
    }
    else
    {
        return L"";
    }
}


// 函数定义
std::string UtilsUnicodeToString(const std::wstring& src, unsigned int iCodePage)
{
    int iTextLen       = WideCharToMultiByte(iCodePage, 0, src.c_str(), -1, NULL, 0, NULL, NULL);
    char* pElementText = new char[iTextLen + 1];
    memset((void*)pElementText, 0, sizeof(char) * (iTextLen + 1));
    ::WideCharToMultiByte(iCodePage, 0, src.c_str(), -1, pElementText, iTextLen, NULL, NULL);
    std::string strText(pElementText);
    delete[] pElementText;
    return strText;
}

std::string UtilsUnicodeToString(const wchar_t* src, unsigned int iCodePage)
{
    int iTextLen       = WideCharToMultiByte(iCodePage, 0, src, -1, NULL, 0, NULL, NULL);
    char* pElementText = new char[iTextLen + 1];
    memset((void*)pElementText, 0, sizeof(char) * (iTextLen + 1));
    ::WideCharToMultiByte(iCodePage, 0, src, -1, pElementText, iTextLen, NULL, NULL);
    std::string strText(pElementText);
    delete[] pElementText;
    return strText;
}

std::wstring UtilsStringToUnicode(const std::string& src, unsigned int iCodePage)
{
    int unicodeLen    = ::MultiByteToWideChar(iCodePage, 0, src.c_str(), -1, NULL, 0);
    wchar_t* pUnicode = new wchar_t[unicodeLen + 1];
    memset(pUnicode, 0, (unicodeLen + 1) * sizeof(wchar_t));
    ::MultiByteToWideChar(iCodePage, 0, src.c_str(), -1, (LPWSTR)pUnicode, unicodeLen);
    std::wstring rt(pUnicode);
    delete[] pUnicode;
    return rt;
}

std::wstring UtilsStringToUnicode(const char* src, unsigned int iCodePage)
{
    int unicodeLen    = ::MultiByteToWideChar(iCodePage, 0, src, -1, NULL, 0);
    wchar_t* pUnicode = new wchar_t[unicodeLen + 1];
    memset(pUnicode, 0, (unicodeLen + 1) * sizeof(wchar_t));
    ::MultiByteToWideChar(iCodePage, 0, src, -1, (LPWSTR)pUnicode, unicodeLen);
    std::wstring rt(pUnicode);
    delete[] pUnicode;
    return rt;
}

std::string UtilsAiiscToUtf8(const char* strAnsiA)
{
#ifdef _WIN32
    int len = MultiByteToWideChar(CP_ACP, 0, strAnsiA, -1, NULL, 0);
    if (len <= 0)
    {
        return "";
    }
    unsigned short* wszUtf8 = (unsigned short*)malloc((len + 1) * sizeof(unsigned short));
    memset(wszUtf8, 0, (len + 1) * sizeof(unsigned short));
    MultiByteToWideChar(CP_ACP, 0, strAnsiA, -1, (LPWSTR)wszUtf8, len);
    len = WideCharToMultiByte(CP_UTF8, 0, (LPCWSTR)wszUtf8, -1, NULL, 0, NULL, NULL);
    if (len <= 0)
    {
        if (wszUtf8 != NULL)
        {
            free(wszUtf8);
            wszUtf8 = NULL;
        }
        return "";
    }
    char* szUtf8 = (char*)malloc((len + 1) * sizeof(char));
    memset(szUtf8, 0, (len + 1) * sizeof(char));
    WideCharToMultiByte(CP_UTF8, 0, (LPCWSTR)wszUtf8, -1, (LPSTR)szUtf8, len, NULL, NULL);
    std::string strUtf8(szUtf8);
    if (wszUtf8 != NULL)
    {
        free(wszUtf8);
        wszUtf8 = NULL;
    }
    if (szUtf8 != NULL)
    {
        free(szUtf8);
        szUtf8 = NULL;
    }
    return strUtf8;
#else
    std::string strUtf8(strAnsiA);
    return strUtf8;
#endif
}

std::string UtilsUtf8ToAiisc(const char* strUtf8A)
{
#ifdef _WIN32
    int len = MultiByteToWideChar(CP_UTF8, 0, strUtf8A, -1, NULL, 0);
    if (len <= 0)
    {
        return "";
    }
    unsigned short* wszUtf8 = (unsigned short*)malloc((len + 1) * sizeof(unsigned short));
    memset(wszUtf8, 0, (len + 1) * sizeof(unsigned short));
    MultiByteToWideChar(CP_UTF8, 0, strUtf8A, -1, (LPWSTR)wszUtf8, len);
    len = WideCharToMultiByte(CP_ACP, 0, (LPCWSTR)wszUtf8, -1, NULL, 0, NULL, NULL);
    if (len <= 0)
    {
        if (wszUtf8 != NULL)
        {
            free(wszUtf8);
            wszUtf8 = NULL;
        }
        return "";
    }
    char* szUtf8 = (char*)malloc((len + 1) * sizeof(char));
    memset(szUtf8, 0, (len + 1) * sizeof(char));
    WideCharToMultiByte(CP_ACP, 0, (LPCWSTR)wszUtf8, -1, (LPSTR)szUtf8, len, NULL, NULL);
    std::string strUtf8(szUtf8);
    if (wszUtf8 != NULL)
    {
        free(wszUtf8);
        wszUtf8 = NULL;
    }
    if (szUtf8 != NULL)
    {
        free(szUtf8);
        szUtf8 = NULL;
    }
    return strUtf8;
#else
    std::string strAnsi(strUtf8A);
    return strAnsi;
#endif
}

int UtilsGetFileProperty(UtilsFileProperty& stProperty, const std::wstring& strFilePath)
{
    LOGW_DEBUG(L"UtilsGetFileProperty, file_path:%s", strFilePath.c_str());

    int iRet = HRA_FAILED;
    unsigned char* pBuff = NULL;
    DWORD dwHandle       = 0;
    DWORD dwSize         = GetFileVersionInfoSizeExW(FILE_VER_GET_NEUTRAL, strFilePath.c_str(), &dwHandle);
    if (dwSize <= 0)
    {
        LOGW_WARN(L"GetFileVersionInfoSizeExW error:%lu! path:%s", GetLastError(), strFilePath.c_str());
        goto _exit;
    }

    pBuff = (unsigned char*)malloc(dwSize);
    if (pBuff == NULL)
    {
        LOGW_WARN(L"malloc error! path:%s", strFilePath.c_str());
        goto _exit;
    }
    memset(pBuff, 0, dwSize);

    if (!GetFileVersionInfoExW(FILE_VER_GET_NEUTRAL, strFilePath.c_str(), 0, dwSize, pBuff))
    {
        LOGW_WARN(L"GetFileVersionInfoExW error:%lu! path:%s", GetLastError(), strFilePath.c_str());
        goto _exit;
    }

    // Retrieve the language and code page information
    wchar_t szKeyTmp[MAX_PATH] = {0};
    _snwprintf_s(szKeyTmp, MAX_PATH, L"%s", L"\\VarFileInfo\\Translation");
    UINT uiLen    = 0;
    LPVOID lpData = NULL;
    if (!VerQueryValueW(pBuff, szKeyTmp, &lpData, &uiLen) || uiLen < sizeof(DWORD))
    {
        LOGW_WARN(L"VerQueryValueW error:%lu! key:%s, path:%s", GetLastError(), szKeyTmp, strFilePath.c_str());
        goto _exit;
    }
    if (lpData == NULL)
    {
        LOGW_WARN(L"VerQueryValueW error:%lu! key:%s, path:%s", GetLastError(), szKeyTmp, strFilePath.c_str());
        goto _exit;
    }
    DWORD* pLangCodePage = (DWORD*)lpData;
    DWORD dwLangCharset  = MAKELONG(HIWORD(pLangCodePage[0]), LOWORD(pLangCodePage[0]));

    stProperty.clear();
    stProperty.strFilePath       = strFilePath;
    stProperty.strCompanyName    = UtilsGetFilePropertySub(pBuff, L"CompanyName", dwLangCharset);
    stProperty.strFileVersion    = UtilsGetFilePropertySub(pBuff, L"FileVersion", dwLangCharset);
    stProperty.strProductName    = UtilsGetFilePropertySub(pBuff, L"ProductName", dwLangCharset);
    stProperty.strProductVersion = UtilsGetFilePropertySub(pBuff, L"ProductVersion", dwLangCharset);
    stProperty.strFileDescription = UtilsGetFilePropertySub(pBuff, L"FileDescription", dwLangCharset);
    
    iRet = HRA_OK;

_exit:
    if (pBuff)
    {
        free(pBuff);
        pBuff = NULL;
    }
    return iRet;
}

std::wstring UtilsGetFileProperty(const std::wstring& strPropertyKey, const std::wstring& strFilePath)
{
    std::wstring strReturn;
    unsigned char* pBuff = NULL;
    DWORD dwHandle = 0;
    DWORD dwSize   = GetFileVersionInfoSizeExW(FILE_VER_GET_NEUTRAL, strFilePath.c_str(), &dwHandle);
    if (dwSize <= 0)
    {
        LOGW_WARN(L"GetFileVersionInfoSizeExW error:%lu! key:%s, path:%s", GetLastError(), strPropertyKey.c_str(),
                   strFilePath.c_str());
        goto _exit;
    }

    pBuff = (unsigned char*)malloc(dwSize);
    if (pBuff == NULL)
    {
        LOGW_WARN(L"malloc error! key:%s, path:%s", strPropertyKey.c_str(), strFilePath.c_str());
        goto _exit;
    }
    memset(pBuff, 0, dwSize);

    if (!GetFileVersionInfoExW(FILE_VER_GET_NEUTRAL, strFilePath.c_str(), 0, dwSize, pBuff))
    {
        LOGW_WARN(L"GetFileVersionInfoExW error:%lu! key:%s, path:%s", GetLastError(), strPropertyKey.c_str(),
                   strFilePath.c_str());
        goto _exit;
    }

    // Retrieve the language and code page information
    wchar_t szKeyTmp[MAX_PATH] = {0};
    _snwprintf_s(szKeyTmp, MAX_PATH, L"%s", L"\\VarFileInfo\\Translation");
    UINT uiLen    = 0;
    LPVOID lpData = NULL;
    if (!VerQueryValueW(pBuff, szKeyTmp, &lpData, &uiLen) || uiLen < sizeof(DWORD))
    {
        LOGW_WARN(L"VerQueryValueW error:%lu! key:%s, path:%s", GetLastError(), szKeyTmp, strFilePath.c_str());
        goto _exit;
    }
    if (lpData == NULL)
    {
        LOGW_WARN(L"VerQueryValueW error:%lu! key:%s, path:%s", GetLastError(), szKeyTmp, strFilePath.c_str());
        goto _exit;
    }
    DWORD* pLangCodePage = (DWORD*)lpData;
    DWORD dwLangCharset = MAKELONG(HIWORD(pLangCodePage[0]), LOWORD(pLangCodePage[0]));

    strReturn = UtilsGetFilePropertySub(pBuff, strPropertyKey.c_str(), dwLangCharset);

_exit:
    if (pBuff)
    {
        free(pBuff);
        pBuff = NULL;
    }
    return strReturn;
}

std::wstring UtilsGetFilePropertySub(LPCVOID pBuff, LPCWSTR pKeyName, DWORD dwLangCodePage)
{
    wchar_t szKeyTmp[MAX_PATH] = {0};
    LPVOID lpValue             = NULL;
    UINT uiLen                 = 0;
    std::wstring strReturn;

    if (pBuff == NULL || pKeyName == NULL || wcslen(pKeyName) <= 0 || dwLangCodePage <= 0)
    {
        LOGW_ERROR(L"UtilsGetFilePropertySub param null!");
        goto _exit;
    }

    if (wcscmp(pKeyName, L"FileVersion") == 0)
    {
        VS_FIXEDFILEINFO* pVsInfo = NULL;
        _snwprintf_s(szKeyTmp, MAX_PATH, L"\\");
        if (VerQueryValueW(pBuff, szKeyTmp, (void**)&pVsInfo, &uiLen) && pVsInfo != NULL)
        {
            wchar_t szVersion[MAX_PATH] = {0};
            _snwprintf_s(szVersion, MAX_PATH, L"%d.%d.%d.%d", HIWORD(pVsInfo->dwFileVersionMS),
                         LOWORD(pVsInfo->dwFileVersionMS), HIWORD(pVsInfo->dwFileVersionLS),
                         LOWORD(pVsInfo->dwFileVersionLS));
            strReturn = szVersion;
            goto _exit;
        }
    }

    _snwprintf_s(szKeyTmp, MAX_PATH, L"\\StringFileInfo\\%08lx\\%s", dwLangCodePage, pKeyName);
    if (VerQueryValueW(pBuff, szKeyTmp, &lpValue, &uiLen) && lpValue != NULL)
    {
        strReturn = (wchar_t*)lpValue;
        goto _exit;
    }
    LOGW_DEBUG(L"VerQueryValueW failed! key:%s, code:%lu", szKeyTmp, GetLastError());

    //在尝试一次U.S. English
    _snwprintf_s(szKeyTmp, MAX_PATH, L"\\StringFileInfo\\040904b0\\%s", pKeyName);
    if (VerQueryValueW(pBuff, szKeyTmp, &lpValue, &uiLen) && lpValue != NULL)
    {
        strReturn = (wchar_t*)lpValue;
        goto _exit;
    }
    LOGW_DEBUG(L"VerQueryValueW failed! key:%s, code:%lu", szKeyTmp, GetLastError());

    //在尝试一次中文
    _snwprintf_s(szKeyTmp, MAX_PATH, L"\\StringFileInfo\\080404b0\\%s", pKeyName);
    if (VerQueryValueW(pBuff, szKeyTmp, &lpValue, &uiLen) && lpValue != NULL)
    {
        strReturn = (wchar_t*)lpValue;
        goto _exit;
    }
    LOGW_DEBUG(L"VerQueryValueW failed! key:%s, code:%lu", szKeyTmp, GetLastError());

_exit:
    if (lpValue != NULL)
    {
        strReturn = (wchar_t*)lpValue;
    }
    for (std::wstring::size_type nPos = 0; nPos < strReturn.length(); ++nPos)
    {
        if (strReturn[nPos] == L'"')
        {
            strReturn[nPos] = L' ';
        }
    }
    //strReturn = UtilsReplaceTrendInfo(strReturn);
    return UtilsReplaceTrendInfo(strReturn);
}

std::wstring& UtilsReplaceTrendInfo(std::wstring& strString)
{
    if (strString.empty())
    {
        return strString;
    }

    strString = UtilsReplaceString(strString, L"trend_company_name", L"Asiainfo Security", false);
    strString = UtilsReplaceString(strString, L"trend_product_name", L"Asiainfo Security", false);
    strString = UtilsReplaceString(strString, L"Trend Micro inc.", L"Asiainfo Security", false);
    strString = UtilsReplaceString(strString, L"Trend Micro", L"Asiainfo Security", false);
    return strString;
}

std::wstring& UtilsReplaceString(std::wstring& strString, const std::wstring& strOld,
                                                    const std::wstring& strNew, bool bCaseSensitive)
{
    if (strString.empty() || strOld.empty())
    {
        return strString;
    }

    if (bCaseSensitive)
    {
        for (std::wstring::size_type pos = 0; pos != std::wstring::npos; pos += strNew.length())
        {
            if ((pos = strString.find(strOld, pos)) != std::string::npos)
            {
                strString.replace(pos, strOld.length(), strNew);
            }
            else
            {
                break;
            }
                
        }
        return strString;
    }
    else
    {
        std::wstring strStringLower = strString;
        std::transform(strStringLower.begin(), strStringLower.end(), strStringLower.begin(), ::towlower);
        std::wstring strOldLower = strOld;
        std::transform(strOldLower.begin(), strOldLower.end(), strOldLower.begin(), ::towlower);
        std::wstring strNewLower = strNew;
        std::transform(strNewLower.begin(), strNewLower.end(), strNewLower.begin(), ::towlower);

        for (std::wstring::size_type pos = 0; pos != std::wstring::npos; pos += strNewLower.length())
        {
            if ((pos = strStringLower.find(strOldLower, pos)) != std::string::npos)
            {
                strStringLower.replace(pos, strOldLower.length(), strNewLower);
                strString.replace(pos, strOld.length(), strNew);
            }
            else
            {
                break;
            }
        }
        return strString;
    }
}
/*****************************************************************
 * DESCRIPTION: UtilsReplaceAll
 *     替换字符串中所有符合条件的字符
 * INPUTS:
 *     srcStr ：待替换字符串
 *     oldStr : 待匹配字符串
 *     newStr ：替换之后的字符串
 * OUTPUTS:
 *
 * RETURNS:
 *     替换后的字符串
 * CAUTIONS:
 *
 *****************************************************************/
std::string UtilsReplaceAll(std::string srcStr, const std::string& oldStr, const std::string& newStr)
{
    size_t startPos = 0;
    while ((startPos = srcStr.find(oldStr, startPos)) != std::string::npos)
    {
        srcStr.replace(startPos, oldStr.length(), newStr);
        startPos += newStr.length();
    }
    return srcStr;
}
 

// 读取写入hra注册表项中的指定路径
std::string UtilsGetRegDataPath(const std::string& strSrvName)
{
    wchar_t wszHraKey[MAX_PATH] = {0};
    _snwprintf_s(wszHraKey, MAX_PATH, L"%ls\\%ls", REG_HRA_SERVICE_REGISTRY_KEY,
                 UtilsStringToUnicode(strSrvName).c_str());
    HKEY hKey;
    if (ERROR_SUCCESS != RegOpenKeyExW(HKEY_LOCAL_MACHINE, wszHraKey, 0, KEY_READ, &hKey))
    {
        return "";
    }
    WCHAR wszValue[MAX_PATH] = {0};
    DWORD dwType             = 2;
    DWORD dwLen              = MAX_PATH;
    if (ERROR_SUCCESS != RegQueryValueExW(hKey, REG_HRA_DATA_DIR, NULL, &dwType, (LPBYTE)wszValue, &dwLen))
    {
        RegCloseKey(hKey);
        return "";
    }
    char szBUffer[MAX_PATH] = {0};
    WideCharToMultiByte(CP_UTF8, 0, wszValue, -1, szBUffer, MAX_PATH, NULL, NULL);
    PathAddBackslashA(szBUffer);
    RegCloseKey(hKey);
    return szBUffer;
}

bool ExecuteCommand(std::string& strResult, unsigned int uStdType, const char* szFormat, ...)
{
    char szCmd[MAX_COMD_BUFF_LEN];
    memset(szCmd, 0, sizeof(szCmd));
    va_list args;
    va_start(args, szFormat);
    int len = vsnprintf(szCmd, MAX_COMD_BUFF_LEN - 1, szFormat, args);
    va_end(args);

    // 创建匿名管道
    SECURITY_ATTRIBUTES saAttr;
    saAttr.nLength              = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle       = TRUE;
    saAttr.lpSecurityDescriptor = NULL;

    HANDLE hReadPipe, hWritePipe;
    if (!CreatePipe(&hReadPipe, &hWritePipe, &saAttr, 0))
    {
        LOG_ERROR("ExecuteCommand Error creating pipe, errorCode:%lu.", GetLastError());
        return false;
    }

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(STARTUPINFO));
    si.cb = sizeof(STARTUPINFO);
    if (uStdType == 2)
    { // 关联标准错误
        si.hStdError = hWritePipe;
    }
    else
    { // 关联标准输出
        si.hStdOutput = hWritePipe;
    }
    si.dwFlags |= STARTF_USESTDHANDLES;

    LOG_INFO("ExecuteCommand current commnadLine:[%s].", szCmd);
    if (!CreateProcessA(NULL, szCmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi))
    {
        LOG_ERROR("ExecuteCommand Error creating process. errorCode:%lu.", GetLastError());
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        return false;
    }
    // 关闭写入端
    CloseHandle(hWritePipe);

    // 读取管道输出
    strResult.clear();
    char buffer[128]   = {0};
    DWORD bytesRead    = 0;
    while (::ReadFile(hReadPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead != 0)
    {
        buffer[bytesRead] = '\0';
        strResult.append(buffer);
    }

    // 关闭管道和进程句柄
    CloseHandle(hReadPipe);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    LOG_INFO("Data obtained in this execution:[%s].", strResult.c_str());
    return true;
}

bool RefreshProcessEnvBlock()
{
    HKEY hKey;
    DWORD dwRet             = ERROR_SUCCESS;
    LPCWSTR wszRegistryPath = L"SYSTEM\\ControlSet001\\Control\\Session Manager\\Environment";

    dwRet = RegOpenKeyExW(HKEY_LOCAL_MACHINE, wszRegistryPath, 0, KEY_QUERY_VALUE, &hKey);
    if (dwRet != ERROR_SUCCESS)
    {
        LOG_WARN("The registry key cannot be opened at this time, retCode:%lu.", dwRet);
        return false;
    }

    //RegEnumValueW()
    DWORD dwIndex                  = 0;
    wchar_t wszValueName[MAX_PATH] = {0};
    DWORD dwNameSize               = MAX_PATH;
    DWORD dwType;
    LPBYTE dataBuffer  = NULL;
    DWORD dwBufferSize = 0;
    DWORD dwValueSize  = 0;
    // 获取该项中最大的键值数据大小
    dwRet = RegQueryInfoKeyW(hKey, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, &dwBufferSize, NULL, NULL);
    if (dwRet != ERROR_SUCCESS)
    {
        LOG_WARN("Could not get the maximum size of the key value in the current registry key, retCode:%lu.", dwRet);
        return false;
    }

    dataBuffer = new BYTE[dwBufferSize+1];
    memset(dataBuffer, 0, dwBufferSize + 1);
    dwValueSize = dwBufferSize;

    //遍历键值
    while (RegEnumValueW(hKey, dwIndex, wszValueName, &dwNameSize, NULL, &dwType, dataBuffer, &dwValueSize) ==
           ERROR_SUCCESS)
    {
        wchar_t wszValueData[2048] = {0};
        std::wstring wstrData;
        if (dwType == REG_DWORD)
        {
            DWORD dwData = *reinterpret_cast<DWORD*>(dataBuffer);
            wstrData      = std::to_wstring(dwData);
            wcsncpy_s(wszValueData, sizeof(wszValueData) / sizeof(wchar_t), wstrData.c_str(), wstrData.size());
        }
        else
        {
            //wstrData.assign(reinterpret_cast<const wchar_t*>(dataBuffer), dwValueSize);
            wstrData = reinterpret_cast<wchar_t*>(dataBuffer);
            dwRet = ExpandEnvironmentStringsW(wstrData.c_str(), wszValueData, sizeof(wszValueData) / sizeof(wchar_t));
            if (dwRet == 0)
            {
                wcsncpy_s(wszValueData, sizeof(wszValueData) / sizeof(wchar_t), wstrData.c_str(), wstrData.size());
            }
        }

        // 把该环境变量更新到当前进程的 environment block  
        if (dwType != REG_DWORD && dwRet > 2048)
        {
            SetEnvironmentVariableW(wszValueName, wstrData.c_str());        
        }
        else
        {
            SetEnvironmentVariableW(wszValueName, wszValueData);
        }

        // 重置变量以备下一次循环
        ++dwIndex;
        dwNameSize = MAX_PATH;
        dwValueSize = dwBufferSize;
    }

    delete[] dataBuffer;
    dataBuffer = NULL;
    RegCloseKey(hKey);

    return true;
}

std::string UtilsCopyFileToDir(const std::string& strFilePath, const std::string& strDirPath)
{
    if (strFilePath.size() == 0 || !UtilsIsFileExist(UtilsStringToUnicode(strFilePath.c_str()).c_str()))
    {
        LOG_ERROR("The file[%s] is empty or the file does not exist.", strFilePath.c_str());
        return "";
    }
    if (!IsDirExist(UtilsStringToUnicode(strDirPath).c_str()))
    {   // 判断
        if (HRA_OK != UtilsCheckCreateDir(strDirPath))
        {
            LOG_ERROR("CreateDirectory:%s error!, Code:%lu", strDirPath.c_str(), GetLastError());
            return "";
        }
        LOG_INFO("Create strDirPath[%s] succeed.", strDirPath.c_str());
    }

    std::string strFileName = strFilePath.substr(strFilePath.find_last_of("\\") + 1, strFilePath.size());
    char szFile[MAX_PATH]   = {0};
    _snprintf_s(szFile, sizeof(szFile), "%s\\%s", strDirPath.c_str(), strFileName.c_str());
    if (!CopyFileA(strFilePath.c_str(), szFile, FALSE))
    {
        LOG_ERROR("CopyFileA %s-->%s error! Code:%lu", strFilePath.c_str(), szFile, GetLastError());
        return "";
    }
    LOG_INFO("CopyFileA %s-->%s succeed!", strFilePath.c_str(), szFile);
    return szFile;
}

std::string UtilsPathAppend(const std::string& path1, const char* path2)
{
    char tmpPath[MAX_PATH] = {0};
    memcpy_s(tmpPath, sizeof(tmpPath), path1.c_str(), path1.length());
    PathAppendA(tmpPath, path2);
    return tmpPath;
}

std::string UtilsGetFileFromDir(const std::string& strDir, const std::string& strKey, int maxLevel)
{
    maxLevel--;
    WIN32_FIND_DATAA wfd;
    ::ZeroMemory(&wfd, sizeof(wfd));
    HANDLE hFile = FindFirstFileA(UtilsPathAppend(strDir, "*.*").c_str(), &wfd);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        LOG_ERROR("FindFirstFileA find file[%s] get invalid handle, errorCode:%lu.", strDir.c_str(), GetLastError());
        return "";
    }
    do
    {
        if (wfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            if (_stricmp(wfd.cFileName, ".") == 0 || _stricmp(wfd.cFileName, "..") == 0)
            {
                continue;
            }
            if (maxLevel != 0)
            {
                std::string filePath = UtilsGetFileFromDir(UtilsPathAppend(strDir, wfd.cFileName), strKey.c_str(), maxLevel);
                if (!filePath.empty())
                {
                    FindClose(hFile);
                    return filePath;
                }
            }
        }
        else
        {
            std::string fileName = wfd.cFileName;
            if (fileName.find(strKey) != std::string::npos)
            {
                FindClose(hFile);
                return UtilsPathAppend(strDir, wfd.cFileName);
            }
        }
    } while (FindNextFileA(hFile, &wfd));
    FindClose(hFile);
    return "";
}

void UtilsGetAllMatchFileInDir(const std::string& strDir, const std::string& strKey, std::vector<std::string>& files,
                               int maxLevel)
{
    maxLevel--;
    WIN32_FIND_DATAA wfd;
    ::ZeroMemory(&wfd, sizeof(wfd));
    HANDLE hFile = ::FindFirstFileA(UtilsPathAppend(strDir, "*.*").c_str(), &wfd);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        return;
    }

    do
    {
        if (wfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            if (_stricmp(wfd.cFileName, ".") == 0 || _stricmp(wfd.cFileName, "..") == 0)
            {
                continue;
            }
            else
            {
                if (maxLevel > 0)
                {
                    UtilsGetAllMatchFileInDir(UtilsPathAppend(strDir, wfd.cFileName), strKey.c_str(), files, maxLevel);
                }
            }
        }
        else
        {
            std::string fileName = wfd.cFileName;
            if (fileName.find(strKey) != std::string::npos)
            {
                files.push_back(UtilsPathAppend(strDir, wfd.cFileName));
            }
        }
    } while (::FindNextFileA(hFile, &wfd));
    ::FindClose(hFile);
    return;
}

int UtilsUnzipWithTarget(const std::string& strZipFilePath, const std::string& strTarget)
{
    int lRet          = HRA_OK;
    unzFile pvZipFile = NULL;
    unz_global_info zGlobalInfo;
    memset(&zGlobalInfo, 0, sizeof(zGlobalInfo));
    unz_file_info zFileInfo;
    memset(&zFileInfo, 0, sizeof(zFileInfo));
    std::string strUnzipPath;
    char szSubFileName[MAX_PATH];
    memset(szSubFileName, 0, sizeof(szSubFileName));

    LOG_INFO("Zip file path:%s", strZipFilePath.c_str());

    int lIndex = strZipFilePath.rfind("\\");
    if (lIndex != std::string::npos)
    {
        strUnzipPath = strZipFilePath.substr(0, lIndex + 1); // 解压路径
    }
    else
    {
        strUnzipPath = ".";
    }

    //打开zip文件
    pvZipFile = unzOpen(strZipFilePath.c_str());
    if (NULL == pvZipFile)
    {
        char errMsg[MAX_PATH] = {0};
        strerror_s(errMsg, MAX_PATH, errno);
        LOG_ERROR("The file is not a compressed file. %s", errMsg);
        lRet = HRA_FAILED; // 可能不是压缩文件，不处理
        goto err;
    }

    //获取压缩文件的全局信息
    if (unzGetGlobalInfo(pvZipFile, &zGlobalInfo) != UNZ_OK)
    {
        LOG_ERROR(" Failed to obtain global information about compressed files. ");
        lRet = HRA_FAILED;
        goto err;
    }

    for (int i = 0; i < zGlobalInfo.number_entry; ++i)
    {
        //从压缩包循环获得子文件信息：文件名， 文件大小
        if (UNZ_OK !=
            unzGetCurrentFileInfo(pvZipFile, &zFileInfo, szSubFileName, sizeof(szSubFileName), NULL, 0, NULL, 0))
        {
            LOG_ERROR(" Failed to get child file information .");
            lRet = HRA_FAILED;
            goto err;
        }

        LOG_DEBUG("Sub file name:%s", szSubFileName);
        std::string strSubFileName = szSubFileName;
        if (strSubFileName.empty())
        {
            printf_s("Sub file name empty!\n");
            lRet = HRA_FAILED;
            goto err;
        }
        if (strSubFileName == "." || strSubFileName == ".\\" || strSubFileName == ".." || strSubFileName == "..\\")
        {
            unzGoToNextFile(pvZipFile);
            continue;
        }
        std::replace(strSubFileName.begin(), strSubFileName.end(), '/', '\\');
        if (_stricmp(strSubFileName.c_str(), strTarget.c_str()) != 0)
        {
            unzGoToNextFile(pvZipFile);
            continue;
        }

        std::string strSubFilePath = strUnzipPath + strSubFileName; // 拼接子文件路径与解压路径

        std::string strPathTmp = strSubFilePath.substr(0, strSubFilePath.rfind("\\"));
        //判断父路径是否存在，不存在则创建
        if (!IsDirExist(UtilsStringToUnicode(strPathTmp).c_str()))
        {
            if (HRA_OK != UtilsCheckCreateDir(strPathTmp.c_str()))
            {
                LOG_ERROR("CreateDirectory:%s error!, Code:%lu", strPathTmp.c_str(), GetLastError());
                lRet = HRA_FAILED;
                goto err;
            }
            LOG_DEBUG("Create subdir succeed! %s", strPathTmp.c_str());
        }

        if (UNZ_OK != unzOpenCurrentFile(pvZipFile))
        {
            LOG_ERROR(" Failed to open the subfile. ");
            lRet = HRA_FAILED;
            goto err;
        }

        //申请内存
        int lFileLength   = zFileInfo.uncompressed_size; // 子文件长度
        char* pscFileData = (char*)malloc(lFileLength + 1);
        if (pscFileData == NULL)
        {
            LOG_ERROR("Failed to malloc memory.");
            lRet = HRA_FAILED;
            goto err;
        }
        memset(pscFileData, 0, lFileLength + 1);

        //解压子文件
        int lUnzSubfileLen = unzReadCurrentFile(pvZipFile, (voidp)pscFileData, lFileLength);
        if (pscFileData != NULL)
        {
            pscFileData[lUnzSubfileLen] = '\0';
        }
        LOG_DEBUG("Sub file size:%lu, unzip size:%d", zFileInfo.compressed_size, lUnzSubfileLen);

        //写入文件
        std::ofstream file(strSubFilePath.c_str(), std::ios::out | std::ios::binary);
        if (!file.good())
        {
            LOG_ERROR(" Failed to create sub file. errno:%d,  %s", errno, strSubFilePath.c_str());
            lRet = HRA_FAILED;
            unzCloseCurrentFile(pvZipFile);
            if (pscFileData)
            {
                free(pscFileData);
                pscFileData = NULL;
            }
            goto err;
        }
        file.seekp(0, std::ios::beg);
        if (pscFileData != NULL)
        {
            file.write(pscFileData, lUnzSubfileLen);
        }
        size_t nFileSize = file.tellp();
        file.close();
        LOG_DEBUG("Write sub file succeed! size:%llu %s", (uint64_t)nFileSize, strSubFilePath.c_str());
        unzCloseCurrentFile(pvZipFile);
        unzGoToNextFile(pvZipFile);
        if (pscFileData)
        {
            free(pscFileData);
            pscFileData = NULL;
        }
    }

    LOG_INFO("Unzip file succeed:%s", strZipFilePath.c_str());

err:
    if (pvZipFile)
    {
        unzClose(pvZipFile);
    }
    return lRet;
}

std::string UtilsGetVulnZipPathFromZips(const std::vector<std::string>& vecFiles, const std::string& strZipTemp)
{
    for (auto it = vecFiles.begin(); it != vecFiles.end(); ++it)
    {
        if (_stricmp(strZipTemp.c_str(), it->c_str()) == 0)
        {
            continue;
        }

        UtilsUnzipWithTarget(it->c_str(), "meta_info.json");

        std::string strTmp = it->substr(0, it->rfind("\\") + 1) + "meta_info.json";
        LOG_INFO("current json file:[%s]", strTmp.c_str());
        Json::Value jsRoot = FileToJson(strTmp.c_str());
        if (jsRoot.isMember("pattern_type") && jsRoot["pattern_type"].isString() &&
            _stricmp(jsRoot["pattern_type"].asString().c_str(), "win-vuln-os") == 0)
        {
            return it->c_str();
        }
    }
    return "";
}

std::vector<DWORD> GetPidByRegexName(const wchar_t* wszKey)
{
    PROCESSENTRY32 pe32;
    std::vector<DWORD> vecPID;

    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE)
    {
        return vecPID;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(hProcessSnap, &pe32))
    {
        CloseHandle(hProcessSnap);
        return vecPID;
    }

    std::wstring wstrKey = wszKey + std::wstring(L"\\w+\\.exe");
    std::wregex pattern(wstrKey, std::regex_constants::icase);
    do
    {
        std::wsmatch matchs;
        if (std::regex_search(std::wstring(pe32.szExeFile), matchs, pattern))
        {
            vecPID.push_back(pe32.th32ProcessID);
        }
    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
    return vecPID;
}

static bool ConvertSUVersionToDotFormat(const std::string& strRawSUVersion, std::string& strDotFormat)
{
    strDotFormat = "";

    std::regex regPattern("(\\d+)(\\d{2})(\\d{2})(\\d{4})");

    std::smatch regMatch;

    if(!std::regex_match(strRawSUVersion, regMatch, regPattern))
    {
        LOG_INFO("%s do not match expect format", strRawSUVersion.c_str());
        return false;
    }

    if(regMatch.size() != 5)
    {
        LOG_INFO("%s do not match expect format", strRawSUVersion.c_str());
        return false;

    }

    std::string strMajorVer = regMatch[1];
    std::string strMinVer = regMatch[2];
    std::string strReverseVer = regMatch[3];
    std::string strBuildNum = regMatch[4];

    int iMajorVer = atoi(strMajorVer.c_str());
    int iMinVer = atoi(strMinVer.c_str());
    int iReverseVer = atoi(strReverseVer.c_str());
    int iBuildNum = atoi(strBuildNum.c_str());

    char szDotFormat[MAX_PATH] = {0};

    sprintf_s(szDotFormat, "%d.%d.%d.%d", iMajorVer, iMinVer, iReverseVer, iBuildNum);

    strDotFormat = szDotFormat;

    LOG_DEBUG("strRawSUVersion: %s, strDotFormat: %s", strRawSUVersion.c_str(), strDotFormat.c_str());

    return true;
}

bool ReadSUVersionFromMetaInfo(const std::string& strPatternDir, std::string& strDotStyleVersion)
{
    strDotStyleVersion = "";

    // read su_version from meta_info.json
    char szPath[MAX_PATH] = {0};
    sprintf_s(szPath, strPatternDir.c_str());

    ::PathAppendA(szPath, PATTERN_INFORMATION);

    if (!PathFileExistsA(szPath))                                          
    {
        LOG_INFO("path: %s not exist", szPath);
        return false;
    }

    Json::Value jsonMetaInfo = FileToJson(szPath);

    if (!jsonMetaInfo.isMember("su_version"))
    {
        LOG_INFO("do not contains su version key, file path: %s", szPath);
        return false;
    }

    std::string strSURawVersion = jsonMetaInfo["su_version"].asString();

    LOG_DEBUG("strSURawVersion: %s", strSURawVersion.c_str());

    std::string strDotVersion;

    // convert raw version format to dot format
    // 106000167 ---> 1.6.0.167
    if(!ConvertSUVersionToDotFormat(strSURawVersion, strDotVersion))
    {
        LOG_INFO("convert su raw version failed, strSURawVersion: %s", strSURawVersion.c_str());
        return false;
    }

    LOG_DEBUG("strDotVersion: %s", strDotVersion.c_str());

    strDotStyleVersion = strDotVersion;
    
    return true;
}
