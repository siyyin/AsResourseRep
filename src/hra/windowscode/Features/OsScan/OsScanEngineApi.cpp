#include <stdlib.h>
#include <algorithm>
#include <sys/stat.h>
#include "OsScanEngineApi.h"
#include "utility/HraUtils.h"
#ifdef _WIN32
#include <windows.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <memory>
#include "utility/HraReport.h"
#include "utility/HraKbDataMgr.h"
#include "utility/HraJson.h"
#else
#include <stdio.h>
#include <string.h>
#include <dlfcn.h> 
#include <iostream>
#include <fstream>

using namespace std;

#endif

#define MAX_LEN_1024       1024
////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	加载引擎，导入符号. </summary>
///
/// <remarks>	, 2021/12/27. </remarks>
///
/// <param name="pstOsScanEngineApi">	[out] 输出引擎导出的符号. </param>
///
/// <returns>	An int. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
int OsScanEngineLoad(struct OsScanEngineApi * pstOsScanEngineApi, const std::string& strPatternPath)
{
    if (!pstOsScanEngineApi)
    {
        LOG_ERROR("Engine api is null.");
        return -2;
    }

    //std::string strPatternPath;
    bool bVALoadPatternRet = false;
    bool bRet = true;
    char strEngineVer[MAX_LEN_64] = {0};
    char strPatternVer[MAX_LEN_64] = {0};

    bRet = VAGetEngineVersion(strEngineVer, MAX_LEN_64);
    if (!bRet)
    {
        LOG_ERROR("VAGetEngineVersion failed!");
        return -1;
    }
        
    LOG_INFO("VAScan engine version: %s", strEngineVer);

    //提取接口
    pstOsScanEngineApi->pVAScanContext = VAInitialize();
    if (!pstOsScanEngineApi->pVAScanContext)
    {
        LOG_ERROR("pstOsScanEngineApi->pVAScanContext NULL!");
        return -1;
    }
        

    //加载Pattern
    //获取pattern路径
    //strPatternPath = UtilsGetOSscanPatternVersionPath();

    struct stat stFileStat; 
    if(stat(strPatternPath.c_str(), &stFileStat) != 0)
    {
        LOG_ERROR("pattern %s is not exists!", strPatternPath.c_str());
        return -2;
    }
    else
    {
        if(stFileStat.st_mode & S_IFDIR)
        {
            LOG_ERROR("pattern path: %s is dir!", strPatternPath.c_str());
            return -2;
        }
    }

    bVALoadPatternRet = VALoadPattern(pstOsScanEngineApi->pVAScanContext, strPatternPath.c_str());
    if (!bVALoadPatternRet)
    {
        LOG_ERROR("LOAD PATTERN FAILED, error:%s", pstOsScanEngineApi->pVAScanContext->pszErrorMsg);
        return -2;
    }

    //获取pattern version
    bRet = VAGetPatternVersion(pstOsScanEngineApi->pVAScanContext, strPatternVer, MAX_LEN_64);
    if (!bRet)
    {
        LOG_ERROR("VAGetPatternVersion failed!");
        return -1;
    }
        
    LOG_INFO("Load pattern version: %s", strPatternVer);
	Sleep(5000);
    return 0;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	导入pattern. </summary>
///
/// <remarks>	, 2021/12/27. </remarks>
///
/// <param name="pscPatternPath">	 	[in] pattern路径. </param>
/// <param name="pstOsScanEngineApi">	[in] 引擎的符号. </param>
///
/// <returns>	An int. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
int OsScanPatternLoad(const char *pscPatternPath, struct OsScanEngineApi *pstOsScanEngineApi)
{
    // 加载Pattern
    if(!pstOsScanEngineApi || !pstOsScanEngineApi->pVAScanContext)
    {
        return -2;
    }

    VA_SCAN_CONTEXT* pVAScanContext = pstOsScanEngineApi->pVAScanContext;
    //指定pattern路径
    pstOsScanEngineApi->ucPatternIsLoad = VALoadPattern(pVAScanContext, pscPatternPath);
    if (!pstOsScanEngineApi->ucPatternIsLoad)
    {
        LOG_ERROR("LOAD PATTERN FAILED | %s", pVAScanContext->pszErrorMsg);
        return -2;
    }

    /*
        char PatternVersion[64] = { 0 };
        VAGetPatternVersion(pVAScanContext, PatternVersion, 64);
        std::cout << "Pattern Version #" << PatternVersion << std::endl;
    */
    return 0;
}




////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>解析全量cve json文件.  作为scan func的入参传递给pattern</summary>
///
/// <remarks>  2023/9/6. </remarks>
///
/// <param name="">	已知json文件的名称及路径，仅需获取版本即可</param>
///
/// <returns> json string. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
std::string ParseAllCVEInfo()
{
	std::string strPatternVersion = UtilsGetOSscanPatternVersion();
	std::string strWorkPath = UtilsGetWorkPath();
	std::string strAllCVEInfoPath = strWorkPath + OSSACN_PATTERN_DIR +"data\\all_cve_info$" + strPatternVersion;

	return UtilsFileDecryption(strAllCVEInfoPath);

}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	引擎扫描接口. </summary>
///
/// <remarks>	, 2021/12/27. </remarks>
///
/// <param name="pstOsScanEngineApi">	[in] 引擎的符号. </param>
/// <param name="strScanResultData"> 	[out] 扫描结果. </param>
///
/// <returns>	An int. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
int OsScanEngineDoScan(struct OsScanEngineApi *pstOsScanEngineApi, std::string &strScanResultData, bool bIsAllCveScan)
{
	std::string strKBScanRet = "";
	int iTimeOut = 5 * 60 * 1000; //超时时间5分钟
	int iRetCode = 0;

    if(!pstOsScanEngineApi)
    {
        LOG_ERROR("Null pointer pstOsScanEngineApi!");
		iRetCode = -2;
		return iRetCode;
    }

	VA_SCAN_RESULT* pVAScanResult = NULL;
	// 使用std::unique_ptr来确保pVAScanResult资源释放
	std::unique_ptr<VA_SCAN_RESULT, bool(*)(VA_SCAN_RESULT* &)> uniPtr(pVAScanResult, VAFreeScanResult);

	bool bVAScanEventRet = false;
	std::string strIpcName = UtilsGetHraIpcName();

	if(!bIsAllCveScan)
	{
		//先清理内存中数据，后发送请求
		unsigned long long nSeq = 0;
		HraKbDataMgr::getInstance().clear();
		CReportInfo cReportKbDataReq;
		//请求KB数据
		int ret = cReportKbDataReq.KbRequest(nSeq);
		if(ret == 0)
		{
			int iTimeCount = 0;
			//从内存中获取产品补丁管理模块返回的补丁结果
			while(true)
			{
				//超过五分钟还未获得结果，则执行旧方案
				if (iTimeCount > iTimeOut)
				{
					break;
				}
				HraKbDataMgr::KbData data;
				bool bRet = HraKbDataMgr::getInstance().getData(data, nSeq);
				LOG_INFO("Get KB data, seq:%llu, ret:%s", nSeq, bRet ? "true" : "false");
				if (bRet)
				{
					if(!data.strData.empty() && data.strData != "")
					{
						strKBScanRet = data.strData;
						break;
					}
				}
				Sleep(5000);
				iTimeCount += 5000;
			}
		}
		LOG_INFO("Leakrepair ret :%s", strKBScanRet.c_str());
		if(strKBScanRet.empty())
		{
			//表示补丁扫描失败，没有返回值，主要场景为产品不具备补丁管理功能
			LOG_INFO("the os is not supported kb scan, execute all cve scan processing");
			//HRA_EMPTY = 16,
			iRetCode = 16;
			return iRetCode;
		}

		const char *szKBScanRet = strKBScanRet.c_str();

		//analysis the kb scan result
		bool bCheckRet = VACheckLeakRepairSupportOs(szKBScanRet);

		if (bCheckRet)
		{
			std::string strAllCVEInfo = ParseAllCVEInfo();
			const char *szAllCVEInfo = strAllCVEInfo.c_str();

			bVAScanEventRet = VAExecuteScanWithArg(pstOsScanEngineApi->pVAScanContext, szAllCVEInfo, szKBScanRet, pVAScanResult);
			Sleep(5000);

		}
		else
		{
			//表示补丁扫描结果为空,包含两种场景：1、没有待修复的补丁 2、未授权补丁管理模块
			LOG_INFO("the kb scan result is null, execute all cve scan processing");
			//HRA_EMPTY = 16,
			iRetCode = 16;
			return iRetCode;
		}
	}
	else 
	{
		LOG_INFO("scan with the all cve rules pattern by comparing versions method");
		bVAScanEventRet = VAExecuteScan(pstOsScanEngineApi->pVAScanContext, pVAScanResult);
	}


	if (!bVAScanEventRet || !pVAScanResult->strResult || !pVAScanResult->dwLen)
    {
        LOG_ERROR("VAScanEvent() failed!!!");
		iRetCode = -3;
		return iRetCode;
    }

	// 取出扫描结果
	std::unique_ptr<char[]> pszResult(new char[pVAScanResult->dwLen + 1]);
	if (!pszResult)
	{
		LOG_ERROR("Memory allocation failed!!!");
		iRetCode = -4;
		return iRetCode;
	}
	memset(pszResult.get(), 0, pVAScanResult->dwLen + 1);
	strncpy_s(pszResult.get(), pVAScanResult->dwLen + 1, pVAScanResult->strResult, pVAScanResult->dwLen);
	// 打印，解析扫描结果
	strScanResultData = pszResult.get();

	//判断cve扫描结果是否为空(主要场景为待修复的补丁没有对应的cve),若为空则执行全量cve扫描
	Json::Value root = StringToJson(strScanResultData.c_str(), strScanResultData.size());
	Json::Value arrayResult = root["result"];
	std::string StrArrayResult = arrayResult.toStyledString();
	size_t CheckStrArrayResult = StrArrayResult.find("CveId");
	
	//若Kb方法扫描结果为空则继续执行oval扫描方案，若oval扫描结果为空则上报
	bool bIsNullKbMthodResult = false;
	if (CheckStrArrayResult == std::string::npos && bIsAllCveScan == false)
	{
		LOG_INFO("the cve scan result is null, execute all cve scan processing");
		bIsNullKbMthodResult = true;
	}

	if (arrayResult.isNull() || !arrayResult.isArray() || bIsNullKbMthodResult)
	{
        LOG_INFO("Kb method scan result: %s, is null: %d, size: %llu", StrArrayResult.c_str(),
                 (int)arrayResult.isNull(), (unsigned long long)StrArrayResult.length());
		//HRA_EMPTY = 16,
		iRetCode = 16;
		return iRetCode;
	}

	// 内存会在 std::unique_ptr 离开作用域时自动释放
	return iRetCode;

}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	初始化引擎. </summary>
///
/// <remarks>	, 2021/12/27. </remarks>
///
/// <param name="pstOsScanEngineApi">	[out] 引擎的符号. </param>
///
/// <returns>	An int. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
int OsScanEngineInit(struct OsScanEngineApi *pstOsScanEngineApi, const std::string& strPatternPath)
{
    int lRet = 0;

    if(!pstOsScanEngineApi)
    {
        LOG_ERROR("Engine api is null.");
        return -2;
    }

    lRet = OsScanEngineLoad(pstOsScanEngineApi, strPatternPath);
    if (lRet != 0)
    {
        LOG_ERROR("Engine load failed.");
        return lRet;
    }
    return 0;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	恢复IOA引擎状态. </summary>
///
/// <remarks>	, 2021/12/27. </remarks>
///
/// <param name="pstOsScanEngineApi">	[in] 引擎的符号. </param>
///
/// <returns>	A void. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
void OsScanEngineUnInit(struct OsScanEngineApi *pstOsScanEngineApi)
{
    if(!pstOsScanEngineApi)
    {
        return ;
    }
    
    // 恢复IOA引擎状态
    VAUnInitialize(pstOsScanEngineApi->pVAScanContext);

    return ;
}
