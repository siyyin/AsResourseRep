#include <WinSock2.h>
#include <WS2tcpip.h>
#include <IPHlpApi.h>
#include "HraCompress.h"
#include "HraJson.h"
#include "HraUtils.h"
#include "Logger.h"

#pragma comment(lib, "jsoncpp.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")


int GetAdapter(std::vector<std::string>& vectIPv4, std::vector<std::string>& vectIPv6)
{
	ULONG                 flags = GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS; //包括 IPV4 ，IPV6 网关
	ULONG                 family = AF_UNSPEC; //返回包括 IPV4 和 IPV6 地址
	PIP_ADAPTER_ADDRESSES pAddresses = NULL;
	ULONG                 outBufLen = 0;
	DWORD                 dwRetVal = 0;
	PIP_ADAPTER_ADDRESSES pCurrAddresses = NULL;
	PIP_ADAPTER_UNICAST_ADDRESS pUnicast = NULL;

	int iLoopTimes = 0;
	outBufLen = 15000;
	do
	{
		// 获取需要内存长度 与 分配内存
		dwRetVal = GetAdaptersAddresses(family, flags, NULL, NULL, &outBufLen);
		if (dwRetVal != ERROR_BUFFER_OVERFLOW &&
			outBufLen < 1) // 只获取长度 不填地址，会出现无内存 && 额外判断所需buf长度
		{
			LOG_ERROR("GetAdaptersAddresses get memory length failed, errorCode:%lu", dwRetVal);
			return HRA_FAILED;
		}
		pAddresses = (PIP_ADAPTER_ADDRESSES)malloc(outBufLen);
		if (pAddresses == NULL)
		{
			LOG_ERROR("malloc pAddresses failed.");
			return HRA_FAILED;
		}

		dwRetVal = GetAdaptersAddresses(family, flags, NULL, pAddresses, &outBufLen);
		if (dwRetVal != ERROR_SUCCESS)
		{
			free(pAddresses);
			pAddresses = NULL;
			LOG_WARN("GetAdaptersAddresses error times:%d", (iLoopTimes + 1));
		} else
		{
			break;
		}
		iLoopTimes++;
		Sleep(1000);
	} while (dwRetVal == ERROR_BUFFER_OVERFLOW && iLoopTimes < 5); //尝试获取多次

	int iInterfaceCount = 0;
	if (dwRetVal == ERROR_SUCCESS)
	{
		pCurrAddresses = pAddresses;
		while (pCurrAddresses)
		{
			pUnicast = pCurrAddresses->FirstUnicastAddress;
			while (pUnicast) //单播IP
			{
				CHAR IP[130] = { 0 };
				if (AF_INET == pUnicast->Address.lpSockaddr->sa_family) // IPV4 地址，使用 IPV4 转换
				{
					inet_ntop(PF_INET, &((sockaddr_in*)pUnicast->Address.lpSockaddr)->sin_addr, IP, sizeof(IP));
					vectIPv4.push_back(IP);
					LOG_DEBUG("local ip is  %s", IP);
				} else if (AF_INET6 == pUnicast->Address.lpSockaddr->sa_family) // IPV6 地址，使用 IPV6 转换
				{
					inet_ntop(PF_INET6, &((sockaddr_in6*)pUnicast->Address.lpSockaddr)->sin6_addr, IP, sizeof(IP));
					vectIPv6.push_back(IP);
					LOG_DEBUG("local ip is  %s", IP);
				}
				pUnicast = pUnicast->Next;
			}

			iInterfaceCount++;
			pCurrAddresses = pCurrAddresses->Next;
		}
	} else
	{
		LOG_ERROR("GetAdaptersAddresses error.");
		return HRA_FAILED;
	}
	if (pAddresses) free(pAddresses);

	return HRA_OK;
}

Json::Value AgentGetAllIP()
{
	WSADATA wsaData;
	int     iRet = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iRet)
	{
		LOG_ERROR("wss: WSAStartup Failed.");
		return "";
	}

	Json::Value strIParray;
	strIParray.resize(0);
	std::vector<std::string> vectIPv4;
	std::vector<std::string> vectIPv6;
	vectIPv4.clear();
	vectIPv6.clear();
	iRet = 0;
	iRet = GetAdapter(vectIPv4, vectIPv6);
	if (iRet != HRA_OK)
	{
		LOG_WARN("Get the native IP error！");
		return strIParray;
	}

	for (auto iter4 = vectIPv4.begin(); iter4 != vectIPv4.end(); ++iter4)
	{
		// 管理端不要127.0.0.1, 因为IP是他们的一个搜索字段.
		if (strcmp(iter4->c_str(), "127.0.0.1") == 0)
		{
			continue;
		}
		// 可以多用Json,直接就是数组, 减少手动拼接; 
		strIParray.append(iter4->c_str());
	}
	for (auto iter6 = vectIPv6.begin(); iter6 != vectIPv6.end(); ++iter6)
	{
		if (strcmp(iter6->c_str(), "::1") == 0)
		{
			continue;
		}

		strIParray.append(iter6->c_str());
	}

	WSACleanup();
	return strIParray;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	获取注册信息. </summary>
///
/// <remarks>	, 2021/12/18. </remarks>
///
/// <param name="">	no	param </param>
///
/// <returns>	The regster information. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
std::string GetRegsterInfo(void)
{
	Json::Value jsClientInfo;
	Json::Value jsBodyObj;

	jsClientInfo["device_id"] = UtilsGetUUID();
	jsClientInfo["time_stamp"] = UtilsGetRunTime();
	jsClientInfo["system_info"] = UtilsGetOsReleaseName();
	jsClientInfo["program_version"] = UtilsGetAppVersion();
    jsClientInfo["appscan_pattern_version"] = "0";//Windows没有appscan pattern，为了保持接口不变，默认传0
	jsClientInfo["sysscan_pattern_version"] = UtilsGetOSscanPatternVersion();
	jsClientInfo["baseline_pattern_version"] = UtilsGetBaselinePatternVersion();
    jsClientInfo["wpscan_pattern_version"] = UtilsGetDolphinPatternVersion();
    jsClientInfo["vulnpoc_pattern_version"]  = UtilsGetVulnPocPatternVersion();
    jsClientInfo["ip"]                       = AgentGetAllIP();

	jsBodyObj["client_info"] = jsClientInfo;

	Json::FastWriter writer;
	return writer.write(jsBodyObj);
}


////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	获取上报json body， 构建json对象，转化成字符串. </summary>
///
/// <remarks>	, 2021/12/18. </remarks>
///
/// <param name="ucMsgType">	   	Type of the message. </param>
/// <param name="pscContentData">  	Information describing the psc content. </param>
/// <param name="ulContentLen">	   	Length of the ul content. </param>
/// <param name="ucMsgCompression">	The message compression. </param>
///
/// <returns>	The report JSON body. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
std::string GetReportJsonBody(unsigned char ucMsgType, const char *pscContentData, 
							  unsigned int ulContentLen, unsigned char ucMsgCompression)
{
	Json::Value jsObj;
	std::string strContentData;

	//如果压缩数据先压缩数据
	if (ucMsgCompression == NEED_COMPRESSION) {
		//压缩转换原始数据
		CCompressedBuffer compressedBuffer(COMPRESS_CACHE_MAX_SIZE);
		compressedBuffer.Write(pscContentData, ulContentLen);
		compressedBuffer.Finish();

		strContentData = UtilsByteToHexStr((unsigned char *)compressedBuffer.GetRawBuffer(), 
			compressedBuffer.GetCompressedSize());
		LOG_INFO("CompressedBuffer origin size %u, compress size %u, converstr size %u.",
			ulContentLen, (unsigned int)(compressedBuffer.GetCompressedSize()), (unsigned int)(strContentData.size()));
	}
	else
	{
		strContentData = pscContentData;
	}

	jsObj["msg_type"] = ucMsgType;
	jsObj["msg_size"] = ulContentLen;
	jsObj["msg_compression"] = ucMsgCompression;
	jsObj["msg_content"] = strContentData;


	Json::FastWriter writer;
	return writer.write(jsObj);
}


////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	获取上报结果. </summary>
///
/// <remarks>	, 2021/12/18. </remarks>
///
/// <param name="pscTaskId"> 	Identifier for the psc task. </param>
/// <param name="lErrorCode">	The error code. </param>
/// <param name="pstrBuff">  	[in,out] If non-null, buffer for pstr data. </param>
/// <param name="ulLen">	 	Length of the ul. </param>
/// <param name="lScanType"> 	扫描类型. </param>
///
/// <returns>	The report result information. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
std::string GetReportResultInfo(const char* pscTaskId, int lErrorCode, const char* pstrBuff, int nRetLogLevel)
{
	Json::Value jsClientInfo;
	Json::Value jsBodyObj;

	jsClientInfo["device_id"] = UtilsGetUUID();
	jsClientInfo["time_stamp"] = UtilsGetRunTime();
	jsClientInfo["task_id"] = (pscTaskId == NULL ? "" : pscTaskId);
	jsClientInfo["error_code"] = lErrorCode;
	jsClientInfo["error_info"] = lErrorCode == 0 ? "success" : "failed";
	jsClientInfo["result_info"] = (pstrBuff == NULL ? "" : pstrBuff);
	jsBodyObj["result"]=jsClientInfo;
    if (nRetLogLevel == LOG_LEVEL_DEBUG)
    {
        LOG_DEBUG("Get report result info:\n %s.", jsBodyObj.toStyledString().c_str());
    }
    else
    {
        LOG_INFO("Get report result info:\n %s.", jsBodyObj.toStyledString().c_str());
    }
	Json::FastWriter writer;
	return writer.write(jsBodyObj);
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	获取上报结果. </summary>
///
/// <remarks>	, 2021/12/18. </remarks>
///
/// <param name="lErrorCode">	The error code. </param>
/// <param name="lCmdType">  	Type of the command. </param>
/// <param name="strModlue"> 	The modlue. </param>
/// <param name="strVersion">	The version. </param>
///
/// <returns>	The report pattern update result. 
/// 			    {
//     "device_id": "2",
//     "results": [
//         {
//             "error_code": 0,
//             "error_info": "succeeded",
//             "command_type": 6006,
//             "other_info": {
//                 "vuln_soft_pattern": {
//                     "update": false,
//                     "version": "1.0.1"
//                 },
//                 "vuln_os_pattern": {
//                     "update": true,
//                     "version": "1.0.1"
//                 },
//                 "baseline_pattern": {
//                     "update": false,
//                     "version": "1.0.1"
//                 }
//             }
//         }
//     ]
//}
/// </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
std::string GetReportPatternUpdateResult(int lErrorCode, int lCmdType, std::string strModlue, const std::string &strVersion)
{
	Json::Value jsInfo;
	Json::Value jsResults;
	Json::Value jsOtherInfo;

	jsOtherInfo["vuln_soft_pattern"]["update"] = false;
	jsOtherInfo["vuln_soft_pattern"]["version"] = "0";

	jsOtherInfo["vuln_os_pattern"]["update"] = false;
	jsOtherInfo["vuln_os_pattern"]["version"] = "0";

	jsOtherInfo["baseline_pattern"]["update"] = false;
	jsOtherInfo["baseline_pattern"]["version"] = "0";

    jsOtherInfo["wpscan_pattern"]["update"] = false;
    jsOtherInfo["wpscan_pattern"]["version"] = "0";

    jsOtherInfo["vulnpoc_pattern"]["update"]  = false;
    jsOtherInfo["vulnpoc_pattern"]["version"] = "0";

    jsOtherInfo["asset_pattern"]["update"]  = false;
    jsOtherInfo["asset_pattern"]["version"] = "0";

	jsOtherInfo[strModlue]["update"] = lErrorCode == 0 ? true : false;
	jsOtherInfo[strModlue]["version"] = strVersion;

	jsResults["other_info"] = jsOtherInfo;
	jsResults["error_code"] = lErrorCode;
	jsResults["error_info"] = lErrorCode == 0 ? "success" : "failed";
	jsResults["command_type"] = lCmdType;

	jsInfo["results"].append(jsResults);
	jsInfo["device_id"] = UtilsGetUUID();

	LOG_INFO("The result of pattern updating is :\n %s.", jsInfo.toStyledString().c_str());
	Json::FastWriter writer;
	return writer.write(jsInfo);
}


////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	字符串转json. </summary>
///
/// <remarks>	, 2021/12/18. </remarks>
///
/// <param name="pscJsonData">  	Information describing the psc JSON. </param>
/// <param name="ulJsonDataLen">	Length of the ul JSON data. </param>
///
/// <returns>	A Json::Value. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
Json::Value StringToJson(const char* pscJsonData, unsigned int ulJsonDataLen)
{
    Json::Value jsRoot;
    Json::Reader jsReader;
    if (pscJsonData == NULL)
    {
        LOG_ERROR("Json data is null.");
        jsRoot.clear();
        goto _end;
    }

    try
    {
        if (!jsReader.parse(pscJsonData, jsRoot))
        {
            LOG_ERROR("Json parse data failed.");
            jsRoot.clear();
            goto _end;
        }
    }
    catch (std::exception& ex)
    {
        LOG_ERROR("Json parse data exception %s.", ex.what());
        jsRoot.clear();
        goto _end;
    }

_end:
    return jsRoot;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	JSON to string. </summary>
///
/// <remarks>	, 2021/12/18. </remarks>
///
/// <param name="jsObj">	The js object. </param>
///
/// <returns>	A std::string. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
std::string JsonToString(const Json::Value& jsObj)
{
	Json::FastWriter writer;

	if (jsObj.size() == 0)
	{
		return "";
	}

	return writer.write(jsObj);
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	json文件转json字符串. </summary>
///
/// <remarks>	, 2021/12/18. </remarks>
///
/// <param name="pscFilePath">	Full pathname of the psc file. </param>
///
/// <returns>	A Json::Value. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
Json::Value FileToJson(const char *pscFilePath)
{
	std::ifstream ifs;
	Json::Reader jsReader;
	Json::Value jsRoot;

	if(NULL == pscFilePath)
	{
		LOG_ERROR("Parameter is null.");
		goto _end;
	}
	ifs.open(pscFilePath);
	if(!ifs)
	{
		LOG_ERROR("Failed to open the configuration file: %s", pscFilePath);
		goto _end;
	}
	try
	{
		if(!jsReader.parse(ifs, jsRoot))
		{
			LOG_ERROR("Json parse data failed.");
			goto _end;
		}
	}
	catch(std::exception &ex)
	{
		LOG_ERROR("Json parse data exception %s.\n", ex.what());
	}

_end:
	ifs.close();
	return jsRoot;
}

/// <summary>
/// 从cmd_data数组中获取command_data字段
/// </summary>
/// <param name="jsArrayCmd"></param>
/// <returns></returns>
Json::Value GetCommandDataFromArrayCmd(const Json::Value& jsArrayCmd)
{
    Json::Value jsRet;
    if (!jsArrayCmd.isMember("command_data"))
    {
        goto _exit;
    }
    jsRet = jsArrayCmd["command_data"];

_exit:
    return jsRet;
}
