/***************************************************************************
// (C) Copyright (C) 2021 亚信科技（成都）有限公司 All Rights Reserved.
// 文件名称 :	VAScan.h
// 
// 描述 :	声明VAScan引擎的接口
//
// 作者 :	huangyong5@asiainfo-sec.com
//
// 时间 :	2021/9/20
*****************************************************************************/
#ifndef VASCAN_H
#define VASCAN_H

#ifdef __cplusplus
  extern "C" {
#endif

#define VASCAN_API
#define FILE_PATH_LEN 1024
#define MAX_LEN_64 64

typedef struct _VA_SCAN_CONTEXT {
	void *pLuaState;
	char* pszErrorMsg;
}VA_SCAN_CONTEXT;

typedef struct _VA_SCAN_RESULT {
	char* strResult;
	unsigned int dwLen;
} VA_SCAN_RESULT;

typedef struct _PATTERN_HEADER
{
	char ptnMagic[MAX_LEN_64];       //pattern识别标识
	char ptnVersion[MAX_LEN_64];     //pattern 版本号
	char ptnBuildTime[MAX_LEN_64]; //pattern build时间
	unsigned int ptnOriginalSize;	      //pattern原始文件大小
	unsigned int ptnCompressSize;     //pattern压缩和加密之后大小
}PATTERN_HEADER;
//--------------------------------------------------------------------------
/******************************** define  VA Scan interface ********************************/
//--------------------------------------------------------------------------
//
// 函数名称 :		VAInitialize			
//
// 描述 :			初始化VA Scan引擎，包括初始化全局变量，创建lua解释器等
//
// 输入参数:			无
//
// 输出参数:			无
//
// 返回值:			lua解释器的地址
//
// 修改记录：		
//
// 其他:				
//--------------------------------------------------------------------------
VASCAN_API VA_SCAN_CONTEXT* VAInitialize(void);

//--------------------------------------------------------------------------
//
// 函数名称 :		VALoadPattern			
//
// 描述 :			加载VA Pattern文件，解密VA Pattern到内存，并执行Pattern初始化操作
//
// 输入参数:			pScanContext为lua解释器地址，strPatternFilePath为包含Pattern的lua脚本路径
//
// 输出参数:			无
//
// 返回值:			true/false，标识Pattern加载是否成功
//
// 修改记录：		
//
// 其他:				
//--------------------------------------------------------------------------
VASCAN_API bool VALoadPattern(VA_SCAN_CONTEXT* pScanContext, const char* strPatternFilePath);

//--------------------------------------------------------------------------
//
// 函数名称 :		VAExecuteScan			
//
// 描述 :			执行pattern扫描本地系统/应用漏洞，并返回相关漏洞信息
//
// 输入参数:		pScanContext: lua解释器地址；
//                     pScanResult: 输入时候pScanResult->strResult==NULL;
//                     pScanResult->dwLen==0
//
// 输出参数:		如果有结果返回, pScanResult->strResult为扫描结果的json格式字符串;
//                                                  pScanResult->dwLen, pScanResult->strResult的长度                                          
//                     注意：pScanResult->strResult是在pattern中动态分配的内存，所以需要调用者使用完后释放掉
//
// 返回值:			true/false，标识是否发现系统/应用漏洞
//
// 修改记录：
//
// 其他:				
//--------------------------------------------------------------------------
VASCAN_API bool VAExecuteScan(VA_SCAN_CONTEXT* pScanContext, VA_SCAN_RESULT* &pScanResult);

//--------------------------------------------------------------------------
//
// 函数名称 :		VAExecuteScanWithArg			
//
// 描述 :			执行pattern扫描本地系统漏洞，并返回相关漏洞信息
//
// 输入参数:		pScanContext: lua解释器地址；
//                  szArg: 补丁管理扫描结果
//                     pScanResult: 输入时候pScanResult->strResult==NULL;
//                     pScanResult->dwLen==0
//
// 输出参数:		如果有结果返回, pScanResult->strResult为扫描结果的json格式字符串;
//                                                  pScanResult->dwLen, pScanResult->strResult的长度                                          
//                     注意：pScanResult->strResult是在pattern中动态分配的内存，所以需要调用者使用完后释放掉
//
// 返回值:			true/false，标识是否发现系统漏洞
//
// 修改记录：
//
// 其他:				
//--------------------------------------------------------------------------
VASCAN_API bool VAExecuteScanWithArg(VA_SCAN_CONTEXT* pScanContext, const char* szCVEInfo , const char* szKBInfo, VA_SCAN_RESULT* &pScanResult);

//--------------------------------------------------------------------------
//
// 函数名称 :		VAFreeScanResult			
//
// 描述 :			释放扫描结果内存空间
//
// 输入参数:			pScanResult: 包含扫描结果的json内容和长度
//
// 输出参数:			无
//
// 返回值:			true/false，标识空间释放是否成功
//
// 修改记录：		
//
// 其他:				
//--------------------------------------------------------------------------
VASCAN_API bool VAFreeScanResult(VA_SCAN_RESULT* &pScanResult);

//--------------------------------------------------------------------------
//
// 函数名称 :		VAGetPatternVersion			
//
// 描述 :			获取当前加载的pattern的版本号
//
// 输入参数:		pScanContext: lua解释器地址；
//                     OutVersion: 用于返回版本信息的字符串
//                     OutSize: 返回字符串的输入长度，此长度必须大于等于32;
//
// 输出参数:		如果有结果返回, OutVersion 会保存版本信息的值
//
// 返回值:			true/false，如果有错误，会返回false.
//
// 修改记录：		
//
// 其他:				
//--------------------------------------------------------------------------
VASCAN_API bool VAGetPatternVersion(VA_SCAN_CONTEXT* pScanContext, char* OutVersion, int OutSize);

//--------------------------------------------------------------------------
//
// 函数名称 :		VAGetEngineVersion			
//
// 描述 :			获取当前引擎的版本号
//
// 输入参数:		OutVersion: 用于返回版本信息的字符串
//                     OutSize: 返回字符串的输入长度，此长度必须大于等于32;
//
// 输出参数:		如果有结果返回, OutVersion 会保存版本信息的值
//
// 返回值:			true/false，如果有错误，会返回false.
//
// 修改记录：		
//
// 其他:				
//--------------------------------------------------------------------------			
VASCAN_API bool VAGetEngineVersion(char* OutVersion, int OutSize);

//--------------------------------------------------------------------------
//
// 函数名称 :		VACheckLeakRepairSupportOs		
//
// 描述 :			判断补丁管理是否支持当前操作系统
//
// 输入参数:			补丁管理扫描结果
//
// 输出参数:			无
//
// 返回值:			true/false，如果有错误，会返回false.
//
// 修改记录：		
//
// 其他:				
//--------------------------------------------------------------------------
VASCAN_API bool VACheckLeakRepairSupportOs(const char* szKBInfo);

//--------------------------------------------------------------------------
//
// 函数名称 :		VAUnInitialize			
//
// 描述 :			释放lua解释器，恢复全局变量到未初始化状态
//
// 输入参数:			pScanContext为lua解释器地址
//
// 输出参数:			无
//
// 返回值:			无
//
// 修改记录：		
//
// 其他:				
//--------------------------------------------------------------------------
VASCAN_API void VAUnInitialize(VA_SCAN_CONTEXT* pScanContext);

#ifdef __cplusplus
}
#endif
 
#endif
