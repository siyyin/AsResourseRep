#ifndef __HRA_JSON_H__
#define __HRA_JSON_H__
#include <fstream>
#include "json/json.h"
#include "comm.h"
#include "Logger.h"

std::string HRA_UTILITY_EXPORT GetRegsterInfo(void);
std::string HRA_UTILITY_EXPORT GetReportResultInfo(const char* pscTaskId, int lErrorCode, const char* pstrBuff,
                                                   int nRetLogLevel = LOG_LEVEL_INFO);
std::string HRA_UTILITY_EXPORT GetReportJsonBody(unsigned char ucMsgType, const char *pscContentData, 
							  unsigned int ulContentLen, unsigned char ucMsgCompression);
Json::Value HRA_UTILITY_EXPORT StringToJson(const char *pscJsonData, unsigned int ulJsonDataLen);
std::string HRA_UTILITY_EXPORT JsonToString(const Json::Value& jsObj);
Json::Value HRA_UTILITY_EXPORT FileToJson(const char *pscFilePath);
std::string HRA_UTILITY_EXPORT GetReportPatternUpdateResult(int lErrorCode, int lCmdType, 
										 std::string strModlue, const std::string &strVersion);
Json::Value HRA_UTILITY_EXPORT GetCommandDataFromArrayCmd(const Json::Value& jsArrayCmd);
#endif /* __HRA_JSON_H__ */