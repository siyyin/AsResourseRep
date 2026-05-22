// AttackIO.cpp : Defines the exported functions for the DLL application.
//
#ifdef _WIN32
#include <windows.h>
#else
#include <string.h>
#include <wchar.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#endif
#include<string>
#include<stdexcept>
#include "../include/VAScan.h"
#include "./ExtendFunc/ExtendFunc.h"
#include "../cypher/cypher.h"
#include "../include/zlib/zlib.h"
#include "../md5/md5.h"
#include "VAScanVersion.h"
#ifdef _WIN32
#define SNPRINT sprintf_s
#else 
#define SNPRINT  snprintf
#endif

const int  g_iErrBufLen = 1024;
PATTERN_HEADER g_pthHeader = {0};

static int manal_atpanic(lua_State* L) {
	const char* message = lua_tostring(L, -1);
	if (message != NULL)
		throw  std::runtime_error(message);
	else 
		throw std::runtime_error("An unexpected error occurred and forced the lua state to call atpanic");
}

#ifndef _WIN32
typedef int INT32;
void strncpy_s(char *dest, INT32 dmax, const char *src, INT32 slen)
{
    INT32 orig_dmax;
    char *orig_dest;
    const char *overlap_bumper;

    if (src == NULL || dest == NULL) {
        return;
    }

    if (dmax == 0) {
        return;
    }

    /* hold base in case src was not copied */
    orig_dmax = dmax;
    orig_dest = dest;

    if (slen == 0) {
        return;
    }

    if (dest < src) {
        overlap_bumper = src;

        while (dmax > 0) {
            if (dest == overlap_bumper) {
                return;
            }

            if (slen == 0) {
/*
 * Copying truncated to slen chars.  Note that the TR says to
 * copy slen chars plus the null char.  We null the slack.
 */
#ifdef SAFECLIB_STR_NULL_SLACK
                while (dmax) {
                    *dest = '\0';
                    dmax--;
                    dest++;
                }
#else
                *dest = '\0';
#endif
                return;
            }

            *dest = *src;
            if (*dest == '\0') {
#ifdef SAFECLIB_STR_NULL_SLACK
                /* null slack */
                while (dmax) {
                    *dest = '\0';
                    dmax--;
                    dest++;
                }
#endif
                return;
            }

            dmax--;
            slen--;
            dest++;
            src++;
        }

    } else {
        overlap_bumper = dest;

        while (dmax > 0) {
            if (src == overlap_bumper) {
                return;
            }

            if (slen == 0) {
/*
 * Copying truncated to slen chars.  Note that the TR says to
 * copy slen chars plus the null char.  We null the slack.
 */
#ifdef SAFECLIB_STR_NULL_SLACK
                while (dmax) {
                    *dest = '\0';
                    dmax--;
                    dest++;
                }
#else
                *dest = '\0';
#endif
                return;
            }

            *dest = *src;
            if (*dest == '\0') {
#ifdef SAFECLIB_STR_NULL_SLACK
                /* null slack */
                while (dmax) {
                    *dest = '\0';
                    dmax--;
                    dest++;
                }
#endif
                return;
            }

            dmax--;
            slen--;
            dest++;
            src++;
        }
    }

    /*
   * the entire src was not copied, so zero the string
   */
    return;
}
#endif

// 初始化VA引擎
VA_SCAN_CONTEXT* VAInitialize(void)
{
    initExtend();
	// 创建lua解释器
	VA_SCAN_CONTEXT* pScanContext = new VA_SCAN_CONTEXT;
	if (!pScanContext)
		return NULL;

	memset(pScanContext, 0, sizeof(VA_SCAN_CONTEXT));
	pScanContext->pszErrorMsg = new char[g_iErrBufLen];
	if (!pScanContext->pszErrorMsg) {
		delete  pScanContext;
		return NULL;
	}
	memset(pScanContext->pszErrorMsg, 0, g_iErrBufLen);
	pScanContext->pLuaState = (void*)luaL_newstate();
	if (pScanContext->pLuaState == NULL){
		delete []pScanContext->pszErrorMsg; 
		delete  pScanContext;
		return NULL;
	} 
	// 载入Lua解释器会用到库
	luaL_openlibs((lua_State*)pScanContext->pLuaState);
	//注册扩展函数
	luaL_register((lua_State*)pScanContext->pLuaState, "extendFunc", extendFunc);
	lua_atpanic((lua_State*)pScanContext->pLuaState, manal_atpanic);
	return pScanContext;
}

// VA引擎加载Pattern
bool VALoadPattern(VA_SCAN_CONTEXT* pScanContext, const char* strPatternFilePath)
{
	FILE* fEncrypt = NULL;
	char* pOriginalBuf = NULL, *pCompressBuf = NULL, *pEncryptBuf = NULL;
	CypherCtx en_ctx = NULL;
	unsigned long ulOriginalSize = 0, ulCompressSize = 0, ulEncryptSize = 0;
	bool bLoadSuccss = false;
	int iRet = 0;

	// 参数校验
	if (!pScanContext || !strPatternFilePath ||  strlen(strPatternFilePath) == 0)
	    return false;
	
	//加载pattern并且解密
#ifdef _WIN32
	fopen_s(&fEncrypt, strPatternFilePath, "rb");
#else 
	fEncrypt = fopen(strPatternFilePath, "rb");
#endif // _WIN32
	if (!fEncrypt) {
		goto load_finish;
	}
	//读入加密pattern内容，校验MD5, 解析pattern header
	fseek(fEncrypt, 0, SEEK_END);
	ulEncryptSize = ftell(fEncrypt);
	if (ulEncryptSize <= sizeof(g_pthHeader) + MD5LEN) 
		goto load_finish;

	pEncryptBuf = new char[ulEncryptSize];
	if (!pEncryptBuf) 
		goto load_finish;

	memset(pEncryptBuf, 0, ulEncryptSize);
	fseek(fEncrypt, 0, SEEK_SET);
	fread(pEncryptBuf, ulEncryptSize, 1, fEncrypt);
	MD5_CTX ctx;
    __VSMD5Init(&ctx);
    __VSMD5Update(&ctx, (unsigned char*)pEncryptBuf, ulEncryptSize - MD5LEN);  // 数据部分md5校验
    __VSMD5Final(&ctx);
	if (memcmp(pEncryptBuf + ulEncryptSize - MD5LEN, ctx.digest, MD5LEN) != 0)
	{
		//printf("pattern md5 check is failed\n");
		goto load_finish;
	}
	memcpy(&g_pthHeader, pEncryptBuf, sizeof(g_pthHeader));
	ulOriginalSize = g_pthHeader.ptnOriginalSize;
	ulCompressSize = g_pthHeader.ptnCompressSize;
	//解密数据
	pCompressBuf = new char[ulCompressSize];
	if (!pCompressBuf)
	{
		//printf("new compress memory failed\n");
		goto load_finish;
	}
	memset(pCompressBuf, 0, ulCompressSize);

	if (CypherInit(&en_ctx, ~g_pthHeader.ptnOriginalSize, ~g_pthHeader.ptnCompressSize) != PCE_SUCCESS)
	{
		//printf("decrypt init failed\n");
		goto load_finish;	
	}
	if (CypherDecrypt(en_ctx, (PCE_UCHAR*)(pEncryptBuf + sizeof(g_pthHeader)), (PCE_UCHAR*)pCompressBuf, ulCompressSize)
		!= PCE_SUCCESS)
	{
		//printf("decrypt failed\n");
		goto load_finish;	
	}
	//解压数据
	pOriginalBuf = new char[ulOriginalSize + 1];
	if (!pOriginalBuf)
	{
		printf("new original memory failed\n");
		goto load_finish;
	}
	memset(pOriginalBuf, 0, ulOriginalSize + 1);
	if(uncompress((Bytef*)pOriginalBuf, &ulOriginalSize, (const Bytef*)pCompressBuf, ulCompressSize) != Z_OK)  
	{  
		//printf("uncompress failed!\n");  
		goto load_finish;
	} 

	iRet =  luaL_dostring((lua_State*)pScanContext->pLuaState, pOriginalBuf);
	if (iRet)
	{
		SNPRINT(pScanContext->pszErrorMsg, g_iErrBufLen, "%s", lua_tostring((lua_State*)pScanContext->pLuaState, -1));
		lua_pop((lua_State*)pScanContext->pLuaState, -1);
	}
	else
	    bLoadSuccss = true;
load_finish:
	if (pOriginalBuf)
		delete[] pOriginalBuf;
	if (pCompressBuf)
		delete[] pCompressBuf;
	if (pEncryptBuf)
		delete[] pEncryptBuf;
	if (fEncrypt)
		fclose(fEncrypt);
	if (en_ctx)
		free(en_ctx);
	return bLoadSuccss;
}

bool VAExecuteScan(VA_SCAN_CONTEXT* pScanContext, VA_SCAN_RESULT* &pScanResult)
{
	bool Status = false;
	//参数检查
	if (!pScanContext)
		return false;

	memset(pScanContext->pszErrorMsg, 0, g_iErrBufLen);
    ResetFileCache();
	// 扫描函数入栈
	lua_getglobal((lua_State*)pScanContext->pLuaState, "ScanFun");
	if (!lua_isfunction((lua_State*)pScanContext->pLuaState, -1))
	{
		SNPRINT(pScanContext->pszErrorMsg, g_iErrBufLen, "%s", lua_tostring((lua_State*)pScanContext->pLuaState, -1));
		// lua_pop((lua_State*)pScanContext->pLuaState, -1);
		return false;
	}

	// 扫描参数入栈
#ifdef _WIN32
	__try {
#endif // _WIN32
		do {
			//lua_pushstring((lua_State*)pScanContext->pLuaState, strInputEvent);		   // 参数strInputEvent压入栈
			//lua_pushnumber((lua_State*)pScanContext->pLuaState, dwInputLen);       // 参数dwInputLen压入栈
			// 执行扫描函数
			if (lua_pcall((lua_State*)pScanContext->pLuaState, 0, 1, 0) != 0)
			{
				SNPRINT(pScanContext->pszErrorMsg, g_iErrBufLen, "VAExecuteScan with error %s", \
					            lua_tostring((lua_State*)pScanContext->pLuaState, -1));
				break;
			}
			// 从虚拟栈中取出扫描结果
			if (!lua_isstring((lua_State*)pScanContext->pLuaState, -1)) 
			{
				break;
			}
			// 获取返回字符串的字符个数
			unsigned int iResultLen = (unsigned int)strlen(lua_tostring((lua_State*)pScanContext->pLuaState, -1));
			if (iResultLen > 0)
			{
				pScanResult = new VA_SCAN_RESULT;
				if (!pScanResult)
				{
					SNPRINT(pScanContext->pszErrorMsg, g_iErrBufLen, "alloc Scan Result Memory failed");
					break;
				}
				else
				{
					pScanResult->dwLen = 0;
					pScanResult->strResult = NULL;
				}
				pScanResult->strResult = new char[iResultLen + 1];
				if (!pScanResult->strResult)
				{
					SNPRINT(pScanContext->pszErrorMsg, g_iErrBufLen, "alloc result memory failed");
					delete pScanResult;
					pScanResult = NULL;
					break;
				}
				else
				{
					memset(pScanResult->strResult, 0, iResultLen + 1);
					pScanResult->dwLen = iResultLen + 1;
					const char * x = lua_tostring((lua_State*)pScanContext->pLuaState, -1);
					strncpy_s(pScanResult->strResult, pScanResult->dwLen, x, iResultLen);
					Status = true;
				}
			}
		} while (false);
		lua_pop((lua_State*)pScanContext->pLuaState, 1);

#ifdef _WIN32
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return false;
	}
#endif
	return Status;
}

// 释放扫描结果所占内存
bool VAFreeScanResult(VA_SCAN_RESULT* &pScanResult)
{
	if (!pScanResult)
		return false;
	if (pScanResult->strResult)
	{
		delete []pScanResult->strResult;
		pScanResult->strResult = NULL;
	}
	 
	delete pScanResult; 
	pScanResult = NULL;
	return true;
}

// 恢复IOA引擎到未初始化状态
void VAUnInitialize(VA_SCAN_CONTEXT* pScanContext)
{
	if (!pScanContext)
		return;
	
    if (pScanContext->pLuaState)
        lua_close((lua_State*)pScanContext->pLuaState);	

	if (pScanContext->pszErrorMsg)
		delete []pScanContext->pszErrorMsg;

	delete pScanContext;
	pScanContext = NULL;

    FreeExtend();
	return;
}

bool VAGetPatternVersion(VA_SCAN_CONTEXT* pScanContext, char* OutVersion, int OutSize)
{
	if (!pScanContext || !pScanContext->pLuaState) 
		return false;

	if (!OutVersion || OutSize < MAX_LEN_64 || strlen(g_pthHeader.ptnVersion) == 0)
		return false;

  char ptnVersion[MAX_LEN_64] = {0};
  char ver1[5] = {0};
  char ver2[5] = {0};
  char ver3[5] = {0};

  memcpy(ver1,g_pthHeader.ptnVersion,2);
  memcpy(ver2,g_pthHeader.ptnVersion+2,2);
  memcpy(ver3,g_pthHeader.ptnVersion+5,4);
#ifdef _WIN32
  sprintf_s(ptnVersion, "%d.%d.0.%d", atoi(ver1),atoi(ver2),atoi(ver3)%1000);
#else
  sprintf(ptnVersion, "%d.%d.0.%d", atoi(ver1),atoi(ver2),atoi(ver3)%1000);
#endif
	strncpy_s(OutVersion, OutSize, ptnVersion, sizeof(ptnVersion));
	return true;
}

bool VAGetEngineVersion(char* OutVersion, int OutSize)
{
	if (!OutVersion || OutSize < MAX_LEN_64)
		return false;

	strncpy_s(OutVersion, OutSize, TM_VERSION_BUILD_SZ, strlen(TM_VERSION_BUILD_SZ));
	return true;
}