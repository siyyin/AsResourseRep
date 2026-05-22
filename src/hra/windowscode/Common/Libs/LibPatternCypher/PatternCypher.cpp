#include "PatternCypher.h"
#include <string.h>
#include <time.h>
#include "cypher.h"
#include "md5.h"
#include "zlib/zlib.h"
#include "utility/Logger.h"

#define PATTERN_MAGIC "VA magic"

/// <summary>
/// 获得打包时间
/// </summary>
/// <param name="pszBuildTime"></param>
/// <param name="iLen"></param>
/// <returns></returns>
bool get_build_time(char* pszBuildTime, int iSize)
{
    if (!pszBuildTime || iSize <= 0)
    {
        return false;
    }
    time_t rawtime;
    struct tm timeinfo = {0};
    time(&rawtime);
    localtime_s(&timeinfo, &rawtime);
    _snprintf_s(pszBuildTime, iSize, iSize - 1, "%d/%d/%d %d:%d:%d", 1900 + timeinfo.tm_year, 1 + timeinfo.tm_mon,
                timeinfo.tm_mday, timeinfo.tm_hour, timeinfo.tm_min, timeinfo.tm_sec);
    return true;
}

/// <summary>
/// lua加密
/// 加密buff
/// </summary>
/// <param name="pInput"></param>
/// <param name="nInsize"></param>
/// <param name="pOutput"></param>
/// <param name="nOutsize"></param>
/// <returns></returns>
int LuaBuffEncode(const unsigned char* pOriginalBuf, unsigned long ulOriginalSize, int nVersion,
                  unsigned char** ppEncryptBuf, unsigned long& ulEncryptSize)
{
    LOG_INFO("LuaBuffEncode start! ulOriginalSize:%lu, nVersion:%d", ulOriginalSize, nVersion);
    int iRet = HRA_OK;

    unsigned char* pCompressBuf   = NULL;
    unsigned long  ulCompressSize = 0;
    PATTERN_HEADER pthHeader;
    memset(&pthHeader, 0, sizeof(pthHeader));

    CypherCtx en_ctx = NULL;
    MD5_CTX ctx;
    memset(&ctx, 0, sizeof(ctx));

    if (pOriginalBuf == NULL || ulOriginalSize <= 0 || ppEncryptBuf == NULL || *ppEncryptBuf != NULL)
    {
        iRet = HRA_BAD_PARAM;
        LOG_ERROR("Param NULL!");
        goto _exit;
    }
    
    ulCompressSize = compressBound(ulOriginalSize);
    LOG_DEBUG("ulCompressSize:%lu", ulCompressSize);
    if (ulCompressSize <= 0)
    {
        iRet = HRA_BAD_PARAM;
        LOG_ERROR("compressBound error! ulOriginalSize:%lu", ulOriginalSize);
        goto _exit;
    }

    pCompressBuf = (unsigned char*)malloc(ulCompressSize);
    if (!pCompressBuf)
    {
        iRet = HRA_MALLOC_FAIL;
        LOG_ERROR("malloc failed!");
        goto _exit;
    }
    memset(pCompressBuf, 0, ulCompressSize);

    //格式化数据头
    _snprintf_s(pthHeader.ptnMagic, sizeof(pthHeader.ptnMagic), "%s", PATTERN_MAGIC);
    _snprintf_s(pthHeader.ptnVersion, sizeof(pthHeader.ptnVersion), "%d", nVersion);
    get_build_time(pthHeader.ptnBuildTime, sizeof(pthHeader.ptnBuildTime));
    pthHeader.ptnOriginalSize = ulOriginalSize;

    //压缩原始数据
    if (compress((Bytef*)pCompressBuf, &ulCompressSize, (const Bytef*)pOriginalBuf, ulOriginalSize) != Z_OK)
    {
        iRet = HRA_FAILED;
        LOG_ERROR("compress failed! ulCompressSize:%lu, ulOriginalSize:%lu", ulCompressSize, ulOriginalSize);
        goto _exit;
    }
    LOG_DEBUG("compress succeed! ulCompressSize:%lu", ulCompressSize);

    pthHeader.ptnCompressSize = ulCompressSize;
    ulEncryptSize             = sizeof(pthHeader) + ulCompressSize + MD5LEN;
    *ppEncryptBuf               = (unsigned char*)malloc(ulEncryptSize);
    if (*ppEncryptBuf == NULL)
    {
        iRet = HRA_MALLOC_FAIL;
        LOG_ERROR("malloc failed!");
        goto _exit;
    }
    memset(*ppEncryptBuf, 0, ulEncryptSize);
    LOG_DEBUG("ulEncryptSize:%lu", ulEncryptSize);

    memcpy(*ppEncryptBuf, &pthHeader, sizeof(pthHeader)); //拷贝数据头
    //加密数据体
    if (CypherInit(&en_ctx, ~pthHeader.ptnOriginalSize, ~pthHeader.ptnCompressSize) != PCE_SUCCESS)
    {
        iRet = HRA_FAILED;
        LOG_ERROR("CypherInit failed! ptnOriginalSize:%lu, ptnCompressSize:%lu", pthHeader.ptnOriginalSize,
                  pthHeader.ptnCompressSize);
        goto _exit;
    }
    if (CypherEncrypt(en_ctx, (PCE_UCHAR*)pCompressBuf, (PCE_UCHAR*)(*ppEncryptBuf + sizeof(pthHeader)),
                      ulCompressSize) != PCE_SUCCESS)
    {
        iRet = HRA_FAILED;
        LOG_ERROR("CypherEncrypt failed! ptnOriginalSize:%lu, ptnCompressSize:%lu", pthHeader.ptnOriginalSize,
                  pthHeader.ptnCompressSize);
        goto _exit;
    }
    //计算MD5
    __VSMD5Init(&ctx);
    __VSMD5Update(&ctx, (unsigned char*)*ppEncryptBuf, sizeof(pthHeader) + ulCompressSize);
    __VSMD5Final(&ctx);
    memcpy(*ppEncryptBuf + sizeof(pthHeader) + ulCompressSize, ctx.digest, sizeof(ctx.digest));
    LOG_INFO("LuaBuffEncode succeed! size:%lu", ulOriginalSize);

_exit:
    if (pCompressBuf)
    {
        free(pCompressBuf);
        pCompressBuf = NULL;
    }

    if (iRet != HRA_OK && *ppEncryptBuf != NULL)
    {
        free(*ppEncryptBuf);
        *ppEncryptBuf = NULL;
    }

    if (en_ctx)
    {
        free(en_ctx);
        en_ctx = NULL;
    }

    return iRet;
}

/// <summary>
/// lua解密
/// 解密buff
/// </summary>
/// <param name="pInput"></param>
/// <param name="nInsize"></param>
/// <param name="pOutput"></param>
/// <param name="nOutsize"></param>
/// <returns></returns>
int LuaBuffDecode(const unsigned char* pEncryptBuf, unsigned long ulEncryptSize, int& nVersion,
                  unsigned char** ppOriginalBuf, unsigned long& ulOriginalSize)
{
    LOG_INFO("LuaBuffDecode start! ulEncryptSize:%lu", ulEncryptSize);
    int iRet = HRA_OK;
    PATTERN_HEADER stPatternHeader;
    memset(&stPatternHeader, 0, sizeof(stPatternHeader));
    CypherCtx en_ctx             = NULL;
    unsigned char* pCompressBuf  = NULL;
    unsigned long ulCompressSize = 0;
    //unsigned char* pOriginalBuf  = NULL;

    if (pEncryptBuf == NULL || ulEncryptSize <= 0 || ppOriginalBuf == NULL || *ppOriginalBuf != NULL)
    {
        iRet = HRA_BAD_PARAM;
        LOG_ERROR("Param NULL!");
        goto _exit;
    }

    if (ulEncryptSize <= sizeof(stPatternHeader) + MD5LEN)
    {
        iRet = HRA_BAD_PARAM;
        LOG_ERROR("ulEncryptSize:%lu error!", ulEncryptSize);
        goto _exit;
    }

    //数据部分md5校验
    MD5_CTX ctx;
    __VSMD5Init(&ctx);
    __VSMD5Update(&ctx, pEncryptBuf, ulEncryptSize - MD5LEN); // 数据部分md5校验
    __VSMD5Final(&ctx);
    if (memcmp(pEncryptBuf + ulEncryptSize - MD5LEN, ctx.digest, MD5LEN) != 0)
    {
        iRet = HRA_FAILED;
        LOG_ERROR("memcmp error!");
        goto _exit;
    }

    memcpy(&stPatternHeader, pEncryptBuf, sizeof(stPatternHeader));
    ulOriginalSize = stPatternHeader.ptnOriginalSize;
    ulCompressSize = stPatternHeader.ptnCompressSize;
    LOG_DEBUG("ulOriginalSize:%lu, ulCompressSize:%lu", ulOriginalSize, ulCompressSize);

    if (ulOriginalSize <= 0 || ulCompressSize <= 0)
    {
        iRet = HRA_COND_CHK_FAIL;
        LOG_ERROR("ulOriginalSize:%lu or ulCompressSize:%lu error!", ulOriginalSize, ulCompressSize);
        goto _exit;
    }

    //解密数据
    pCompressBuf = (unsigned char*)malloc(ulCompressSize);
    if (!pCompressBuf)
    {
        iRet = HRA_NULL_PTR;
        LOG_ERROR("malloc error!");
        goto _exit;
    }
    memset(pCompressBuf, 0, ulCompressSize);
    if (CypherInit(&en_ctx, ~stPatternHeader.ptnOriginalSize, ~stPatternHeader.ptnCompressSize) != PCE_SUCCESS)
    {
        iRet = HRA_FAILED;
        LOG_ERROR("CypherInit error! ptnOriginalSize:%lu, ptnCompressSize:%lu", stPatternHeader.ptnOriginalSize,
                  stPatternHeader.ptnCompressSize);
        goto _exit;
    }
    if (CypherDecrypt(en_ctx, (PCE_UCHAR*)(pEncryptBuf + sizeof(stPatternHeader)), (PCE_UCHAR*)pCompressBuf,
                      ulCompressSize) != PCE_SUCCESS)
    {
        iRet = HRA_FAILED;
        LOG_ERROR("CypherDecrypt error! ptnOriginalSize:%lu, ptnCompressSize:%lu", stPatternHeader.ptnOriginalSize,
                  stPatternHeader.ptnCompressSize);
        goto _exit;
    }
    LOG_DEBUG("Buff decrypt succeed! ulCompressSize:%lu", ulCompressSize);

    //解压数据
    *ppOriginalBuf = (unsigned char*)malloc(ulOriginalSize + 1);
    if (*ppOriginalBuf == NULL)
    {
        iRet = HRA_NULL_PTR;
        LOG_ERROR("malloc error!");
        goto _exit;
    }
    memset(*ppOriginalBuf, 0, ulOriginalSize + 1);
    if (uncompress((Bytef*)*ppOriginalBuf, &ulOriginalSize, (const Bytef*)pCompressBuf, ulCompressSize) != Z_OK)
    {
        iRet = HRA_FAILED;
        LOG_ERROR("uncompress error!");
        goto _exit;
    }
    LOG_DEBUG("Buff uncompress succeed! ulCompressSize:%lu", ulCompressSize);

    try
    {
        nVersion = atoi(stPatternHeader.ptnVersion);
    }
    catch (...)
    {
        iRet     = HRA_FAILED;
        nVersion = 0;
        LOG_ERROR("atoi error! version:%s", stPatternHeader.ptnVersion);
        goto _exit;
    }

    LOG_INFO("LuaBuffDecode succeed! size:%lu, version:%d", ulOriginalSize, nVersion);

_exit:
    if (pCompressBuf != NULL)
    {
        free(pCompressBuf);
        pCompressBuf = NULL;
    }

    if (iRet != HRA_OK)
    {
        if (*ppOriginalBuf != NULL)
        {
            free(*ppOriginalBuf);
            *ppOriginalBuf = NULL;
            ulOriginalSize = 0;
        }
    }

    if (en_ctx)
    {
        free(en_ctx);
        en_ctx = NULL;
    }

    return iRet;
}

/// <summary>
/// 释放pOutput申请的内存
/// </summary>
/// <param name="ppBuff"></param>
void FreeCypherBuff(unsigned char** ppBuff)
{
    if (ppBuff != NULL && *ppBuff != NULL)
    {
        free(*ppBuff);
        *ppBuff = NULL;
    }
}
