#pragma once

#ifdef __cplusplus
extern "C"
{
#endif

    #define MAX_LEN_64 64
    typedef struct _PATTERN_HEADER
    {
        char ptnMagic[MAX_LEN_64];     // pattern识别标识
        char ptnVersion[MAX_LEN_64];   // pattern 版本号
        char ptnBuildTime[MAX_LEN_64]; // pattern build时间
        unsigned int ptnOriginalSize;  // pattern原始文件大小
        unsigned int ptnCompressSize;  // pattern压缩和加密之后大小
    } PATTERN_HEADER;

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
                      unsigned char** ppEncryptBuf, unsigned long& ulEncryptSize);

    /// <summary>
    /// lua解密
    /// 解密buff
    /// </summary>
    /// <param name="pEncryptBuf"></param>
    /// <param name="nEncryptSize"></param>
    /// <param name="pOriginalBuf"></param>
    /// <param name="nOriginaSize"></param>
    /// <returns></returns>
    int LuaBuffDecode(const unsigned char* pEncryptBuf, unsigned long ulEncryptSize, int& nVersion,
                      unsigned char** ppOriginalBuf, unsigned long& ulOriginalSize);

    /// <summary>
    /// 释放pOutput申请的内存
    /// </summary>
    /// <param name="ppBuff"></param>
    void FreeCypherBuff(unsigned char** ppBuff);


#ifdef __cplusplus
}
#endif