#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "DolphinNTLMCode.h"
#include "hash_md4.h"
#include <Windows.h>

//Init values
//#define INIT_A 0x67452301
//#define INIT_B 0xefcdab89
//#define INIT_C 0x98badcfe
//#define INIT_D 0x10325476
//
//#define SQRT_2 0x5a827999
//#define SQRT_3 0x6ed9eba1

const char itoa16[16] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};


//void ntlm_crypt(const unsigned int nt_buffer[16], unsigned int output[4])
//{
//    unsigned int a = INIT_A;
//    unsigned int b = INIT_B;
//    unsigned int c = INIT_C;
//    unsigned int d = INIT_D;
//
//    /* Round 1 */
//    a += (d ^ (b & (c ^ d))) + nt_buffer[0]; a = (a << 3) | (a >> 29);
//    d += (c ^ (a & (b ^ c))) + nt_buffer[1]; d = (d << 7) | (d >> 25);
//    c += (b ^ (d & (a ^ b))) + nt_buffer[2]; c = (c << 11) | (c >> 21);
//    b += (a ^ (c & (d ^ a))) + nt_buffer[3]; b = (b << 19) | (b >> 13);
//
//    a += (d ^ (b & (c ^ d))) + nt_buffer[4]; a = (a << 3) | (a >> 29);
//    d += (c ^ (a & (b ^ c))) + nt_buffer[5]; d = (d << 7) | (d >> 25);
//    c += (b ^ (d & (a ^ b))) + nt_buffer[6]; c = (c << 11) | (c >> 21);
//    b += (a ^ (c & (d ^ a))) + nt_buffer[7]; b = (b << 19) | (b >> 13);
//
//    a += (d ^ (b & (c ^ d))) + nt_buffer[8]; a = (a << 3) | (a >> 29);
//    d += (c ^ (a & (b ^ c))) + nt_buffer[9]; d = (d << 7) | (d >> 25);
//    c += (b ^ (d & (a ^ b))) + nt_buffer[10]; c = (c << 11) | (c >> 21);
//    b += (a ^ (c & (d ^ a))) + nt_buffer[11]; b = (b << 19) | (b >> 13);
//
//    a += (d ^ (b & (c ^ d))) + nt_buffer[12]; a = (a << 3) | (a >> 29);
//    d += (c ^ (a & (b ^ c))) + nt_buffer[13]; d = (d << 7) | (d >> 25);
//    c += (b ^ (d & (a ^ b))) + nt_buffer[14]; c = (c << 11) | (c >> 21);
//    b += (a ^ (c & (d ^ a))) + nt_buffer[15]; b = (b << 19) | (b >> 13);
//
//    /* Round 2 */
//    a += ((b & (c | d)) | (c & d)) + nt_buffer[0] + SQRT_2; a = (a << 3) | (a >> 29);
//    d += ((a & (b | c)) | (b & c)) + nt_buffer[4] + SQRT_2; d = (d << 5) | (d >> 27);
//    c += ((d & (a | b)) | (a & b)) + nt_buffer[8] + SQRT_2; c = (c << 9) | (c >> 23);
//    b += ((c & (d | a)) | (d & a)) + nt_buffer[12] + SQRT_2; b = (b << 13) | (b >> 19);
//
//    a += ((b & (c | d)) | (c & d)) + nt_buffer[1] + SQRT_2; a = (a << 3) | (a >> 29);
//    d += ((a & (b | c)) | (b & c)) + nt_buffer[5] + SQRT_2; d = (d << 5) | (d >> 27);
//    c += ((d & (a | b)) | (a & b)) + nt_buffer[9] + SQRT_2; c = (c << 9) | (c >> 23);
//    b += ((c & (d | a)) | (d & a)) + nt_buffer[13] + SQRT_2; b = (b << 13) | (b >> 19);
//
//    a += ((b & (c | d)) | (c & d)) + nt_buffer[2] + SQRT_2; a = (a << 3) | (a >> 29);
//    d += ((a & (b | c)) | (b & c)) + nt_buffer[6] + SQRT_2; d = (d << 5) | (d >> 27);
//    c += ((d & (a | b)) | (a & b)) + nt_buffer[10] + SQRT_2; c = (c << 9) | (c >> 23);
//    b += ((c & (d | a)) | (d & a)) + nt_buffer[14] + SQRT_2; b = (b << 13) | (b >> 19);
//
//    a += ((b & (c | d)) | (c & d)) + nt_buffer[3] + SQRT_2; a = (a << 3) | (a >> 29);
//    d += ((a & (b | c)) | (b & c)) + nt_buffer[7] + SQRT_2; d = (d << 5) | (d >> 27);
//    c += ((d & (a | b)) | (a & b)) + nt_buffer[11] + SQRT_2; c = (c << 9) | (c >> 23);
//    b += ((c & (d | a)) | (d & a)) + nt_buffer[15] + SQRT_2; b = (b << 13) | (b >> 19);
//
//    /* Round 3 */
//    a += (d ^ c ^ b) + nt_buffer[0] + SQRT_3; a = (a << 3) | (a >> 29);
//    d += (c ^ b ^ a) + nt_buffer[8] + SQRT_3; d = (d << 9) | (d >> 23);
//    c += (b ^ a ^ d) + nt_buffer[4] + SQRT_3; c = (c << 11) | (c >> 21);
//    b += (a ^ d ^ c) + nt_buffer[12] + SQRT_3; b = (b << 15) | (b >> 17);
//
//    a += (d ^ c ^ b) + nt_buffer[2] + SQRT_3; a = (a << 3) | (a >> 29);
//    d += (c ^ b ^ a) + nt_buffer[10] + SQRT_3; d = (d << 9) | (d >> 23);
//    c += (b ^ a ^ d) + nt_buffer[6] + SQRT_3; c = (c << 11) | (c >> 21);
//    b += (a ^ d ^ c) + nt_buffer[14] + SQRT_3; b = (b << 15) | (b >> 17);
//
//    a += (d ^ c ^ b) + nt_buffer[1] + SQRT_3; a = (a << 3) | (a >> 29);
//    d += (c ^ b ^ a) + nt_buffer[9] + SQRT_3; d = (d << 9) | (d >> 23);
//    c += (b ^ a ^ d) + nt_buffer[5] + SQRT_3; c = (c << 11) | (c >> 21);
//    b += (a ^ d ^ c) + nt_buffer[13] + SQRT_3; b = (b << 15) | (b >> 17);
//
//    a += (d ^ c ^ b) + nt_buffer[3] + SQRT_3; a = (a << 3) | (a >> 29);
//    d += (c ^ b ^ a) + nt_buffer[11] + SQRT_3; d = (d << 9) | (d >> 23);
//    c += (b ^ a ^ d) + nt_buffer[7] + SQRT_3; c = (c << 11) | (c >> 21);
//    b += (a ^ d ^ c) + nt_buffer[15] + SQRT_3; b = (b << 15) | (b >> 17);
//
//    memset(output, 0, 4 * 4);
//    output[0] = a + INIT_A;
//    output[1] = b + INIT_B;
//    output[2] = c + INIT_C;
//    output[3] = d + INIT_D;
//}

// 这包括 Unicode 转换和填充
//void prepare_key(const char* key, unsigned int nt_buffer[16])
//{
//    int i = 0;
//    int length = (int)strlen(key);
//    memset(nt_buffer, 0, 16 * 4);
//    //The length of key need to be <= 27
//    for (; i < length / 2; i++)
//    {
//        nt_buffer[i] = key[2 * i] | (key[2 * i + 1] << 16);
//    }
//
//    if (length % 2 == 1)
//    {
//        nt_buffer[i] = key[length - 1] | 0x800000;
//    }
//    else
//    {
//        nt_buffer[i] = 0x80;
//    }
//
//    nt_buffer[14] = length << 4;
//}

//这会将输出转换为十六进制形式
void convert_hex(const unsigned int output[4], char hex_format[33])
{
    memset(hex_format, 0, 33);
    //Iterate the integer
    for (int i = 0; i < 4; i++)
    {
        int j = 0;
        unsigned int n = output[i];
        //iterate the bytes of the integer		
        for (; j < 4; j++)
        {
            unsigned int convert = n % 256;
            hex_format[i * 8 + j * 2 + 1] = itoa16[convert % 16];
            convert = convert / 16;
            hex_format[i * 8 + j * 2 + 0] = itoa16[convert % 16];
            n = n / 256;
        }
    }
    //null terminate the string
    hex_format[32] = 0;
}


//int dolphin_hash_code(const char* szPasswd, char hex_format[33])
//{
//    if (szPasswd == NULL)
//    {
//        return -1;
//    }
//
//    int nlen = (int)strlen(szPasswd);
//    if (nlen > 27)
//    {
//        return -2;
//    }
//
//    unsigned int nt_buffer[16];
//    prepare_key(szPasswd, nt_buffer);
//    unsigned int output[4];
//    ntlm_crypt(nt_buffer, output);
//    convert_hex(output, hex_format);
//
//    return 0;
//}

int dolphin_hash(const char* pszPasswd, char* pszHash, int nSize)
{
    if (pszPasswd == NULL || pszHash == NULL || nSize <= MD4_DIGEST_SIZE * 2)
    {
        return -1;
    }

    ////低位补0
    //int nPwdLen = (int)strlen(pszPasswd);
    //int nUniPwdLen = nPwdLen * 2;
    //char* pszUniPwd = (char*)malloc(nUniPwdLen+1);
    //if (pszUniPwd == NULL)
    //{
    //    return -2;
    //}
    //memset(pszUniPwd, 0, nUniPwdLen + 1);
    //for (int i = 0; i < nPwdLen; ++i)
    //{
    //    pszUniPwd[i * 2] = pszPasswd[i];
    //    pszUniPwd[i * 2 + 1] = '\0';
    //}

    //Unicode转换
    int nUlen = ::MultiByteToWideChar(CP_UTF8, 0, pszPasswd, -1, NULL, 0);
    if (nUlen < 0)
    {
        return -2;
    }
    int nBuffSize = (nUlen + 1) * sizeof(wchar_t);
    wchar_t* pszUniPwd = (wchar_t*)malloc(nBuffSize);
    if (pszUniPwd == NULL)
    {
        return -3;
    }
    memset(pszUniPwd, 0, nBuffSize);
    ::MultiByteToWideChar(CP_UTF8, 0, pszPasswd, -1, (LPWSTR)pszUniPwd, nUlen);
    int nUstrLen = lstrlenW(pszUniPwd);
    if (nUstrLen < 0)
    {
        return -4;
    }

    //MD4
    unsigned char szMd4Hash[MD4_DIGEST_SIZE];
    memset(szMd4Hash, 0, sizeof(szMd4Hash));
    hash_md4((const unsigned char*)pszUniPwd, nUstrLen * sizeof(wchar_t), szMd4Hash);

    //转换16进制字符串
    memset(pszHash, 0, nSize);
    convert_hex((const unsigned int*)szMd4Hash, pszHash);

    if (pszUniPwd)
    {
        free(pszUniPwd);
        pszUniPwd = NULL;
    }

    return 0;
}