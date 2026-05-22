#ifndef DIAGENT_STRINGUTILS_H
#define DIAGENT_STRINGUTILS_H
#include <string>
#include <vector>
namespace di_rest_client
{

std::string WcharToString(std::wstring& src);
std::string WcharToString(const wchar_t* src);

std::wstring StringToWchar(std::string& src);
std::wstring StringToWchar(const char* src);

#ifdef _WIN32
std::string UnicodeToString(std::wstring& src);
std::string UnicodeToString(const wchar_t* src);

std::wstring StringToUnicode(std::string& src);
std::wstring StringToUnicode(const char* src);

std::string UnicodeToUtf8String(std::wstring& src);
std::string UnicodeToUtf8String(const wchar_t* src);
#endif

bool StrEqual(const char* pszText1, const char* pszText2);
bool StrEqual(const wchar_t* pszText1, const wchar_t* pszText2);

#ifdef _WIN32
bool StartWithIgnoreCase(const wchar_t* pszText, const wchar_t* pszPrefix);
#endif
bool EndWithIgnoreCase(const wchar_t* pszText, const wchar_t* pszSuffix);

bool StrEndWith(const char* pszText, const char* pszPostfix);

void RemovePrefix(wchar_t* pszText, const wchar_t* pszPrefix);

void SplitString(const std::string& content, const std::string& delimiter, std::vector<std::string>* result);

bool SplitString(std::string str, const char * spit, std::string & before, std::string & after);

std::string & StrReplace(std::string & str, const std::string & old_value, const std::string & new_value);

std::string Base64Encode(unsigned char const* buffer, unsigned int len);

int Binary2CStr(const unsigned char* inbuff, unsigned int inlen, char* outbuff, unsigned int outlen);

int StringIsUTF8(unsigned char* str, int length);

/* AES-128_CBC_PKCS5Padding_Encrypt
* 入参:
*	plaintext:     明文
*	plaintext_len: 明文长度
*	key:           密钥 长度只能是16/24/32字节 否则OPENSSL会对key进行截取或PKCS0填充
*   iv:            初始向量
*   ciphertext:    密文
* 返回值:    密文的长度
*/
int AES_CBC_PKCS5_Encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext);

/* AES-128_CBC_PKCS5Padding_Decrypt
* 入参:
*	ciphertext:     密文字符串
*	ciphertext_len: 密文长度
*	key:            密钥 长度只能是16/24/32字节 否则OPENSSL会对key进行截取或PKCS0填充
*   iv:             初始向量
*   plaintext:      解密后的明文
* 返回值: 明文 需要free
*/
int AES_CBC_PKCS5_Decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext);

std::string ansi_to_utf8(const char* strAnsiA);

std::string utf8_to_ansi(const char* strUtf8A);

void trimString(std::string & str );

#ifdef _WIN32
std::string byteToHexStr(unsigned char* byte_arr, int arr_len);
int hexStrToByte(char *s, unsigned char* bits);
std::string encrypt_msg_to_server(const char* pSrcMsg);
std::string decrypt_msg_from_server(char* pszBuffer);
void splitstr(const std::string& str, char tag, std::vector<std::string>& list);
void splitstr_v2(const std::string& str, const std::string& pattern, std::vector<std::string>& list);
std::string dec2hex(int i, int width);
std::string& replace_all_distinct(std::string& str, const std::string& old_value, const std::string& new_value);
bool AllisNum(std::string str);
bool IsVersionNumber(std::string sParam);
#endif

}  // namespace di_rest_client
#endif  // DIAGENT_STRINGUTILS_H
