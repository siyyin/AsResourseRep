#pragma once
#include <string>

#define SUFFIX_JSON "json"

/// <summary>
/// 加密单个json文件
/// </summary>
/// <param name="strPath"></param>
/// <param name="nVersion"></param>
/// <returns></returns>
bool encode_json_file(const std::string& strPath, int nVersion);

/// <summary>
/// 解密单个json文件
/// </summary>
/// <param name="strPath"></param>
/// <returns></returns>
bool decode_json_file(const std::string& strPath);
