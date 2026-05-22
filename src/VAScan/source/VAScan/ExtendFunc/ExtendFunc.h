//--------------------------------------------------------------------------
// (C) Copyright (C) 2019 亚信科技（成都）有限公司
//      All Rights Reserved.
//
// 文件名称 :	ExternFunc.h
// 
// 描述 :	声明引擎扩展接口，用于Lua脚本
//
// 作者 :	songhy3
//
// 时间 :	2019.10.22
//
// 修改记录：
//
//--------------------------------------------------------------------------
#ifndef EXTERNFUNC_H
#define EXTERNFUNC_H

extern "C" {
#include "../../include/lua/lua.h"
#include "../../include/lua/lualib.h"
#include "../../include/lua/lauxlib.h"
}

#ifdef _WIN32
int GetFileSignerName(lua_State *L);
#endif
int PrintDbgMsgA(lua_State *L);
int PrintDbgMsgW(lua_State *L);

/*
// 判断pid是否有监听端口
int CheckPidIsServer(lua_State * L);

// 获取系统路径
int GetSystemRoot(lua_State * l);

// 计算两个ip的netmask
int calc_net_mask(lua_State * l);

// 测试程序
int TestFunc(lua_State * L);
*/

int initExtend();
int FreeExtend();
int ResetFileCache();

int FunGetLinuxBuild(lua_State *L);
int FunLinuxVersion(lua_State *L);
int FunGetFileVersion(lua_State *L);
int FunGetKernelRuning(lua_State *L);
int FunGetKernelBoot(lua_State *L);

int FunGetWindowsVersion(lua_State *L);
int FunGetWindowsBuild(lua_State *L);
int FunGetWindowsRevisonNumber(lua_State *L);
int FunGetInstallKB(lua_State *L);
int FunGetWindowsOs(lua_State *L);
int FunMatchRegex(lua_State *L);

//定义扩展函数表
static const struct luaL_Reg extendFunc[] =
{
  {"PrintDbgMsgA",		PrintDbgMsgA},
	{"PrintDbgMsgW",		PrintDbgMsgW},
  {"GetFileVersion",		FunGetFileVersion},

  {"GetLinuxBuild",		FunGetLinuxBuild},
  {"LinuxVersion",		FunLinuxVersion},
  {"GetKernelRuning",		FunGetKernelRuning},
  {"GetKernelBoot",		FunGetKernelBoot},

  {"GetWindowsVersion",		FunGetWindowsVersion},
  {"GetWindowsBuild",		FunGetWindowsBuild},
  {"GetWindowsRevisonNumber",		FunGetWindowsRevisonNumber},
  {"GetInstallKB",		FunGetInstallKB},
  {"GetWindowsOs",		FunGetWindowsOs},
#ifndef _WIN32
  {"VersionMatch",		FunMatchRegex},
#endif
	//{"TestFunc", TestFunc},
  {NULL, NULL}       //数组中最后一对必须是{NULL, NULL}，用来表示结束      
};

#endif
