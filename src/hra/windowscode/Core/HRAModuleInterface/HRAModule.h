#ifndef HRAModule_h__
#define HRAModule_h__

#include "json/json.h"

#ifdef HRAMODULEINTERFACE_API_COMPILED
#ifdef WIN32
#define HRA_MODULEINTERFACE_EXPORT __declspec(dllexport)
#else
#define HRA_MODULEINTERFACE_EXPORT
#endif
#else
#ifdef WIN32
#define HRA_MODULEINTERFACE_EXPORT __declspec(dllimport)
#else
#define HRA_MODULEINTERFACE_EXPORT extern
#endif
#endif


/* 数据结构定义 */
struct HraModuleElmtFunMap
{
	unsigned int ulMsgType;
	int (* init)(void); 
	int (* deinit)(void); 
	int (* handle)(const Json::Value& jsContect); 
};

#endif // HRAModule_h__
