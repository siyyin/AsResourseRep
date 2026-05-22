/*****************************************************************
* Copyright (C) 2021 Asia info security Technology Co.,Ltd.*
******************************************************************
* HraModule.h
*
* DESCRIPTION:
*     
* AUTHOR:
*     qinyong
* CREATED DATE:
*     2021-8-15
* REVISION:
*     1.0
*
* MODIFICATION HISTORY
* --------------------
* $Log:$
*
*****************************************************************/
#pragma once
#ifndef __HRA_MODULE_H__
#define __HRA_MODULE_H__

#include "utility/comm.h"
#include "HRAModule.h"

/* 函数声明 */
HRA_MODULEINTERFACE_EXPORT struct HraModuleElmtFunMap *FindElmtHandler(unsigned int ulMsgType);
HRA_MODULEINTERFACE_EXPORT int ModuleInit(void);
HRA_MODULEINTERFACE_EXPORT int ModuleDeinit(void);

#endif /* __HRA_MODULE_H__ */
