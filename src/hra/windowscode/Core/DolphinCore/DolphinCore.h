#pragma once
#include <stddef.h>
#include "DolphinCoreDef.h"

HRA_DOLPHIN_CORE_EXPORT const USER_PWD_RESULT*  DolphinCore_GetResult();
HRA_DOLPHIN_CORE_EXPORT void DolphinCore_FreeResult();
HRA_DOLPHIN_CORE_EXPORT int DolphinCore_DoWorker(const wchar_t* szSystemFile = NULL, const wchar_t* szSamFile = NULL);
HRA_DOLPHIN_CORE_EXPORT int DolphinCore_Elevate();
