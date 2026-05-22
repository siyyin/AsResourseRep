#ifndef __CYPHER_DEFS_H
#define __CYPHER_DEFS_H

#include <stdlib.h>
#include <stdio.h>

/**inner used*/
//#ifdef __GNUC__
//#define PC_API
//#else
//#define PC_API __declspec(dllexport)
//#endif

#define     PCE_SUCCESS      0
#define     PCE_ENULLARG    -1
#define     PCE_EARG        -2
#define     PCE_EFAIL       -3
#define     PCE_EMEM        -4

typedef void* CypherCtx;
typedef unsigned char PCE_UCHAR;

#endif
