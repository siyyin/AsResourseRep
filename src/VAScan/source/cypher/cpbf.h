/*********************************************************************
* Filename:   blowfish.h
* Author:     Brad Conte (brad AT bradconte.com)
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    Defines the API for the corresponding Blowfish implementation.
*********************************************************************/

#ifndef BLOWFISH_H
#define BLOWFISH_H

/*************************** HEADER FILES ***************************/

#ifdef __cplusplus
extern "C"{
#endif
/****************************** MACROS ******************************/
#define BLOWFISH_BLOCK_SIZE 8           // Blowfish operates on 8 bytes at a time

/**************************** DATA TYPES ****************************/

#include <stddef.h>
typedef unsigned char BF_BYTE;             // 8-bit byte
typedef unsigned int  BF_WORD;             // 32-bit word, change to "long" for 16-bit machines

typedef struct {
   BF_WORD p[18];
   BF_WORD s[4][256];
} BLOWFISH_KEY;

void cpbf_setup(const BF_BYTE user_key[], BLOWFISH_KEY *keystruct, size_t len);
void cpbf_encrypt(const BF_BYTE in[], BF_BYTE out[], const BLOWFISH_KEY *keystruct);
void cpbf_decrypt(const BF_BYTE in[], BF_BYTE out[], const BLOWFISH_KEY *keystruct);

#ifdef __cplusplus
}
#endif

#endif   // BLOWFISH_H
