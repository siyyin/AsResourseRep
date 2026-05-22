#ifndef __CYPHER_H
#define __CYPHER_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "cypher_defs.h"


/*==========================================================================*/
/**   @brief Init the Pattern Cypher Content
 *    @param[in]     cypher       Cypher Content
 *    @return    PCE_SUCCESS  if successfully set.
 *    @return    PCE_EMEM     out of memory.
 */
/*PC_API extern*/ int CypherInit(CypherCtx* cypher,int key,int salt);

/*==========================================================================*/
/**   @brief Encrypt input data
*    @param[in]     cypher       Cypher Content
*    @param[in]     in           input data
*    @param[in]     out          encrypt data
*    @return    PCE_SUCCESS  if successfully set.
*    @return    PCE_EMEM     out of memory.
*/
int CypherEncrypt(CypherCtx cypher, PCE_UCHAR in[], PCE_UCHAR out[], int length);


/*==========================================================================*/
/**   @brief Decrypt input data
*    @param[in]     cypher       Cypher Content
*    @param[in]     in           input data
*    @param[in]     out          decrypt data
*    @return    PCE_SUCCESS  if successfully set.
*    @return    PCE_EMEM     out of memory.
*/
int CypherDecrypt(CypherCtx cypher, PCE_UCHAR in[], PCE_UCHAR out[], int length);


/*==========================================================================*/
/**   @brief Cleanup Cypher Content.
 *    @param[in]     cypher       Cypher Content
 *    @return    PCE_SUCCESS if successfully set.
 *    @return    PCE_ENULLARG null arguments were provided.
 */
/*PC_API extern*/ int CypherCleanup(CypherCtx cypher);


/*==========================================================================*/
/**   @brief Get engine version.
 *    @return    version
 */
/*PC_API extern*/ const char *CypherGetVersion(void);

#ifdef __cplusplus
}
#endif

#endif

