/* Copyright (c) 2021 Connected Way, LLC. All rights reserved.
 * Use of this source code is governed by a Creative Commons 
 * Attribution-NoDerivatives 4.0 International license that can be
 * found in the LICENSE file.
 */
#if !defined(__OFC_FILE_MATCH_H__)
#define __OFC_FILE_MATCH_H__

#include "ofc/core.h"
#include "ofc/file.h"

#define    OFC_FILE_MATCH_PATHNAME 0x01  /* No wildcard can ever match `/'. */
#define    OFC_FILE_MATCH_PERIOD 0x02  /* Leading `.' is matched explicitly. */
#define    OFC_FILE_MATCH_CASEFOLD 0x04  /* Compare without regard to case.  */

#if defined(__cplusplus)
extern "C" 
{
#endif
OFC_CORE_LIB OFC_BOOL
ofc_file_match(OFC_CHAR *pattern, OFC_CHAR *string, OFC_INT flags);

#if defined(__cplusplus)
}
#endif

#endif
