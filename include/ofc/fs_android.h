/* Copyright (c) 2021 Connected Way, LLC. All rights reserved.
 * Use of this source code is governed by a Creative Commons 
 * Attribution-NoDerivatives 4.0 International license that can be
 * found in the LICENSE file.
 */
#if !defined(__OFC_FSANDROID_H__)
#define __OFC_FSANDROID_H__

#include "ofc/types.h"
#include "ofc/file.h"

#define OFC_FS_ANDROID_BLOCK_SIZE 512

/**
 * \defgroup fs_android Android File System Dependent Support
 * \ingroup fs
 */

/** \{ */

#if defined(__cplusplus)
extern "C"
{
#endif

OFC_VOID OfcFSAndroidDestroyOverlapped(OFC_HANDLE hOverlapped);

OFC_VOID
OfcFSAndroidSetOverlappedOffset(OFC_HANDLE hOverlapped, OFC_OFFT offset);

OFC_VOID OfcFSAndroidStartup(OFC_VOID);

OFC_VOID OfcFSAndroidShutdown(OFC_VOID);

int OfcFSAndroidGetFD(OFC_HANDLE);

OFC_HANDLE OfcFSAndroidGetOverlappedEvent(OFC_HANDLE hOverlapped);

#if defined(__cplusplus)
}
#endif

#endif

/** \} */
