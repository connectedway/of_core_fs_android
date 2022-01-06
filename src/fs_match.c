/* Copyright (c) 2021 Connected Way, LLC. All rights reserved.
 * Use of this source code is governed by a Creative Commons 
 * Attribution-NoDerivatives 4.0 International license that can be
 * found in the LICENSE file.
 */
#include "ofc/core.h"
#include "ofc/types.h"
#include "ofc/libc.h"
#include "ofc/fs_match.h"

static OFC_CHAR
ofc_file_match_lower(OFC_INT flags, OFC_CHAR c) {
    if (flags & OFC_FILE_MATCH_CASEFOLD) {
        c = OFC_TOLOWER(c);
    }
    return (c);
}


OFC_CORE_LIB OFC_BOOL
ofc_file_match(OFC_CHAR *pattern, OFC_CHAR *name, OFC_INT flags) {
    OFC_BOOL ret;

    ret = OFC_TRUE;
    if (pattern != OFC_NULL) {
        for (; *pattern != '\0' && ret == OFC_TRUE;) {
            /*
             * Dispatch on the pattern character
             */
            switch (*pattern) {
                case '?':
                    pattern++;
                    /*
                     * Match any one character
                     */
                    if (*name == '\0')
                        /*
                         * Trying to match end of string.  That's a failure
                         */
                        ret = OFC_FALSE;
                    else {
                        if (*name == '.')
                            ret = OFC_FALSE;
                        else
                            /*
                             * Matched the character, on to the next
                             */
                            name++;
                    }
                    break;

                case '\\':
                    /*
                     * Escape, so let's use the next character as is
                     */
                    pattern++;

                    if (ofc_file_match_lower(flags, *pattern) !=
                        ofc_file_match_lower(flags, *name))
                        ret = OFC_FALSE;
                    else {
                        /*
                         * Matched, on to next
                         */
                        pattern++;
                        name++;
                    }
                    break;

                case '*':
                    if (*name != '\0') {
                        pattern++;
                        name++;
                    }
                    /*
                     * Eat extra wildcards
                     */
                    for (; *pattern == '*'; pattern++);
                    if (*pattern != '\0') {
                        /*
                         * We need to recursively try to match strings
                         */
                        for (; *name != '\0' &&
                               ofc_file_match(pattern, name, flags) == OFC_FALSE;
                               name++);

                        if (*name == '\0')
                            ret = OFC_FALSE;
                        else
                            pattern += ofc_strlen(pattern);
                    }
                    break;

                default:
                    if (ofc_file_match_lower(flags, *pattern) !=
                        ofc_file_match_lower(flags, *name))
                        ret = OFC_FALSE;
                    else {
                        pattern++;
                        name++;
                    }
                    break;
            }
        }
    }

    return (ret);
}
