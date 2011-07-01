/*-
 * Copyright (c) 2010 Gennady Proskurin <gpr@mail.ru>
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#ifndef _NG_IPMAC_H_
#define _NG_IPMAC_H_

#define NG_IPMAC_NODE_TYPE	"ipmac"
#define NGM_IPMAC_COOKIE	250251510

enum {
	NGM_IPMAC_ADD = 1,
	NGM_IPMAC_STAT = 2|NGM_READONLY,
	NGM_IPMAC_LIST = 3|NGM_READONLY,
	NGM_IPMAC_CLEAR = 4,
};

#define NG_IPMAC_HOOK_IN		"in"
#define NG_IPMAC_HOOK_MATCH		"match"
#define NG_IPMAC_HOOK_MISMATCH		"mismatch"
#define NG_IPMAC_HOOK_NOTFOUND		"notfound"
#define NG_IPMAC_HOOK_UNKNOWN		"unknown"
#define NG_IPMAC_HOOK_DEBUG		"debug"

#endif
