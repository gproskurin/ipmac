#

SYSDIR?= /usr/src/freebsd-head/sys
KMOD=	ng_ipmac
SRCS= 	ng_ipmac.c ng_ipmac.h

.include <bsd.kmod.mk>
