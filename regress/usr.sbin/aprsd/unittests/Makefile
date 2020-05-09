# $OpenBSD: Makefile,v 1.5 2019/06/17 13:13:03 claudio Exp $

.PATH:		${.CURDIR}/../../../../usr.sbin/aprsd

PROGS += object_compose_test position_compose_test

.  for p in ${PROGS}
REGRESS_TARGETS += run-regress-$p
.endfor

CFLAGS+= -I${.CURDIR} -I${.CURDIR}/../../../../usr.sbin/aprsd
LDADD= -lutil
DPADD+= ${LIBUTIL}

SRCS_object_compose_test=	object_compose_test.c aprs.c
run-regress-object_compose_test: object_compose_test
	./object_compose_test

SRCS_position_compose_test=	position_compose_test.c aprs.c
run-regress-position_compose_test: position_compose_test
	./position_compose_test

.include <bsd.regress.mk>
