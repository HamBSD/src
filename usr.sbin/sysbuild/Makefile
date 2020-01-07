#	$OpenBSD $

MAN=	sysbuild.8

SCRIPT=	sysbuild.sh

realinstall:
	${INSTALL} ${INSTALL_COPY} -o ${BINOWN} -g ${BINGRP} -m ${BINMODE} \
		${.CURDIR}/${SCRIPT} ${DESTDIR}${BINDIR}/sysbuild

.include <bsd.prog.mk>
