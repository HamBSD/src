#!/bin/ksh
#
# $OpenBSD$
#
# Copyright (c) 1997-2015 Todd Miller, Theo de Raadt, Ken Westerback
# Copyright (c) 2015 Robert Peichaer <rpe@openbsd.org>
# Copyright (c) 2016, 2017 Antoine Jacoutot <ajacoutot@openbsd.org>
# Copyright (c) 2019 Christian Weisgerber <naddy@openbsd.org>
# Copyright (c) 2019 Florian Obser <florian@openbsd.org>
# Copyright (c) 2020 Iain R. Learmonth <irl@fsfe.org>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

set -e
umask 0022
export PATH=/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin

ARCH=$(uname -m)
MAKEJOBS=$((`sysctl -n hw.ncpuonline` + 1))
NOPERM=/noperm
RELEASE=/home/release

ug_err()
{
	echo "${1}" 1>&2 && return ${2:-1}
}

usage()
{
	ug_err "usage: ${0##*/} [-1 | -2]"
}

STAGE1=false
STAGE2=false

while getopts 12 arg; do
	case ${arg} in
	1)	STAGE1=true;;
	2)	STAGE2=true;;
	*)	usage;;
	esac
done

(($(id -u) != 0)) && ug_err "${0##*/}: need root privileges"

if $STAGE1 && $STAGE2; then
	usage
fi

stage1()
{
	echo "############################################################"
	echo "# 1. Update sources...                                     #"
	echo "############################################################"
	echo "Updating src..."
	(cd /home/src.git && git fetch origin master:master)
	(cd /usr/src && got update -b master)
	echo "Updating xenocara..."
	(cd /usr/xenocara && cvs up -Pd)

	echo "############################################################"
	echo "# 2. Build and install a new kernel...                     #"
	echo "############################################################"
	(cd /usr/src/sys/arch/${ARCH}/compile/GENERIC.MP && make obj &&
		make config && make -j ${MAKEJOBS} && make install)
}

if $STAGE1; then
	stage1
	exit 0
fi

stage2()
{
	echo "############################################################"
	echo "# 3. Build a new base system...                            #"
	echo "############################################################"
	(cd /usr/src && make -j ${MAKEJOBS} obj && make -j ${MAKEJOBS} build)
	sysmerge
	(cd /dev && ./MAKEDEV all)

	echo "############################################################"
	echo "# 4. Make and validate the base system release...          #"
	echo "############################################################"
	echo "TODO: check that noperm mnt isn't mounted"
	[ -d ${NOPERM} ] || mkdir ${NOPERM}
	mount_mfs -s 1G -o rw,noperm swap ${NOPERM}
	[ -d ${NOPERM}/dest ] || mkdir ${NOPERM}/dest
	chown build:wheel ${NOPERM} ${NOPERM}/dest
	chmod 700 ${NOPERM} ${NOPERM}/dest
	[ -d ${RELEASE} ] || mkdir ${RELEASE}
	chown build:wheel ${RELEASE}
	(export DESTDIR=${NOPERM}/dest RELEASEDIR=${RELEASE} ;
		cd /usr/src/etc && make -j ${MAKEJOBS} release &&
		cd /usr/src/distrib/sets &&
		sh checkflist > /root/base.checkflist)

	echo "############################################################"
	echo "# 5. Build and install Xenocara...                         #"
	echo "############################################################"
	(cd /usr/xenocara && make bootstrap && make -j ${MAKEJOBS} obj &&
		make -j ${MAKEJOBS} build)

	echo "############################################################"
	echo "# 6. Make and validate the Xenocara release...             #"
	echo "############################################################"
	[ -d ${NOPERM}/xdest ] || mkdir ${NOPERM}/xdest
	chown build:wheel ${NOPERM} ${NOPERM}/xdest
	chmod 700 ${NOPERM} ${NOPERM}/xdest
	(export DESTDIR=${NOPERM}/xdest RELEASEDIR=${RELEASE} ;
		cd /usr/xenocara && make -j ${MAKEJOBS} release &&
		make checkdist)

	echo "############################################################"
	echo "# 8. Create boot and installation disk images...           #"
	echo "############################################################"
	(export RELDIR=/home/release RELXDIR=/home/release ;
		cd /usr/src/distrib/$(machine)/iso && make && make install )
}

if $STAGE2; then
	stage2
	exit 0
fi

usage
