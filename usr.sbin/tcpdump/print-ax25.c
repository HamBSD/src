/*	$OpenBSD: print-ether.c,v 1.36 2019/12/03 01:43:33 dlg Exp $	*/

/*
 * Copyright (c) 1988, 1989, 1990, 1991, 1992, 1993, 1994, 1995, 1996, 1997
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include <sys/time.h>
#include <sys/socket.h>

struct mbuf;
struct rtentry;
#include <net/if.h>

#include <netinet/in.h>
#include <netax25/if_ax25.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_var.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>
#include <netinet/tcp.h>

#include <stdio.h>
#include <pcap.h>


#include "interface.h"

const u_char *packetp;
const u_char *snapend;

void
ax25_print(const u_char *bp, u_int length)
{
	/* TODO: so much of this needs to be converted to macros that extract the relevant bits */
	int d, nd;

	if (qflag) {
		TCHECK2(*bp, 14);
		(void)printf("%s", 
			     ax25_ntoa((struct ax25_addr *)&bp[7]));
		(void)printf(">%s %d: ",
			     ax25_ntoa((struct ax25_addr *)&bp[0]),
			     length);
	} else {
		/* check that enough header is captured to extract full path */
		for (nd = 0;; ++nd) {
			if (nd >= AX25_MAX_DIGIS)
				goto trunc;
			TCHECK2(*bp, 14 + (nd * 7) + 2);
			if (bp[13 + (nd * 7)] & AX25_LAST_MASK)
				break;
		}
		(void)printf("%s", 
			     ax25_ntoa((struct ax25_addr *)&bp[7]));
		(void)printf(">%s",
			     ax25_ntoa((struct ax25_addr *)&bp[0]));
		for (d = 0; d < nd; d++)
			(void)printf(",%s", ax25_ntoa((struct ax25_addr *)&bp[14 + (7 * d)]));
		(void)printf(" %d:", length);
	}
	return;
trunc:
	(void)printf("[|ax25] ");
}

u_short extracted_control;
u_short extracted_pid;

/*
 * This is the top level routine of the printer.  'p' is the points
 * to the AX.25 header of the packet, 'tvp' is the timestamp,
 * 'length' is the length of the packet off the wire, and 'caplen'
 * is the number of bytes actually captured.
 */
void
ax25_if_print(u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
	ts_print(&h->ts);

	/*
	 * Some printers want to get back at the link-level addresses,
	 * and/or check that they're not walking off the end of the packet.
	 * Rather than pass them all the way down, we set these globals.
	 */
	snapend = p + h->caplen;

	ax25_tryprint(p, h->len, 1);
}

void
ax25_tryprint(const u_char *p, u_int length, int first_header)
{
	u_int caplen = snapend - p;
	const u_char *ep;

	if (caplen < AX25_MIN_HDR_LEN) {
		printf("[|ax25]");
		goto out;
	}

	if (eflag)
		ax25_print(p, length);

	/* TODO: get length of header */

	packetp = p;
	//length -= sizeof(struct ether_header);
	//caplen -= sizeof(struct ether_header);
	ep = p; /* what is a header */
	//p += sizeof(struct ether_header);

	u_short control = 0, pid = 0;

	if (ax25_encap_print(control, pid, p, length, caplen) == 0) {
		/* type not known, print raw packet */
		if (!eflag)
			ax25_print((u_char *)ep, length + sizeof(*ep));
		if (!xflag && !qflag) {
			if (eflag)
				default_print(packetp, snapend - packetp);
			else
				default_print(p, caplen);
		}
	}
	if (xflag && first_header) {
		if (eflag)
			default_print(packetp, snapend - packetp);
		else
			default_print(p, caplen);
	}
out:
	if (first_header)
		putchar('\n');
}

/*
 * Prints the packet encapsulated in an AX.25 frame
 * (or an equivalent encapsulation), given the Protocol ID code.
 *
 * Returns non-zero if it can do so, zero if the protocol ID is unknown.
 *
 * Stuffs the protocol ID into a global for the benefit of lower layers
 * that might want to know what it is.
 */

int
ax25_encap_print(u_short control, u_short pid, const u_char *p,
    u_int length, u_int caplen)
{
	extracted_control = control;
	extracted_pid = pid;

	switch (pid) {

#define AX25PROTO_IP 0xcc

	case AX25PROTO_IP:
		ip_print(p, length);
		return (1);
	}

	return 0;
}

