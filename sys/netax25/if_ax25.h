/*	$OpenBSD: if_ether.h,v 1.76 2019/07/17 16:46:18 mpi Exp $	*/
/*	$NetBSD: if_ether.h,v 1.22 1996/05/11 13:00:00 mycroft Exp $	*/

/*
 * Copyright (c) 1982, 1986, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)if_ether.h	8.1 (Berkeley) 6/10/93
 */

#ifndef _NETINET_IF_AX25_H_
#define _NETINET_IF_AX25_H_

/*
 * Some basic AX.25 constants.
 */
#define	AX25_ADDR_LEN		7	/* AX.25 address length			*/
#define AX25_CNTL_LEN		1	/* AX.25 control field length		*/
#define AX25_PID_LEN		1	/* AX.25 PID field length		*/
#define AX25_MIN_HDR_LEN	((AX25_ADDR_LEN * 2) + AX25_CNTL_LEN + AX25_PID_LEN)
#define AX25_MAX_HDR_LEN	((AX25_ADDR_LEN * 10) + AX25_CNTL_LEN + AX25_PID_LEN)
#define AX25_MAX_DIGIS		8	/* Maximum number of digipeaters in path */
#define AX25_MTU		576 + AX25_MAX_HDR_LEN	/* Default AX.25 interface MTU */
/*
 * The maximum supported AX.25 length and some space for encapsulation.
 */
#define AX25_MAX_HARDMTU_LEN	65435

/*
 * AX.25 address - 7 octets
 */
struct ax25_addr {
	u_int8_t ax25_addr_octet[AX25_ADDR_LEN];
};

/*
 * Bitmasks for final octet of address
 */
#define AX25_CR_MASK		0b10000000	/* Command/response bit */
#define AX25_RESERVED_MASK	0b01100000	/* Reserved bits	*/
#define AX25_SSID_MASK		0b00011110	/* SSID bits		*/
#define AX25_LAST_MASK		0b00000001	/* Final address bit	*/

//#include <netax25/protocols.h>

#define	AX25_IS_BROADCAST(addr) \
	(((addr)[0] == "Q" << 1 & (addr)[1] == "S" << 1 & \
	  (addr)[2] == "T" << 1 & (addr)[3] == " " << 1 & \
	  (addr)[4] == " " << 1 & (addr)[5] == " " << 1 & \
	  (addr)[6] == 0))
#define	AX25_IS_ANYADDR(addr)		\
	(((addr)[0] == "A" << 1 & (addr)[1] == "N" << 1 & \
	  (addr)[2] == "Y" << 1 & (addr)[3] == " " << 1 & \
	  (addr)[4] == " " << 1 & (addr)[5] == " " << 1 & \
	  (addr)[6] == 0))
#define	AX25_IS_EQ(a1, a2)	(memcmp((a1), (a2), AX25_ADDR_LEN) == 0)

#ifdef _KERNEL

#include <net/if_var.h>	/* for "struct ifnet" */

extern u_int8_t ax25broadcastaddr[AX25_ADDR_LEN];
extern u_int8_t ax25anyaddr[AX25_ADDR_LEN];
extern u_int8_t ax25nulladdr[AX25_ADDR_LEN];

void	ax25_ifattach(struct ifnet *);
void	ax25_ifdetach(struct ifnet *);
int	ax25_input(struct ifnet *, struct mbuf *, void *);
struct mbuf *
	ax25_encap(struct ifnet *, struct mbuf *, struct sockaddr *,
	    struct rtentry *, int *);
int	ax25_output(struct ifnet *, struct mbuf *, struct sockaddr *,
	    struct rtentry *);
char	*ax25_sprintf(u_char *);
/*
int	ax25_resolve(struct ifnet *, struct mbuf *, struct sockaddr *,
	    struct rtentry *, struct ax25_header *);
int	ax25_ioctl(struct ifnet *, struct arpcom *, u_long, caddr_t);
*/

#else /* _KERNEL */

__BEGIN_DECLS
char *ax25_ntoa(struct ax25_addr *);
struct ax25_addr *ax25_aton(const char *);
__END_DECLS

#endif /* _KERNEL */
#endif /* _NETINET_IF_AX25_H_ */
