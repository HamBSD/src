
#include "bpfilter.h"

#include <sys/errno.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/socket.h>

#include <net/bpf.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <netax25/if_ax25.h>

u_int8_t ax25broadcastaddr[AX25_ADDR_LEN] =
    { 'Q' << 1, 'S' << 1, 'T' << 1, ' ' << 1, ' ' << 1, ' ' << 1, 0 };
u_int8_t ax25anyaddr[AX25_ADDR_LEN] =
    { 'A' << 1, 'N' << 1, 'Y' << 1, ' ' << 1, ' ' << 1, ' ' << 1, 0 };
u_int8_t ax25nulladdr[AX25_ADDR_LEN] =
    { 'N' << 1, '0' << 1, 'C' << 1, 'A' << 1, 'L' << 1, 'L' << 1, 0 };
#define senderr(e) { error = e; goto bad; }

struct ax25_header {
	struct ax25_addr ax25_dhost;
	struct ax25_addr ax25_shost;
};

/*
 * Process a received AX.25 frame.
 */
int
ax25_input(struct ifnet *ifp, struct mbuf *m, void *cookie)
{
	/* Drop short frames */
	if (m->m_len < AX25_MIN_HDR_LEN)
		goto dropanyway;

	/* TODO: do something with the packet in the future */

dropanyway:
	m_freem(m);
	return 1;
}

/*
 * Create a simple (and incomplete) AX.25 header.
 */
int
ax25_resolve(struct ifnet *ifp, struct mbuf *m, struct sockaddr *dst,
    struct rtentry *rt, struct ax25_header *ah)
{
	int error = 0;
	sa_family_t af = dst->sa_family;

	switch (af) {
	case pseudo_AF_HDRCMPLT:
		/* take the src and dst from the sa */
		memcpy(ah, dst->sa_data, sizeof(*ah));
		return 0;
	case AF_UNSPEC:
		/* take the dst from the sa, but get src below */
		memcpy(ah, dst->sa_data, sizeof(*ah));
		break;
	default:
		printf("%s: can't handle af%d\n", ifp->if_xname, af);
		senderr(EAFNOSUPPORT);
	}

	memcpy(&ah->ax25_shost, LLADDR(ifp->if_sadl), ifp->if_addrlen);

	return 0;

bad:
	m_freem(m);
	return error;
}

struct mbuf *
ax25_encap(struct ifnet *ifp, struct mbuf *m, struct sockaddr *dst,
    struct rtentry *rt, int *errorp)
{
	struct ax25_header ah;
	int error;

	error = ax25_resolve(ifp, m, dst, rt, &ah);
	switch (error) {
	case 0:
		break;
	case EAGAIN:
		error = 0;
	default:
		*errorp = error;
		return NULL;
	}

	return m;

	m = m_prepend(m, sizeof(struct ax25_header), M_DONTWAIT);
	if (m == NULL) {
		*errorp = ENOBUFS;
		return NULL;
	}

	memcpy(mtod(m, struct ax25_header *), &ah, sizeof(struct ax25_header));

	return m;
}

/*
 * Encapsulate and output an AX.25 frame.
 */
int
ax25_output(struct ifnet *ifp, struct mbuf *m, struct sockaddr *dst,
    struct rtentry *rt)
{
	int error;
	m = ax25_encap(ifp, m, dst, rt, &error);
	if (m == NULL)
		return error;
	return if_enqueue(ifp, m);
}

/*
 * Perform common duties while attaching to interface list.
 */
void
ax25_ifattach(struct ifnet *ifp)
{
	ifp->if_type = IFT_AX25;
	ifp->if_addrlen = AX25_ADDR_LEN;
	ifp->if_hdrlen = AX25_MIN_HDR_LEN;
	ifp->if_mtu = AX25_MTU;
	ifp->if_output = ax25_output;

	if_ih_insert(ifp, ax25_input, NULL);

	if (ifp->if_hardmtu == 0) {
		ifp->if_hardmtu = AX25_MTU;
	}

	if_alloc_sadl(ifp);
	memcpy(LLADDR(ifp->if_sadl), ax25nulladdr, ifp->if_addrlen);

#if NBPFILTER > 0
	bpfattach(&ifp->if_bpf, ifp, DLT_AX25, sizeof(struct ax25_header));
#endif
}

/*
 * Perform common duties while detaching from the interface list.
 */
void
ax25_ifdetach(struct ifnet *ifp)
{
	if_deactivate(ifp);

	if_ih_remove(ifp, ax25_input, NULL);

	KASSERT(SRPL_EMPTY_LOCKED(&ifp->if_inputs));
}

/*
 * Convert AX25 address to printable (loggable) representation.
 */
char *
ax25_sprintf(u_char *ap)
{
	int i, ssid;
	static char ax25buf[AX25_ADDR_LEN + 4];
	char *cp = ax25buf;
	for (i = 0; i < AX25_ADDR_LEN - 1; i++) {
		*cp++ = *ap++ >> 1;
	}
	*cp++ = '-';
	ssid = *ap >> 1;
	if (ssid > 9) {
		*cp++ = '1';
	}
	*cp++ = '0' + (ssid % 10);
	return ax25buf;
}
