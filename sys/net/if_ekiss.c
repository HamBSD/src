/*	$OpenBSD$ */

/*
 * Copyright (c) 2019 Iain R. Learmonth <irl@fsfe.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 *  TODO:
 *
 * - Rename to ekiss, expecting a future axkiss interface.
 * - Make sure that both ekiss and axkiss can share kiss(4) line disc.
 * - This might mean not using the same software control block for both.
 */

/* A network interface using Ethernet over a KISS TNC. */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/systm.h>
#include <sys/syslog.h>
#include <sys/rwlock.h>
#include <sys/percpu.h>
#include <sys/smr.h>
#include <sys/task.h>

#include <sys/tty.h>
#include <sys/fcntl.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>

#include <net/if_media.h>

#include <netinet/in.h>
#include <netinet/if_ether.h>

#include <net/if_kiss.h>

static int	ekiss_clone_create(struct if_clone *, int);
static int	ekiss_clone_destroy(struct ifnet *);

static int	ekiss_ioctl(struct ifnet *, u_long, caddr_t);
static void	ekiss_start(struct ifqueue *);
static int	ekiss_enqueue(struct ifnet *, struct mbuf *);

static int	ekiss_media_change(struct ifnet *);
static void	ekiss_media_status(struct ifnet *, struct ifmediareq *);

static int	ekiss_up(struct ekiss_softc *);
static int	ekiss_down(struct ekiss_softc *);
static int	ekiss_iff(struct ekiss_softc *);

static struct if_clone ekiss_cloner =
    IF_CLONE_INITIALIZER("ekiss", ekiss_clone_create, ekiss_clone_destroy);

void
ekissattach(int count)
{
	if_clone_attach(&ekiss_cloner);
}

static int
ekiss_clone_create(struct if_clone *ifc, int unit)
{
	struct ekiss_softc *sc;
	struct ifnet *ifp;

	sc = malloc(sizeof(*sc), M_DEVBUF, M_WAITOK|M_ZERO|M_CANFAIL);
	if (sc == NULL)
		return (ENOMEM);

	ifp = &sc->sc_if;

	snprintf(ifp->if_xname, sizeof(ifp->if_xname), "%s%d",
	    ifc->ifc_name, unit);

	ifmedia_init(&sc->sc_media, 0, ekiss_media_change, ekiss_media_status);
	ifmedia_add(&sc->sc_media, IFM_ETHER | IFM_AUTO, 0, NULL);
	ifmedia_set(&sc->sc_media, IFM_ETHER | IFM_AUTO);

	ifp->if_softc = sc;
	ifp->if_hardmtu = ETHER_MAX_HARDMTU_LEN;
	ifp->if_ioctl = ekiss_ioctl;
	ifp->if_qstart = ekiss_start;
	ifp->if_enqueue = ekiss_enqueue;
	ifp->if_flags = IFF_BROADCAST | IFF_MULTICAST | IFF_SIMPLEX;
	ifp->if_xflags = IFXF_CLONED | IFXF_MPSAFE;
	ifp->if_link_state = LINK_STATE_UP;
	IFQ_SET_MAXLEN(&ifp->if_snd, IFQ_MAXLEN);
	ether_fakeaddr(ifp);

	if_counters_alloc(ifp);
	if_attach(ifp);
	ether_ifattach(ifp);

	ifp->if_llprio = IFQ_MAXPRIO;

	kissregister(sc);

	return (0);
}

static int
ekiss_clone_destroy(struct ifnet *ifp)
{
	struct ekiss_softc *sc = ifp->if_softc;

	NET_LOCK();
	sc->sc_dead = 1;

	if (ISSET(ifp->if_flags, IFF_RUNNING))
		ekiss_down(sc);
	NET_UNLOCK();

	ether_ifdetach(ifp);
	if_detach(ifp);

	free(sc, M_DEVBUF, sizeof(*sc));

	return (0);
}

static int
ekiss_ioctl(struct ifnet *ifp, u_long cmd, caddr_t data)
{
	struct ekiss_softc *sc = ifp->if_softc;
	struct ifreq *ifr = (struct ifreq *)data;
	int error = 0;

	if (sc->sc_dead)
		return (ENXIO);

	switch (cmd) {
	case SIOCSIFADDR:
		break;

	case SIOCSIFFLAGS:
		if (ISSET(ifp->if_flags, IFF_UP)) {
			if (!ISSET(ifp->if_flags, IFF_RUNNING))
				error = ekiss_up(sc);
			else
				error = ENETRESET;
		} else {
			if (ISSET(ifp->if_flags, IFF_RUNNING))
				error = ekiss_down(sc);
		}
		break;

	case SIOCSIFLLADDR:
		error = EOPNOTSUPP;
		//error = kiss_set_lladdr(sc, ifr);
		break;

	case SIOCSIFMTU:
		error = EOPNOTSUPP;
		//error = kiss_set_mtu(sc, ifr->ifr_mtu);
		break;

	case SIOCSIFMEDIA:
		error = EOPNOTSUPP;
		break;
	case SIOCGIFMEDIA:
		error = ifmedia_ioctl(ifp, ifr, &sc->sc_media, cmd);
		break;

	default:
		error = ether_ioctl(ifp, &sc->sc_ac, cmd, data);
		break;
	}

	if (error == ENETRESET)
		error = ekiss_iff(sc);

	return (error);
}

static void
ekiss_start(struct ifqueue *ifq)
{
	struct ifnet *ifp = ifq->ifq_if;
	struct ekiss_softc *sc = ifp->if_softc;

	smr_read_enter();
	struct mbuf *m;
	while ((m = ifq_dequeue(ifq)) != NULL)
		kissoutput(sc, m);
	smr_read_leave();
}

static int
ekiss_enqueue(struct ifnet *ifp, struct mbuf *m)
{
	struct ekiss_softc *sc;
	int error;

	error = 0;

	if (!ifq_is_priq(&ifp->if_snd))
		return (if_enqueue_ifq(ifp, m));

	/* if there's the wrong ldisc then abort */

	sc = ifp->if_softc;

	if (sc->sc_devp == NULL)
		return (EINVAL);

	counters_pkt(ifp->if_counters,
	    ifc_opackets, ifc_obytes, m->m_pkthdr.len);

	kissoutput(sc, m);

	return (error);
}

static int
ekiss_media_change(struct ifnet *ifp)
{
	return (EOPNOTSUPP);
}

static void
ekiss_media_status(struct ifnet *ifp, struct ifmediareq *imr)
{
	//struct ekiss_softc *sc = ifp->if_softc;

	imr->ifm_status = IFM_AVALID;
	imr->ifm_active = IFM_ETHER | IFM_AUTO | IFM_ACTIVE;
}

static int
ekiss_up(struct ekiss_softc *sc)
{
	struct ifnet *ifp = &sc->sc_if;

	NET_ASSERT_LOCKED();
	KASSERT(!ISSET(ifp->if_flags, IFF_RUNNING));

	SET(ifp->if_flags, IFF_RUNNING);

	return (ENETRESET);
}

static int
ekiss_down(struct ekiss_softc *sc)
{
	struct ifnet *ifp = &sc->sc_if;

	NET_ASSERT_LOCKED();
	CLR(ifp->if_flags, IFF_RUNNING);

	return (ENETRESET);
}

static int
ekiss_iff(struct ekiss_softc *sc)
{
	struct ifnet *ifp = &sc->sc_if;
	unsigned int promisc = ISSET(ifp->if_flags, IFF_PROMISC);

	NET_ASSERT_LOCKED();

	if (promisc != sc->sc_promisc) {
		sc->sc_promisc = promisc;
	}

	return (0);
}
