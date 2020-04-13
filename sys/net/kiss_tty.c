/*	$OpenBSD$ */

/*
 * Copyright (c) 2006, 2007, 2008 Marc Balmer <mbalmer@openbsd.org>
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
 *  - Set the interface as running in kissopen (and not in kissclose)
 *  - Count the number of input errors occuring
 */

/* A tty line discipline to communicate with a KISS terminal node controller. */

#include "bpfilter.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/tty.h>
#include <sys/conf.h>
#include <sys/proc.h>
#include <sys/smr.h>

#include <net/bpf.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>

#include <net/if_media.h>

#include <netinet/in.h>
#include <netinet/if_ether.h>

#include <net/if_kiss.h>

#ifdef KISS_DEBUG
#define DPRINTFN(n, x)	do { if (kissdebug > (n)) printf x; } while (0)
int kissdebug = 0;
#else
#define DPRINTFN(n, x)
#endif
#define DPRINTF(x)	DPRINTFN(0, x)

#define KISSMAX		1512 /* chosen arbitrarily; TODO: do better */

/* special characters */
#define KISSFEND	0xC0 /* frame end */
#define KISSFESC	0xDB /* frame escape */
#define KISSTFEND	0xDC /* transposed frame end */
#define KISSTFESC	0xDD /* transposed frame escape */

/* commands */
#define KISSCMD_DATA		0x00
#define KISSCMD_TXDELAY		0x01 /* in 10 ms units */
#define KISSCMD_PERSIST		0x02 /* used for CSMA */
#define KISSCMD_SLOTTIME	0x03 /* in 10 ms units */
#define KISSCMD_TXTAIL		0x04 /* in 10 ms units */
#define KISSCMD_FULLDUPLEX	0x05 /* 0=half, anything else=full */
#define KISSCMD_SETHARDWARE	0x06 /* this is not implemented anywhere here */
#define KISSCMD_RETURN		0xFF /* on all ports */

LIST_HEAD(, kiss_softc) kiss_softc_list;

int kiss_count, kiss_nxid;

/* flags for (struct kiss)->sc_flags */
#define KISSFLAG_NEW	1
#define KISSFLAG_DATA	2
#define KISSFLAG_ESCAPE	4

/* software control block for kiss line discipline */
struct kiss {
	char			 ks_cbuf[KISSMAX];	/* reveive buffer */
	int			 ks_flags;		/* async line flags; KISSFLAG_* */
	int			 ks_id;			/* instance id */
	int			 ks_port;		/* rcv from port */
	int			 ks_pos;		/* rcv buf position */
	struct kiss_softc	*ks_netp;		/* interface sc */
#define ks_devp			 ks_netp->sc_devp
};

/* take over a tty and match with a kiss net interface. */
int
kissopen(dev_t dev, struct tty *tp, struct proc *p)
{
	struct kiss_softc *sc;
	struct kiss *ks;
	int error;

	if (tp->t_line == KISSDISC)
		return (ENODEV);
	if ((error = suser(p)) != 0)
		return (error);
	if ((sc = kissalloc(p->p_p->ps_pid)) == NULL) {
		/* most likely there are no kissN interfaces */
		return ENXIO;
	}
	ks = malloc(sizeof(struct kiss), M_DEVBUF, M_WAITOK | M_ZERO);

	ks->ks_id = kiss_nxid++;
	kiss_count++;
	ks->ks_netp = sc;
	sc->sc_devp = (void*)tp;
	tp->t_sc = (caddr_t)ks;

	error = linesw[TTYDISC].l_open(dev, tp, p);
	// TODO: do we really need to call this?
	if (error) {
		free(sc, M_DEVBUF, sizeof(*sc));
		tp->t_sc = NULL;
	}
	return (error);
}

/* clean up and set the tty back to termios. */
int
kissclose(struct tty *tp, int flags, struct proc *p)
{
	struct kiss *ks = (struct kiss *)tp->t_sc;
	ks->ks_devp = NULL;
	free(ks, M_DEVBUF, sizeof(*ks));
	tp->t_line = TTYDISC;	/* switch back to termios */
	tp->t_sc = NULL;
	kiss_count--;
	if (kiss_count == 0)
		kiss_nxid = 0;
	return (linesw[TTYDISC].l_close(tp, flags, p));
	// TODO: do we really need to call this?
}

/* tty input interrupt handler. collects kiss frames. */
int
kissinput(int c, struct tty *tp)
{
	struct kiss *ks = (struct kiss *)tp->t_sc;

	if (c == KISSFEND) {
		if (ks->ks_flags & KISSFLAG_DATA && ks->ks_pos > 14) {
			struct mbuf *m = m_devget(ks->ks_cbuf, ks->ks_pos, 0);
			if_vinput(&ks->ks_netp->sc_if, m);
		}
		ks->ks_flags = KISSFLAG_NEW;
		return 0;
	}

	if (ks->ks_flags & KISSFLAG_NEW) {
		/* this is the first byte in a new frame. */
		int port = (c & 0xF0) >> 4;
		int command = c & 0x0F;

		ks->ks_flags = 0;

		switch (command) {
		case KISSCMD_DATA:
			ks->ks_port = port;
			ks->ks_pos = 0;
			ks->ks_flags |= KISSFLAG_DATA;
			break;
		default:
			printf("kiss: unrecognised command received on port %d\n", port);
			break;
		}
		return 0;
	}

	if (c == KISSFESC) {
		ks->ks_flags |= KISSFLAG_ESCAPE;
		return 0;
	}

	if (ks->ks_flags & KISSFLAG_ESCAPE) {
		int escaped = 0;
		switch (c) {
		case KISSTFESC:
			escaped = KISSFESC;
			break;
		case KISSTFEND:
			escaped = KISSFEND;
			break;
		}
		if (escaped) {
			c = escaped;
		} else {
			/* abort this packet. */
			ks->ks_flags &= ~KISSFLAG_DATA;
		}
		ks->ks_flags &= ~KISSFLAG_ESCAPE;
	}

	if (ks->ks_flags & KISSFLAG_DATA) {
		if (ks->ks_pos < (KISSMAX - 1)) {
			ks->ks_cbuf[ks->ks_pos++] = c;
		} else {
			/* abort the packet. */
			ks->ks_flags &= ~KISSFLAG_DATA;
		}
	}
	return 0;
}

/* output a kiss frame with packet data from an mbuf. */
void
kissoutput(struct kiss_softc *sc, struct mbuf *m) {
	int s;
	register u_char *cp;
	struct tty *tp = (struct tty *)sc->sc_devp;
#if NBPFILTER > 0
	struct ifnet *ifp = &sc->sc_if;

	if (ifp->if_bpf) {
		if (bpf_mtap_ether(ifp->if_bpf, m, BPF_DIRECTION_OUT)) {
			m_freem(m);
			return;
		}
	}
#endif

	smr_read_enter(); // TODO: what is this protecting?
	s = spltty();
	putc(KISSFEND, &tp->t_outq);
	putc(KISSCMD_DATA, &tp->t_outq); /* implicitly port 0 */

	while (m) {
		register u_char *ep;

		cp = mtod(m, u_char *); ep = cp + m->m_len;
		while (cp < ep) {
			/*
			 * Find out how many bytes in the string we can
			 * handle without doing something special.
			 */
			register u_char *bp = cp;

			while (cp < ep) {
				switch (*cp++) {
				case KISSFESC:
				case KISSFEND:
					--cp;
					goto out;
				}
			}
			out:
			if (cp > bp) {
				/*
				 * Put n characters at once
				 * into the tty output queue.
				 */
				if (b_to_q((char *)bp, cp - bp,
				    &tp->t_outq))
					break;
				sc->sc_if.if_obytes += cp - bp;
			}
			/*
			 * If there are characters left in the mbuf,
			 * the first one must be special..
			 * Put it out in a different form.
			 */
			if (cp < ep) {
				if (putc(KISSFESC, &tp->t_outq))
					break;
				if (putc(*cp++ == KISSFESC ?
				   KISSTFESC : KISSTFEND,
				   &tp->t_outq)) {
					(void) unputc(&tp->t_outq);
					break;
				}
				sc->sc_if.if_obytes += 2;
			}
		}
		m = m_free(m);
	}

	putc(KISSFEND, &tp->t_outq);
	splx(s);
	ttstart(tp);
	smr_read_leave();
}

/* allocate the first available network interface. */
struct kiss_softc *
kissalloc(pid_t pid)
{
	struct kiss_softc *sc;

	NET_LOCK();
	LIST_FOREACH(sc, &kiss_softc_list, sc_list) {
		if (sc->sc_xfer == pid) {
			sc->sc_xfer = 0;
			NET_UNLOCK();
			return sc;
		}
	}
	LIST_FOREACH(sc, &kiss_softc_list, sc_list) {
		if (sc->sc_devp == NULL)
			break;
	}
	NET_UNLOCK();
	if (sc == NULL)
		return NULL;

	return sc;
}

/* register a kiss interface with the line discipline. */
void
kissregister(struct kiss_softc *sc)
{
	NET_LOCK();
	LIST_INSERT_HEAD(&kiss_softc_list, sc, sc_list);
	NET_UNLOCK();
}

