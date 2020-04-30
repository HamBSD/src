
/* Structures and declarations for KISS. */

#ifndef _NET_IF_KISS_H_
#define _NET_IF_KISS_H_

struct kiss_softc {
	struct arpcom		 sc_ac;
#define sc_if			 sc_ac.ac_if
	unsigned int		 sc_dead;
	unsigned int		 sc_promisc;
	struct ifmedia		 sc_media;
	void			*sc_devp; /* tty */
	pid_t			sc_xfer; /* used in transferring unit */
	LIST_ENTRY(kiss_softc)	sc_list; /* all kiss interfaces */
};

struct kiss_softc	*kissalloc(pid_t pid);
void			 kissoutput(struct kiss_softc *sc, struct mbuf *m);
void			 kissregister(struct kiss_softc *sc);

#endif /* _NET_IF_KISS_H_ */
