/*
 * iclcd - intentification compliant with license conditions daemon
 *
 * Written by Iain R. Learmonth <irl@fsfe.org> for the public domain.
 */

/*
 * TODO:
 *
 *  * a non-privileged utility to read the heard stations file
 *  * don't use threads, split up into two processes instead and
 *    have specific pledges
 *  * helper functions for logging errors, warnings, with format
 *    strings
 *  * store flags as they are received
 */

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <syslog.h>
#include <stdarg.h>
#include <signal.h>
#include <pthread.h>
#include <errno.h>
#include <time.h>

#include <sys/queue.h>
#include <sys/times.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <net/bpf.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

#include "iclc.h"

static __dead void	 fatal(char *);
static __dead void	 usage(void);
static void		 signal_handler(int sig);
static char		*read_mycallsign(void);
static int		 iclc_compose(char *, char *);
static int		 iclc_open(char *);
static void		 daemonize();
static void		 format_mac();
static void		 iclc_write_text_entry(FILE *, struct iclc_ident *);
static void		 iclc_update(u_char *);
static int		 iclc_verify(u_char *);
static void		 iclc_listen_loop(int, int);
static void		*iclc_beacon_loop(void *);

struct iclc_beacon_attrs {
	char	*call;   /* callsign as ascii text */
	char	*device; /* interface name */
	int	 bpf;    /* bpf file handle */
	int	 period; /* beacon period */
};

static struct bpf_insn insns[] = {
	/* Check EtherType */
	BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 12),
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x88B5, 0, 3),
	/* Check HAMDEX SubType */
	BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 15),
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1),
	BPF_STMT(BPF_RET | BPF_K, (u_int)-1),
	BPF_STMT(BPF_RET | BPF_K, 0),
};

static struct bpf_program filter = {
	sizeof insns / sizeof(insns[0]),
	insns
};

static __dead void
fatal(char* msg)
{
	syslog(LOG_DAEMON | LOG_EMERG,
	    "iclcd hit fatal error; you might want to turn off your radio");
	syslog(LOG_DAEMON | LOG_ERR,
	    "%s", msg);
	exit(1);
}

static __dead void
usage(void)
{
	extern char *__progname;

	fprintf(stderr, "usage: %s [-Dn] [-i interface] [-p period]\n",
	    __progname);
	exit(1);
}

static void
signal_handler(int sig)
{
	switch(sig) {
	case SIGHUP:
		syslog(LOG_DAEMON | LOG_INFO, "caught hangup signal");
		break;
	case SIGTERM:
		syslog(LOG_DAEMON | LOG_EMERG,
		    "caught terminate signal, shutting down");
		exit(0);
		break;
	}
}

static char *
read_mycallsign(void)
{
	FILE    *mcp;
	char    *call, *nl;
	size_t  callsize = 0;
	ssize_t calllen;

	call = NULL;

	if ((mcp = fopen("/etc/mycallsign", "r")) == NULL)
		fatal("could not open /etc/mycallsign");
	if ((calllen = getline(&call, &callsize, mcp)) != -1) {
		if ((nl = strchr(call, '\n')) != NULL)
			nl[0] = '\0';
		return call;
	}
	fatal("could not read callsign from /etc/mycallsign");
}

/*
 * Composes an Ethernet frame in "buf" to beacon the
 * station identification using the callsign in "call"
 * according to version 0 identification frames of the
 * hamdex(7) protocol. buf must be at least 60 bytes in
 * size. The length of the composed frame is returned.
 */
int
iclc_compose(char *buf, char *call)
{
	struct iclc_ident_frame_hdr *frp;

	const char hdr[] = {
	  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // broadcast destination (6 bytes)
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // source filled by bpf (6 bytes)
	  0x88, 0xB5,                         // ethertype (2 bytes)
	  0x00,                               // subtype (1 byte)
	  0x00,                               // version (1 byte)
	  0x00,                               // flags (1 byte)
	  0x00,                               // callsign length (1 byte)
	};

	/* copy header to buf */
	memcpy(buf, hdr, sizeof(hdr));

	/* copy callsign to buf */
	frp = (struct iclc_ident_frame_hdr *)buf;
	frp->fr_calllen = strlen(call);
	if (frp->fr_calllen > ICLC_MAXCALL) {
		fatal("callsign in /etc/mycallsign too long");
	}
	memcpy(&frp->fr_call, call, frp->fr_calllen);

	return sizeof(hdr) + frp->fr_calllen;
}

/*
 * Open a BPF file and attach it to the interface named 'device'.
 * Set immediate mode, check it is an Ethernet interface, and set a
 * filter that only accepts iclc frames.
 */
int
iclc_open(char *device)
{
	int bpf, immediate, iflen;
	struct ifreq bound_if;
	u_int dlt;

	if ((bpf = open("/dev/bpf", O_RDWR)) == -1)
		fatal("/dev/bpf failed to open");

	/* Set immediate mode to process packets as they arrive. */
	immediate = 1;
	if (ioctl(bpf, BIOCIMMEDIATE, &immediate) == -1)
		fatal("failed to set immediate mode");

	/* Bind the network interface. */
	iflen = strlen(device);
	if (strlcpy(bound_if.ifr_name, device, sizeof(bound_if.ifr_name))
	    < iflen)
		fatal("interface name too long");
	if(ioctl(bpf, BIOCSETIF, (caddr_t)&bound_if) == -1)
		fatal("could not bind to interface");

	/* Check the data link layer is Ethernet. */
	if (ioctl(bpf, BIOCGDLT, (caddr_t)&dlt) == -1)
		fatal("failed to get data link type");
	if (dlt != DLT_EN10MB)
		fatal("interface is not an ethernet");

	/* Set filter program. */
	if (ioctl(bpf, BIOCSETF, (caddr_t)&filter) == -1)
		fatal("failed to set bpf filter");

	return bpf;
}

static void
daemonize()
{
	int i;
	i = daemon(0, 0);
	signal(SIGCHLD, SIG_IGN); /* ignore child */
	signal(SIGTSTP, SIG_IGN); /* ignore tty signals */
	signal(SIGTTOU, SIG_IGN);
	signal(SIGTTIN, SIG_IGN);
	signal(SIGHUP, signal_handler); /* catch hangup signal */
	signal(SIGTERM, signal_handler); /* catch kill signal */
}

static void *
iclc_beacon_loop(void *arguments)
{
	struct iclc_beacon_attrs *attrs = (struct iclc_beacon_attrs *)arguments;
	char framebuf[sizeof(struct iclc_ident_frame_hdr) + ICLC_MAXCALL];
	int framelen;
	int unslept;

	framelen = iclc_compose(framebuf, attrs->call);

	syslog(LOG_DAEMON | LOG_INFO,
	    "started up beacon thread (interface %s, callsign: %s)", attrs->device, attrs->call);

	for (;;) {
		if (write(attrs->bpf, &framebuf, framelen) != framelen) {
			syslog(LOG_DAEMON | LOG_EMERG,
			    "failed to send ident frame, might want to unplug");
			syslog(LOG_DAEMON | LOG_ERR,
			    "failure reason: %m");
		}
		unslept = attrs->period;
		while (unslept > 0)
			unslept = sleep(unslept);
	}
}

/*
 * Formats a MAC address as a colon-seperated lowercase hex string.
 * Callers must ensure the buffer is at least 18 bytes in size.
 */
static void
format_mac(char *buf, struct ether_addr *eap)
{
	sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x",
	    eap->ether_addr_octet[0],
	    eap->ether_addr_octet[1],
	    eap->ether_addr_octet[2],
	    eap->ether_addr_octet[3],
	    eap->ether_addr_octet[4],
	    eap->ether_addr_octet[5]);
}

static void
iclc_write_text_entry(FILE* hh, struct iclc_ident *idp)
{
	char source_addr[18];
	format_mac(source_addr, &idp->hwaddr);
	if (fprintf(hh, "%s\t%s\t%d\t%lld\t%lld\n",
	    source_addr,idp->call, idp->flags, idp->first_heard,
	    idp->last_heard) < 0) {
		fatal("failed to write an entry to the heard stations file");
	}
}

/*
 * Update the heard stations with data from received frame. This updates
 * internal state and also the /var/db/heard file.
 */
static void
iclc_update(u_char *buf)
{
	struct iclc_ident_frame_hdr *frp;
	struct iclc_ident *idp;
	FILE *hh;
	char source_addr[18];
	int updated = 0;

	frp = (struct iclc_ident_frame_hdr *)buf;
	format_mac(source_addr, &frp->fr_shost);

	syslog(LOG_DAEMON | LOG_INFO, "updated callsign: %s from mac: %s",
	    (char *)(&buf[16]),
	    source_addr);

	hh = fopen("/var/db/heard", "w");
	if (hh == NULL) {
		fatal("error opening /var/db/heard");
	}

	SLIST_FOREACH(idp, &iclc_idents, entries) {
		if (!updated && memcmp(&idp->hwaddr, &frp->fr_shost, 6) == 0) {
			memcpy(idp->call, &frp->fr_call, frp->fr_calllen);
			idp->last_heard = time(NULL);
			updated = 1;
		}
		iclc_write_text_entry(hh, idp);
	}

	if (!updated) {
		/* this one is new */
		idp = malloc(sizeof(struct iclc_ident));
		memcpy(&idp->hwaddr, &frp->fr_shost, 6);
		memcpy(&idp->call, &frp->fr_call, frp->fr_calllen);
		idp->first_heard = idp->last_heard = time(NULL);
		SLIST_INSERT_HEAD(&iclc_idents, idp, entries);
		iclc_write_text_entry(hh, idp);
	}

	fclose(hh);
}

/*
 * Verifies a packet looks sane and isn't going to be a trouble maker.
 * It is assumed that the packet has already had the EtherType and
 * HAMDEX SubType checked (probably by BPF filter). It is also assumed
 * that buf is at least 60 bytes in size.
 */
static int
iclc_verify(u_char *buf)
{
	int i;
	struct iclc_ident_frame_hdr *frp;
	frp = (struct iclc_ident_frame_hdr *)buf;

	/* check version */
	if (frp->fr_version != 0) {
		syslog(LOG_DAEMON | LOG_WARNING,
		    "rejecting a frame for unknown protocol version");
		return 0;
	}

	/* check callsign length */
	if (frp->fr_calllen == 0 || frp->fr_calllen > ICLC_MAXCALL) {
		syslog(LOG_DAEMON | LOG_WARNING,
		    "rejecting a frame for invalid callsign length");
		return 0;
	}

	/* check chars are printable */
	for (i = 18; i < 18 + frp->fr_calllen; i++) {
		if (buf[i] < 0x20 || buf[i] > 0xfe) {
			syslog(LOG_DAEMON | LOG_WARNING,
			    "rejecting a frame for non-printable characters");
			return 0;
		}
	}

	return 1;
}

static void
iclc_listen_loop(int bpf, int rbufsize)
{
	int cc;
	u_char *rbuf, *bp, *ep;

	rbuf = malloc(rbufsize);
	SLIST_INIT(&iclc_idents);

	for (;;) {
		cc = read(bpf, rbuf, rbufsize);
		if (cc == -1 && errno == EINTR)
			continue;
		if (cc == -1)
			fatal("read error");
		bp = rbuf;
		ep = bp + cc;
		while (bp < ep) {
#define caplen ((struct bpf_hdr *)bp)->bh_caplen
#define hdrlen ((struct bpf_hdr *)bp)->bh_hdrlen
			if (iclc_verify(bp+hdrlen))
				iclc_update(bp + hdrlen);
			bp += BPF_WORDALIGN(hdrlen + caplen);
		}
	}
}

int
main(int argc, char **argv)
{
	int beacon, bpf, daemon, rbufsize, period;
	char ch, *device;

	/* option defaults */
	beacon = 1;
	daemon = 1;
	period = 60;
	device = "ekiss0";

	while ((ch = getopt(argc, argv, "i:p:Dn")) != -1) {
		switch (ch) {
		case 'i':
			device = optarg;
			break;
		case 'p':
			period = atoi(optarg);
			break;
		case 'D':
			daemon = 0;
			break;
		case 'n':
			beacon = 0;
			break;
		default:
			usage();
			break;
		}
	}
	argc -= optind;
	argv += optind;

	char *call = read_mycallsign();

	/* Check for root privileges. */
	if (geteuid())
		fatal("need root privileges");

	if (daemon)
		daemonize();

	/* This will not return if it fails. */
	bpf = iclc_open(device);

	/* Get buffer size needed for reads */
	if (ioctl(bpf, BIOCGBLEN, (caddr_t)&rbufsize) == -1)
		fatal("failed to get buffer size for bpf reads");

	unveil("/var/db/heard", "cw");
	pledge("stdio cpath wpath", NULL);

	pthread_t beacon_thread;
	if (beacon) {
		struct iclc_beacon_attrs *beacon_attrs = malloc(sizeof(struct iclc_beacon_attrs));
		beacon_attrs->call = call;
		beacon_attrs->device = device;
		beacon_attrs->bpf = bpf;
		beacon_attrs->period = period;
		pthread_create(&beacon_thread, NULL, iclc_beacon_loop, beacon_attrs);
	}

	iclc_listen_loop(bpf, rbufsize); /* blocks forever */

	/* XXX: unreachable code, needs to go in signal handler? */
	return pthread_join(beacon_thread, NULL);
}
