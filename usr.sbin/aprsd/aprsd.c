/*
 * aprsd - automatic packet reporting system daemon
 *
 * Written by Iain R. Learmonth <irl@fsfe.org> for the public domain.
 */

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <sys/event.h>
#include <sys/ioctl.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/times.h>
#include <net/bpf.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

#include "aprsd.h"
#include "gps.h"

struct aprs_interface {
	int		 ai_fd;		/* file descriptor */
	int		 ai_rbufsize;	/* receive buffer size */
	char		*ai_name;	/* interface name, (e.g. axtap0) */
};

struct aprs_beacon_attrs {
	long long	 fixed_lon;	/* fixed longitude if no GPS */
	long long	 fixed_lat;	/* fixed latitude if no GPS */
	time_t		 next_time;	/* next beacon time */
	int		 interval;	/* beacon period */
	int		 flags;		/* aprsd.h: BEACONF_* */
	int		 ssid;		/* SSID, 0-15 */
	int		 type;		/* aprsd.h: BEACONT_* */
	char		*call;		/* callsign as ascii text */
	char		*comment;	/* comment text */
	char		*name;		/* object/item name */
	char		*sensor;	/* gps sensor name (e.g. nmea0) */
};

static __dead void		 fatal(char *);
static __dead void		 usage(void);
static void			 signal_handler(int);
static char 			*aprs_lat_ntoa(long long);
static char 			*aprs_lon_ntoa(long long);
static char			*read_mycallsign(void);
static struct aprs_interface	*aprs_lookup_interface(int);
static int			 aprs_compose(char *, struct aprs_beacon_attrs *);
static struct aprs_interface	*aprs_open(char *);
static void			 daemonize();
static void			*aprs_beacon_loop(int, struct aprs_beacon_attrs *[]);

struct aprs_interface *aifs[20];
int naifs = 0;

static __dead void
fatal(char* msg)
{
	syslog(LOG_DAEMON | LOG_ERR,
	    "%s", msg);
	exit(1);
}

static __dead void
usage(void)
{
	extern char *__progname;

	fprintf(stderr, "usage: %s [-D] [-s] [-f file] [if0 [... ifN]]\n",
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
aprs_lat_ntoa(long long udeg)
{
	static char buf[9];
	long deg, rem, umnt, mnt, dmt;
	int north;
	if (udeg < 0) {
		udeg *= -1;
		north = 0;
	} else {
		north = 1;
	}
	deg = udeg / 1000000;
	snprintf(buf, 3, "%02ld", deg);
	umnt = udeg % 1000000 * 60;
	mnt = umnt / 1000000;
	snprintf(&buf[2], 3, "%02ld", mnt);
	buf[4] = '.';
	dmt = umnt % 1000000;
	snprintf(&buf[5], 3, "%02ld", dmt);
	if (north) {
		buf[7] = 'N';
	} else {
		buf[7] = 'S';
	}
	buf[8] = '\0';
	return buf;
}

static char *
aprs_lon_ntoa(long long udeg)
{
	static char buf[10];
	long deg, rem, umnt, mnt, dmt;
	int east;
	if (udeg < 0) {
		udeg *= -1;
		east = 0;
	} else {
		east = 1;
	}
	deg = udeg / 1000000;
	snprintf(buf, 4, "%03ld", deg);
	umnt = udeg % 1000000 * 60;
	mnt = umnt / 1000000;
	snprintf(&buf[3], 3, "%02ld", mnt);
	buf[5] = '.';
	dmt = umnt % 1000000;
	snprintf(&buf[6], 3, "%02ld", dmt);
	if (east) {
		buf[8] = 'E';
	} else {
		buf[8] = 'W';
	}
	buf[9] = '\0';
	return buf;
}

static char *
read_mycallsign(void)
{
	static char fcall[20];
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

static struct aprs_interface *
aprs_lookup_interface(int fd)
{
	int i;
	for (i = 0; i < naifs; i++)
		if (aifs[i]->ai_fd == fd)
			return aifs[i];
	return NULL;
}

static const char pon_hdr[] = {
	'A' << 1, 'P' << 1, 'B' << 1, 'S' << 1, 'D' << 1, 'D' << 1, 0x60, /* destination */
	0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0xed,	/* source */
	0x03,						/* ui frame */
	0xf0,						/* no layer 3 */
	'!',						/* position report, no timestamp */
	0, 0, 0, 0, 0, 0, 0, 0,				/* latitude */
	'/',						/* table */
	0, 0, 0, 0, 0, 0, 0, 0, 0,			/* longitude */
	'/',						/* symbol */
};
static const int pon_hdr_size = sizeof(pon_hdr);

static const char pot_hdr[] = {
	'A' << 1, 'P' << 1, 'B' << 1, 'S' << 1, 'D' << 1, 'D' << 1, 0x60, /* destination */
	0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0xed,	/* source */
	0x03,						/* ui frame */
	0xf0,						/* no layer 3 */
	'/',						/* position report, with timestamp */
	0, 0, 0, 0, 0, 0, 'z',				/* timestamp */
	0, 0, 0, 0, 0, 0, 0, 0,				/* latitude */
	'/',						/* symbol table */
	0, 0, 0, 0, 0, 0, 0, 0, 0,			/* longitude */
	'/',						/* symbol */
};
static const int pot_hdr_size = sizeof(pot_hdr);

static const char obj_hdr[] = {
	'A' << 1, 'P' << 1, 'B' << 1, 'S' << 1, 'D' << 1, 'D' << 1, 0x60, /* destination */
	0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0xed,	/* source */
	0x03,						/* ui frame */
	0xf0,						/* no layer 3 */
	';',						/* object report */
	' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',	/* object name */
	'_',						/* object live */
	0, 0, 0, 0, 0, 0, 'z',				/* timestamp */
	0, 0, 0, 0, 0, 0, 0, 0,				/* latitude */
	'/',						/* symbol table */
	0, 0, 0, 0, 0, 0, 0, 0, 0,			/* longitude */
	'/'						/* symbol */
};
static const int obj_hdr_size = sizeof(obj_hdr);

/*
 * Composes an APRS position report. The length of the composed frame is
 * returned. The provided buf must be at least APRS_MAXLEN bytes in size.
 *
 * TODO: APRS_MAXLEN, 256 bytes is the maximum size of a UI frame payload, but
 * the buf here also contains the header. I don't know if the payload size
 * decreases as the path increases. It is possible we could have longer packets
 * but there are also going to be a large number of radios that would not
 * support them.
 */
static int
aprs_compose(char *buf, struct aprs_beacon_attrs *attrs)
{
	struct gps_position pos;
	time_t now;
	char *lat, *lon, *name, timestamp[7];
	int calllen, commentlen, pktlen, i;

	if (attrs->sensor != NULL && gps_get_position(&pos, attrs->sensor) == 2) {
		lat = strdup(aprs_lat_ntoa(pos.lat));
		lon = strdup(aprs_lon_ntoa(pos.lon));
	} else if ((attrs->flags & BEACONF_POSSET) == BEACONF_POSSET) {
		lat = strdup(aprs_lat_ntoa(attrs->fixed_lat));
		lon = strdup(aprs_lon_ntoa(attrs->fixed_lon));
	} else {
		return 0;
	}

	time(&now);
	strftime(timestamp, 7, "%d%H%M", gmtime(&now));

	switch (attrs->type) {
	case BEACONT_PON:
		pktlen = pon_hdr_size;
		memcpy(buf, pon_hdr, pktlen);
		memcpy(&buf[17], lat, 8);
		memcpy(&buf[26], lon, 9);
		break;
	case BEACONT_POT:
		pktlen = pot_hdr_size;
		memcpy(buf, pot_hdr, pktlen);
		memcpy(&buf[17], timestamp, 6);
		memcpy(&buf[24], lat, 8);
		memcpy(&buf[33], lon, 9);
		break;
	case BEACONT_OBJ:
		pktlen = obj_hdr_size;
		memcpy(buf, obj_hdr, pktlen);
		memcpy(&buf[17], attrs->name, strlen(attrs->name));
		memcpy(&buf[27], timestamp, 6);
		memcpy(&buf[34], lat, 8);
		memcpy(&buf[43], lon, 9);
		break;
	default:
		/* TODO: unknown type */
		return 0;
	}

	free(lat);
	free(lon);

	calllen = strlen(attrs->call);
	if (calllen > 6) {
		fatal("callsign in /etc/mycallsign too long");
	}
	for (i = 0; i < calllen; i++)
		buf[7 + i] = attrs->call[i] << 1;
	buf[13] = (attrs->ssid << 1) | 0xe1;

	if (attrs->comment != NULL) {
		commentlen = strlen(attrs->comment);
		if (commentlen < APRS_MAXLEN - pktlen) { /* TODO: could be less than or equal? went conservative */
			memcpy(&buf[pktlen], attrs->comment, commentlen);
			pktlen += commentlen;
		} else {
			/* TODO: comment too big */
			return 0;
		}
	}

	return pktlen;
}

/*
 * Open a BPF file and attach it to the interface named 'device'.
 * Set immediate mode.
 */
struct aprs_interface *
aprs_open(char *device)
{
	int iflen, yes;
	struct ifreq bound_if;
	u_int dlt;
	struct aprs_interface *aif;

	aif = malloc(sizeof(struct aprs_interface));
	aif->ai_name = device;

	if ((aif->ai_fd = open("/dev/bpf", O_RDWR)) == -1)
		fatal("/dev/bpf failed to open");

	yes = 1;

	/* Set immediate mode to process packets as they arrive. */
	if (ioctl(aif->ai_fd, BIOCIMMEDIATE, &yes) == -1)
		fatal("failed to set immediate mode");

	/* Set header complete mode to not override source address. */
	if (ioctl(aif->ai_fd, BIOCSHDRCMPLT, &yes) == -1)
		fatal("could not set header complete mode");

	/* Bind the network interface. */
	iflen = strlen(device);
	if (strlcpy(bound_if.ifr_name, device, sizeof(bound_if.ifr_name))
	    < iflen)
		fatal("interface name too long");
	if (ioctl(aif->ai_fd, BIOCSETIF, (caddr_t)&bound_if) == -1)
		fatal("could not bind to interface");

	if (ioctl(aif->ai_fd, BIOCGBLEN, (caddr_t)&aif->ai_rbufsize) == -1)
		fatal("failed to get buffer size for bpf");

	if (ioctl(aif->ai_fd, BIOCPROMISC, NULL) == -1)
		fatal("could not set promiscuous mode");

	return aif;
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

void
aprs_digipeat(char* pkt, int pktlen, struct aprs_interface *src)
{
	write(aifs[0]->ai_fd, pkt, pktlen);
	/* TODO: so much error handling */
}

static void *
aprs_beacon_loop(int num_beacons, struct aprs_beacon_attrs *beacons[])
{
	struct kevent chlist[10];
	struct kevent evlist[10];
	char framebuf[9000];
	int bi, ii, evi, framelen, kq, nev, nr;
	struct aprs_interface *aif;

	if ((kq = kqueue()) == -1)
		fatal("failed to create kqueue");

	EV_SET(&chlist[0], 1, EVFILT_TIMER, EV_ADD | EV_ENABLE, 0, 1000, 0);

	for (ii = 0; ii < naifs; ii++)
		EV_SET(&chlist[ii + 1], aifs[ii]->ai_fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, 0);

	syslog(LOG_DAEMON | LOG_INFO,
	    "started up beacon loop (callsign: %s)", beacons[0]->call);

	while ((nev = kevent(kq, chlist, naifs + 1, evlist, naifs + 1, NULL)) > 0) {
		for (evi = 0; evi < nev; evi++) {
			if (evlist[evi].filter != EVFILT_TIMER) {
				char *bp, *ep;
				aif = aprs_lookup_interface(evlist[evi].ident);
				if ((nr = read(aif->ai_fd, framebuf, aif->ai_rbufsize)) == -1)
					fatal("read");
				if (aif != aifs[0]) {
					bp = framebuf;
					ep = bp + nr;
					while (bp < ep) {
#define caplen ((struct bpf_hdr *)bp)->bh_caplen
#define hdrlen ((struct bpf_hdr *)bp)->bh_hdrlen
						aprs_digipeat(bp + hdrlen, caplen, aif);
						bp += BPF_WORDALIGN(hdrlen + caplen);
					}
				}
				continue;
			}
			time_t now;
			time(&now);
			for (bi = 0; bi < num_beacons; bi++) {
				if (beacons[bi]->next_time <= now) {
					framelen = aprs_compose(framebuf, beacons[bi]);
					if (write(aifs[0]->ai_fd, &framebuf, framelen) != framelen)
						syslog(LOG_DAEMON | LOG_ERR, "failed to send packet: %m");
					beacons[bi]->next_time = now + beacons[bi]->interval;
				}
			}
		}
	}
	fatal("kevent");
}

int
main(int argc, char **argv)
{
	struct aprsd_config conf;
	struct aprs_beacon_attrs *beacons[20];
	int ci, daemon, skipdelay, ssid;
	char ch, *conffile, *device;
	const char *errstr;

	conf.num_beacons = 0;

	/* option defaults */
	conffile = "/etc/aprsd.conf";
	daemon = 1;
	device = "axkiss0";
	skipdelay = 0;
	ssid = 0;

	while ((ch = getopt(argc, argv, "DS:i:f:s")) != -1) {
		switch (ch) {
		case 'i':
			device = optarg;
			break;
		case 'f':
			conffile = optarg;
		case 'D':
			daemon = 0;
			break;
		case 's':
			skipdelay = 1;
			break;
		case 'S':
			ssid = strtonum(optarg, 0, 15, &errstr);
			if (errstr) {
				warnx("SSID is %s: %s", errstr, optarg);
				usage();
			}
			break;
		default:
			usage();
			break;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc == 0)
		fatal("no interfaces specified");

	if (parse_config(conffile, &conf) == -1)
		fatal("could not parse config");

	char *call = read_mycallsign();

	/* Check for root privileges. */
	if (geteuid())
		fatal("need root privileges");

	if (daemon)
		daemonize();

	for (naifs = 0; naifs < argc; naifs++)
		aifs[naifs] = aprs_open(argv[naifs]);

	if (unveil(NULL, NULL) == -1)
		fatal("failed to unveil");
	if (pledge("stdio cpath wpath", NULL) == -1)
		fatal("failed to pledge");

	if (conf.num_beacons == 0)
		fatal("refusing to run without beacons defined");

	for (ci = 0; ci < conf.num_beacons; ci++) {
		struct beacon_config *bc = conf.beacons[ci];
		struct aprs_beacon_attrs *ba = malloc(sizeof(struct aprs_beacon_attrs));
		beacons[ci] = ba;
		ba->type = bc->type;
		switch (ba->type) {
		case BEACONT_OBJ:
			ba->name = bc->name;
			/* fallthrough */
		case BEACONT_POT:
		case BEACONT_PON:
			ba->flags = bc->flags;
			ba->interval = bc->interval;
			if (skipdelay)
				ba->next_time = 0;
			else
				ba->next_time = time(NULL) + (bc->interval / 2);
			if ((bc->flags & BEACONF_POSSET) == BEACONF_POSSET) {
				if (bc->flags & BEACONF_SOUTH) {
					ba->fixed_lat = 0 - bc->latitude;
				} else {
					ba->fixed_lat = bc->latitude;
				}
				if (bc->flags & BEACONF_WEST) {
					ba->fixed_lon = 0 - bc->longitude;
				} else {
					ba->fixed_lon = bc->longitude;
				}
			}
			ba->sensor = bc->sensor;
			ba->comment = bc->comment;
			ba->call = call;
			ba->ssid = ssid;
			break;
		default:
			fatal("unknown beacon type");
		}
	}
	aprs_beacon_loop(conf.num_beacons, beacons);
}
