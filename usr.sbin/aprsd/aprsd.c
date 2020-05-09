/*
 * aprsd - automatic packet reporting system daemon
 *
 * Written by Iain R. Learmonth <irl@fsfe.org> for the public domain.
 */

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
#include <netax25/if_ax25.h>

#include "aprs.h"
#include "aprsd.h"
#include "gps.h"
#include "log.h"

struct aprs_interface {
	int		 ai_fd;		/* file descriptor */
	int		 ai_rbufsize;	/* receive buffer size */
	const char	*ai_name;	/* interface name, (e.g. axtap0) */
};

static __dead void		 usage(void);
static void			 signal_handler(int);
static char 			*aprs_lat_ntoa(const long long);
static char 			*aprs_lon_ntoa(const long long);
static char			*read_mycallsign(void);
static struct aprs_interface	*aprs_lookup_interface(const int);
static int			 aprs_compose(char *, struct aprs_object *);
static struct aprs_interface	*aprs_open(const char *);
static void			 daemonize();
static void			*aprs_beacon_loop(void);

struct aprsd_config	 conf;
struct aprs_interface	*aifs[20];
int			 naifs = 0;

static __dead void
usage(void)
{
	extern char *__progname;

	fprintf(stderr, "usage: %s [-Dvs] [-s] [-f file] callsign[-ssid] if0 [... ifN]\n",
	    __progname);
	exit(1);
}

static void
signal_handler(int sig)
{
	switch(sig) {
	case SIGHUP:
		log_warnx("caught hangup signal");
		break;
	case SIGTERM:
		log_warnx("caught terminate signal, shutting down");
		exit(0);
		break;
	}
}

static char *
aprs_lat_ntoa(const long long udeg)
{
	static char buf[9];
	long long u;
	long deg, rem, umnt, mnt, dmt;
	int north;
	if (udeg < 0) {
		u = udeg * -1;
		north = 0;
	} else {
		u = udeg;
		north = 1;
	}
	deg = u / 1000000;
	snprintf(buf, 3, "%02ld", deg);
	umnt = u % 1000000 * 60;
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
aprs_lon_ntoa(const long long udeg)
{
	static char buf[10];
	long long u;
	long deg, rem, umnt, mnt, dmt;
	int east;
	if (udeg < 0) {
		u = udeg * -1;
		east = 0;
	} else {
		u = udeg;
		east = 1;
	}
	deg = u / 1000000;
	snprintf(buf, 4, "%03ld", deg);
	umnt = u % 1000000 * 60;
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

static struct aprs_interface *
aprs_lookup_interface(const int fd)
{
	int i;
	for (i = 0; i < naifs; i++)
		if (aifs[i]->ai_fd == fd)
			return aifs[i];
	return NULL;
}

static const char ax25_hdr[] = {
	'A' << 1, 'P' << 1, 'B' << 1, 'S' << 1, 'D' << 1, 'D' << 1, 0x60, /* destination */
	0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0xed,	/* source */
	0x03,						/* ui frame */
	0xf0,						/* no layer 3 */
};
static const int ax25_hdr_size = sizeof(ax25_hdr);

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
aprs_compose(char *buf, struct aprs_object *ao)
{
	struct gps_position gps;
	ssize_t len_info;
	char buf_info[256];

	memcpy(buf, ax25_hdr, ax25_hdr_size);

	/* if ((attrs->sensor != NULL) && (gps_get_position(&gps, attrs->sensor) == 2)) {
		ao.ao_lat = gps.lat;
		ao.ao_lon = gps.lon;
	} else if ((attrs->flags & BEACONF_POSSET) == BEACONF_POSSET) {
		ao.ao_lat = attrs->fixed_lat;
		ao.ao_lon = attrs->fixed_lon;
	} else {
		return 0;
	} */

	if (strcmp(ao->ao_source, ao->ao_name) == 0)
		len_info = aprs_compose_pos_info(buf_info, ao);
	else
		len_info = aprs_compose_obj_info(buf_info, ao);

	memcpy(&buf[16], buf_info, len_info);

	memcpy(&buf[7], ax25_aton(conf.mycall), AX25_ADDR_LEN);
	buf[13] |= 0xe1;

	return 16 + len_info;
}

/*
 * Open a BPF file and attach it to the interface named 'device'.
 * Set immediate mode.
 */
struct aprs_interface *
aprs_open(const char *device)
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

	yes = BPF_DIRECTION_OUT;

	if (ioctl(aif->ai_fd, BIOCSDIRFILT, &yes) == -1) {
		fatal("could not set direction filter");
	}

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
	int i;
	for (i = 0; i < naifs; i++)
		if (aifs[i]->ai_fd != src->ai_fd)
			write(aifs[i]->ai_fd, pkt, pktlen);
	/* TODO: so much error handling */
}

void
aprs_beacon_schedule(struct aprs_object *ao, int idx)
{
	struct timespec now;
	int offset;
	clock_gettime(CLOCK_MONOTONIC, &now);
	/* TODO: deal with decay algorithm here */
	if (idx == -1) {
		ao->ao_nexttime.tv_sec = now.tv_sec + conf.net_cycle;
	} else {
		offset = (conf.net_cycle * (idx + 1)) / (conf.num_entities + 1);
		printf("offset is %d\n", offset);
		ao->ao_nexttime.tv_sec = conf.station->ao_nexttime.tv_sec + offset;
	}
}

void
aprs_beacon(struct aprs_object *ao, int idx)
{
	unsigned char pkt_ax25[512];
	size_t len_ax25;
	int i;
	len_ax25 = aprs_compose(pkt_ax25, ao);
	for (i = 0; i < naifs; i++)
		if (write(aifs[i]->ai_fd, &pkt_ax25, len_ax25) != len_ax25)
			log_warn("failed to send packet on interface %s", aifs[i]->ai_name);
	aprs_beacon_schedule(ao, idx);
}

static void *
aprs_beacon_loop(void)
{
	struct kevent chlist[10];
	struct kevent evlist[10];
	struct timespec now;
	int bi, ii, evi, kq, nev, nr;
	struct aprs_interface *aif;
	unsigned char framebuf[512];

	if ((kq = kqueue()) == -1)
		fatal("failed to create kqueue");

	EV_SET(&chlist[0], 1, EVFILT_TIMER, EV_ADD | EV_ENABLE, 0, 1000, 0);

	for (ii = 0; ii < naifs; ii++)
		EV_SET(&chlist[ii + 1], aifs[ii]->ai_fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, 0);

	log_info("started up beacon loop (callsign: %s)", conf.mycall);

	while ((nev = kevent(kq, chlist, naifs + 1, evlist, naifs + 1, NULL)) > 0) {
		for (evi = 0; evi < nev; evi++) {
			if (evlist[evi].filter != EVFILT_TIMER) {
				char *bp, *ep;
				aif = aprs_lookup_interface(evlist[evi].ident);
				if ((nr = read(aif->ai_fd, framebuf, aif->ai_rbufsize)) == -1)
					fatal("read");
				bp = framebuf;
				ep = bp + nr;
				while (bp < ep) {
#define caplen ((struct bpf_hdr *)bp)->bh_caplen
#define hdrlen ((struct bpf_hdr *)bp)->bh_hdrlen
					aprs_digipeat(bp + hdrlen, caplen, aif);
					bp += BPF_WORDALIGN(hdrlen + caplen);
				}
				continue;
			}
			clock_gettime(CLOCK_MONOTONIC, &now);
			if (conf.station->ao_nexttime.tv_sec <= now.tv_sec)
				aprs_beacon(conf.station, -1);
			for (bi = 0; bi < conf.num_entities; bi++)
				if (conf.entities[bi]->ao_nexttime.tv_sec <= now.tv_sec)
					aprs_beacon(conf.entities[bi], bi);
		}
	}
	fatal("kevent");
}

int
main(int argc, char **argv)
{
	struct timeval now;
	int ci, debug, skipdelay, verbose;
	char ch, *conffile;

	debug = 0;
	verbose = 0;
	skipdelay = 0;
	conffile = "/etc/aprsd.conf";

	/* Check for root privileges. */
	if (geteuid())
		fatalx("need root privileges");

	while ((ch = getopt(argc, argv, "Dvsf:")) != -1) {
		switch (ch) {
		case 'D':
			debug = 1;
			break;
		case 'v':
			verbose = 1;
			break;
		case 's':
			skipdelay = 1;
			break;
		case 'f':
			conffile = optarg;
		default:
			usage();
			break;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc < 2)
		usage();

	log_init(debug, LOG_DAEMON);
	log_setverbose(verbose);

	log_debug("log init");

	if (ax25_aton(argv[0]) == NULL)
		fatalx("invalid station address");
	strlcpy(conf.mycall, argv[0], 10);

	conf.net_cycle = 600;

	if (parse_config(conffile, &conf) == -1)
		fatalx("could not parse config");

	if (!debug)
		daemonize();

	for (naifs = 0; naifs < argc - 1; naifs++)
		aifs[naifs] = aprs_open(argv[naifs + 1]);

	if (unveil(NULL, NULL) == -1)
		fatal("failed to unveil");
	if (pledge("stdio cpath wpath", NULL) == -1)
		fatal("failed to pledge");

	aprs_beacon_schedule(conf.station, -1);
	conf.station->ao_nexttime.tv_sec -= conf.net_cycle;
	if (!skipdelay)
		conf.station->ao_nexttime.tv_sec += conf.net_cycle / (conf.num_entities + 1);
	for (ci = 0; ci < conf.num_entities; ci++)
		aprs_beacon_schedule(conf.entities[ci], ci);
	aprs_beacon_loop();
}
