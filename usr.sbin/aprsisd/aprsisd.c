
#include <assert.h>
#include <ctype.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <vis.h>

#include <sys/event.h>
#include <sys/ioctl.h>
#include <sys/limits.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <net/if.h>
#include <net/if_tun.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netax25/if_ax25.h>

#include <tls.h>

#include "aprsis.h"
#include "tnc2.h"
#include "log.h"

/*
 * Much of the APRS-IS protocol has been based on the details found at:
 * http://www.aprs-is.net/Connecting.aspx
 */

/* Interval between station capabilities beacons */
#define CAPS_BEACON_INTERVAL 1800

/* Timeout for local stations to be removed from heard list */
#define LOC_TIMEOUT 1800

/* Maximum length in time to wait for data before reconnecting */
#define TCP_TIMEOUT 45

struct heard_entry {
	struct ax25_addr addr;
	struct timespec lastheard;
	LIST_ENTRY(heard_entry) entries;
};
LIST_HEAD(heard_list, heard_entry) heard;

struct timespec		 tcp_lastinput; /* last time data was received on tcp connection */
struct timespec		 next_beacon; /* time to send the next station caps */
long			 msg_cnt = 0;
int			 tap; /* file descriptor for tap device */
int			 tcp; /* file descriptor for tcp connection */
int			 usetls; /* command line flag -t */
int			 bidir; /* bi-directional igate */
char			*call; /* login name */
unsigned char		*ncall; /* network format address */
struct tls		*tls_ctx; /* tls context for tls connection */

static __dead void usage(void);
static void	 signal_handler(int sig);
static void	 daemonize(void);
static char	*call_strip_ssid(void);
static void	 send_station_capabilities(int);
static char	*aprsis_pass(void);
static int	 ax25_input(const unsigned char *, const size_t);
static int	 tnc2_output(const unsigned char *, const size_t);
static void	 ax25_output(const unsigned char *, const size_t);
static void	 tnc2_input(const unsigned char *, const size_t);
static void	*get_in_addr(struct sockaddr *);
static void	 aprsis_login_str(char *, char *, char *);
static int	 aprsis_remote_write(const char *, const size_t);
static int	 aprsis_remote_open(char *, char *, char *, char *);
static void	 aprsis_local_open(char *);
static int	 aprsis_local_shuffle(unsigned char *, unsigned char *, int);
static void	 aprsis_loop(void);
int		 main(int, char **);

int
ax25_cmp(const struct ax25_addr *a1, const struct ax25_addr *a2)
{
	int i;
	for (i = 0; i < 6; i++)
		if (a1->ax25_addr_octet[i] != a2->ax25_addr_octet[i])
			return 1;
	if ((a1->ax25_addr_octet[i] & AX25_SSID_MASK) !=
	    (a2->ax25_addr_octet[i] & AX25_SSID_MASK))
		return 2;
	return 0;
}

static __dead void
usage(void)
{
	extern char *__progname;

	fprintf(stderr, "usage: %s [-Dv] [-i axtapN] [-p passcode] [-f filter] callsign [server [port]]\n",
	    __progname);
	exit(1);
}

static void
signal_handler(int sig)
{
	switch (sig) {
	case SIGHUP:
		log_info("caught hangup signal");
		break;
	case SIGTERM:
		log_warnx("caught terminate signal, shutting down");
		exit(0);
		break;
	}
}

static void
daemonize(void)
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

static char *
call_strip_ssid()
{
	static char result[7];
	int i;
	char *ep;

	for (i = 0 ; call[i] != '\0' && call[i] != '-' && i < 7 ; i++ )
		result[i] = call[i];
	result[i] = '\0';
	return result;
}

/* info size must be least 256 bytes. */
static size_t
format_station_capabilities_info(unsigned char *info)
{
	struct heard_entry *hp;
	int loc_cnt = 0;

	LIST_FOREACH(hp, &heard, entries) {
		loc_cnt++;
	}
	return snprintf(info, 256, "<IGATE,LOC_CNT=%d,MSG_CNT=%ld", loc_cnt, msg_cnt);
}

static void
send_station_capabilities(int rfonly)
{
	unsigned char pkt[270]; /* 16 (header) + 256 (info) */
	int len;
	memcpy(pkt, ax25_aton("APBSDI"), AX25_ADDR_LEN);
	memcpy(AX25_ADDR_PTR(pkt, 1), ax25_aton("MM0ROR-10"), AX25_ADDR_LEN);
	AX25_ADDR_PTR(pkt, 1)->ax25_addr_octet[6] |= AX25_LAST_MASK;
	pkt[14] = 0x03;
	pkt[15] = 0xf0;
	len = 16 + format_station_capabilities_info(&pkt[16]);
	ax25_output(pkt, len);
	if (rfonly == 0) {
		log_info("capabilities: %s", &pkt[16]);
		ax25_input(pkt, len);
	}
}

static char *
aprsis_pass()
{
	static char pass[6];
	char *cp;
	int16_t hash;

	cp = call_strip_ssid();
	hash = 0x73e2;
	while (cp != '\0') {
		hash ^= (toupper(*(cp++)) << 8);
		if (cp != '\0')
			hash ^= (toupper(*(cp++)));
	}
	snprintf(pass, 6, "%d", hash);
	return pass;
}

static void
ax25_heard(const struct ax25_addr *a)
{
	struct heard_entry *hp;

	LIST_FOREACH(hp, &heard, entries) {
		if (ax25_cmp(&hp->addr, a) == 0)
			break;
	}

	if (hp == NULL) {
		hp = malloc(sizeof(struct heard_entry));
		memcpy(&hp->addr, a, AX25_ADDR_LEN);
		LIST_INSERT_HEAD(&heard, hp, entries);
	}

	clock_gettime(CLOCK_MONOTONIC, &hp->lastheard);
}

static int
ax25_input(const unsigned char *pkt_ax25, const size_t len_ax25)
{
	unsigned char pkt_tnc2[TNC2_MAXLINE];
	size_t len_tnc2;

	if (len_ax25 < 14)
		/* TODO: should I log here? does ax25_to_tnc2 do this check? */
		return 0;

	ax25_heard(AX25_ADDR_PTR(pkt_ax25, 1));

	len_tnc2 = ax25_to_tnc2(pkt_tnc2, pkt_ax25, len_ax25);

	switch (len_tnc2) {
	case 0:
		/* Packet should be dropped */
		return 0;
	case 1:
		/* This was a general IGate query */
		send_station_capabilities(1);
		return 0;
	case 2:
	case 3:
	case 4:
	case 5:
	case 6:
	case 7:
	case 8:
	case 9:
	case 10:
		/* Keep these reserved as special cases. */
		return 0;
	default:
		return tnc2_output(pkt_tnc2, len_tnc2);
	}
}

static int
tnc2_output(const unsigned char *pkt_tnc2, const size_t len)
{
	char dbg_tnc2[(TNC2_MAXLINE * 4) + 1];
	int i;

	/* defence in depth, this should have been cleared by ax25_to_tnc2 */
	assert(pkt_tnc2[0] != '#');
	for (i = 1; i < len; i++)
		assert(pkt_tnc2[i] != '\r' && pkt_tnc2[i] != '\n');

	/* packets may contain \0 and other non-printables */
	strvisx(dbg_tnc2, pkt_tnc2, len, VIS_WHITE);
	log_debug("snd: %s", dbg_tnc2);

	aprsis_remote_write(pkt_tnc2, len);
	aprsis_remote_write("\r\n", 2);
	return len + 2;
}

static void
ax25_output(const unsigned char *pkt_ax25, const size_t len_ax25)
{
	if (write(tap, pkt_ax25, len_ax25) == -1)
		fatal("ax25_output: write");
}

static void
tnc2_input(const unsigned char *pkt_tnc2, const size_t len_tnc2)
{
	unsigned char pkt_ax25[1024];
	const unsigned char *payload = NULL;
	size_t len_ax25;
	int i;

	memcpy(pkt_ax25, ax25_aton("APBSDI"), AX25_ADDR_LEN);
	memcpy(AX25_ADDR_PTR(pkt_ax25, 1), ncall, AX25_ADDR_LEN);
	AX25_ADDR_PTR(pkt_ax25, 1)->ax25_addr_octet[6] |= AX25_LAST_MASK;
	pkt_ax25[14] = 0x03;
	pkt_ax25[15] = 0xf0;
	pkt_ax25[16] = '}';
	len_ax25 = 17;

	/* Identify the start of the payload */
	for (i = 0; i < len_tnc2; i++) {
		if (pkt_tnc2[i] == ':') {
			payload = &pkt_tnc2[i];
			break;
		}
	}

	if (payload == NULL) {
		log_debug("dropping packet: contained no payload (no colon)");
		return;
	}

	for (i = 0; &pkt_tnc2[i] < payload; i++) {
		if (pkt_tnc2[i] == ',') {
			memcpy(&pkt_ax25[len_ax25], pkt_tnc2, i);
			len_ax25 += i;
			break;
		}
	}

	if (&pkt_tnc2[i] == payload) {
		log_debug("dropping packet: never found a comma in the header");
		return;
	}

	memcpy(&pkt_ax25[len_ax25], payload, len_tnc2 - (payload - pkt_tnc2));
	len_ax25 += len_tnc2 - (payload - pkt_tnc2);

	msg_cnt++;
	ax25_output(pkt_ax25, len_ax25);
}

static void
aprsis_input(const unsigned char *isb, const ssize_t len_isb)
{
	static size_t len_tnc2 = 0;
	static unsigned char pkt_tnc2[TNC2_MAXLINE];
	int i;
	unsigned char dbg_tnc2[(TNC2_MAXLINE * 4) + 1];
	if (len_isb == -1) {
		log_debug("aprsis_input: reset");
		len_tnc2 = 0;
		return;
	}
	log_debug("aprsis_input: %zu bytes", len_isb);
	for (i = 0; i < len_isb; i++) {
		switch (isb[i]) {
			case '\r':
				/* FALLTHROUGH */
			case '\n':
				if (len_tnc2 > 9 && pkt_tnc2[0] != '#') {
					strvisx(dbg_tnc2, pkt_tnc2, len_tnc2, VIS_WHITE);
					log_debug("rcv: %s", dbg_tnc2);
					tnc2_input(pkt_tnc2, len_tnc2);
				}
				len_tnc2 = 0;
				break;
			default:
				pkt_tnc2[len_tnc2++] = isb[i];
				break;
		}
	}
}

static void *
get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET)
		return &(((struct sockaddr_in*)sa)->sin_addr);
	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

static void
aprsis_login_str(char *login, char *pass, char *filter)
{
	memset(login, 0, TNC2_MAXLINE);
	strlcpy(login, "user ", TNC2_MAXLINE);
	strlcat(login, call, TNC2_MAXLINE);
	strlcat(login, " pass ", TNC2_MAXLINE);
	strlcat(login, pass, TNC2_MAXLINE);
	strlcat(login, " vers HamBSD-aprsisd 0.0-dev", TNC2_MAXLINE);
	if (filter != NULL) {
		strlcat(login, " filter ", TNC2_MAXLINE);
		strlcat(login, filter, TNC2_MAXLINE);
	}
	strlcat(login, "\r\n", TNC2_MAXLINE);
}

/*
 * Constructs a filesystem path to the TLS client certificate for a given
 * callsign. The provided buffer must be at least MAXPATHLEN in size.
 */
static char *
aprsis_tls_cert_file(char *buf)
{
	static char sbuf[MAXPATHLEN];
	if (buf == NULL)
		buf = (char *)sbuf;
	snprintf(buf, MAXPATHLEN, "/etc/ssl/%s.crt", call_strip_ssid());
	return buf;
}

/*
 * Constructs a filesystem path to the TLS client key for a given
 * callsign. The provided buffer must be at least MAXPATHLEN in size.
 */
static char *
aprsis_tls_key_file(char *buf)
{
	static char sbuf[MAXPATHLEN];
	if (buf == NULL)
		buf = (char *)sbuf;
	snprintf(buf, MAXPATHLEN, "/etc/ssl/private/%s.key", call_strip_ssid());
	return buf;
}

static int
aprsis_remote_write(const char *buf, const size_t len)
{
	int rem;
	rem = len;
	while (rem > 0) {
		ssize_t ret;
		if (usetls) {
			ret = tls_write(tls_ctx, buf, rem);
			if (ret == TLS_WANT_POLLIN || ret == TLS_WANT_POLLOUT)
				continue;
			if (ret == -1) {
				log_warnx("tls_write: %s", tls_error(tls_ctx));
				return -1;
			}
		} else {
			if (write(tcp, buf, rem) == -1) {
				log_warn("write");
				return -1;
			}
		}
		buf += ret;
		rem -= ret;
	}
	return 0;
}

static int
aprsis_remote_open(char *server, char *port, char *pass,
    char *filter)
{
	struct addrinfo hints, *servinfo, *p;
	struct tls_config *tls_config;
	int nodelay, rv;
	char *login, cert_file[MAXPATHLEN], key_file[MAXPATHLEN], as[INET6_ADDRSTRLEN];

	if (usetls) {
		if (tls_init() == -1)
			fatalx("tls_init");
		if ((tls_ctx = tls_client()) == NULL)
			fatalx("tls_client");
		if ((tls_config = tls_config_new()) == NULL)
			fatalx("tls_config_new");

		/* the ssl.aprs2.net servers cannot cope with "secure" */
		if (tls_config_set_ciphers(tls_config, "compat") == -1)
			fatalx("tls_config_set_ciphers: %s", tls_config_error(tls_config));

		aprsis_tls_cert_file(cert_file);
		log_debug("certificate file: %s", cert_file);
		aprsis_tls_key_file(key_file);
		log_debug("key file: %s", key_file);
		if (tls_config_set_ca_file(tls_config, "/etc/ssl/hamcert.pem") == -1)
			fatalx("tls_config_set_ca_file: %s", tls_config_error(tls_config));
		if (tls_config_set_cert_file(tls_config, cert_file) == -1)
			fatalx("tls_config_set_cert_file: %s", tls_config_error(tls_config));
		if (tls_config_set_key_file(tls_config, key_file) == -1)
			fatalx("tls_config_set_key_file: %s", tls_config_error(tls_config));

		/* ssl.aprs2.net isn't in the names for the servers */
		tls_config_insecure_noverifyname(tls_config);

		if (tls_configure(tls_ctx, tls_config) == -1)
			fatalx("tls_configure: %s", tls_error(tls_ctx));
	}

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ((rv = getaddrinfo(server, port, &hints, &servinfo)) != 0) {
		log_warnx("getaddrinfo: %s\n", gai_strerror(rv));
		return -1;
	}

	for (p = servinfo; p != NULL; p = p->ai_next) {
		inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr), as, sizeof(as));
		log_info("connecting to %s", as);
		if ((tcp = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
			log_warn("socket");
			continue;
		}
		if (connect(tcp, p->ai_addr, p->ai_addrlen) == -1) {
			close(tcp);
			log_warn("connect");
			continue;
		}
		nodelay = 1;
		setsockopt(tcp, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));
		if (usetls) {
			if (tls_connect_socket(tls_ctx, tcp, server) == -1) {
				log_warnx("tls_connect_socket: %s", tls_error(tls_ctx));
				continue;
			}
			if (tls_handshake(tls_ctx) == -1) {
				log_warnx("tls_handshake: %s", tls_error(tls_ctx));
				continue;
			}
			log_debug("established tls session");
		}
		break;
	}

	freeaddrinfo(servinfo);

	if (p == NULL) {
		log_warnx("exhausted servers available for %s", server);
		return -1;
	}

	log_debug("opened connection to %s", as);

	/* undocumented feature, please ignore */
	if (strcmp(pass, "please") == 0)
		pass = aprsis_pass();

	login = malloc(TNC2_MAXLINE);
	aprsis_login_str(login, pass, filter);
	aprsis_remote_write(login, strlen(login));
	log_debug("login string sent");

	free(login);

	log_info("connected to %s", as);
	return 0;
}

static void
aprsis_local_open(char *interface)
{
	struct ifreq ifr;
	struct tuninfo ti;
	char ifpath[PATH_MAX];
	int i, sock;

	if (interface != NULL) {
		if (strlen(interface) < 6 || memcmp(interface, "axtap", 5) != 0)
			fatalx("interface must be an axtap");
		snprintf(ifpath, PATH_MAX, "/dev/%s", interface);
		if ((tap = open(ifpath, O_RDWR)) == -1)
			return;
	} else {
		for (i = 0; i < 100; i++) {
			snprintf(ifpath, PATH_MAX, "/dev/axtap%d", i);
			if ((tap = open(ifpath, O_RDWR)) != -1)
				break;
		}
	}
	ioctl(tap, TUNGIFINFO, &ti);
	ti.flags = IFF_UP | IFF_POINTOPOINT;
	ioctl(tap, TUNSIFINFO, &ti);

	strlcpy(ifr.ifr_name, &ifpath[5], sizeof(ifr.ifr_name));
	ifr.ifr_addr.sa_len = AX25_ADDR_LEN;
	ifr.ifr_addr.sa_family = AF_LINK;
	memcpy(ifr.ifr_addr.sa_data, ncall, AX25_ADDR_LEN);

	sock = socket(AF_INET, SOCK_DGRAM, 0);

	if (ioctl(sock, SIOCSIFLLADDR, &ifr) == -1)
		fatal("SIOCSIFLLADDR");
	
}

static void
aprsis_loop(void)
{
	struct kevent chlist[4];
	struct kevent evlist[4];
	struct timespec now;
	int evi, nr, nev;
	static int kq = -1;
	unsigned char buf[1500]; /* used for both SIGINFO log and axtap reads */
	struct heard_entry *hep, *hetmp;

	if (kq == -1)
		if ((kq = kqueue()) == -1)
			fatal("kqueue");

	/* This one will always be new */
	EV_SET(&chlist[0], tcp, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, 0);

	/* These three might exist, but no harm in updating them */
	EV_SET(&chlist[1], tap, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, 0);
	EV_SET(&chlist[2], 1, EVFILT_TIMER, EV_ADD | EV_ENABLE, 0, 1000, 0);
	EV_SET(&chlist[3], SIGINFO, EVFILT_SIGNAL, EV_ADD | EV_ENABLE, 0, 0, 0);

	/* Initialise timeout */
	clock_gettime(CLOCK_MONOTONIC, &tcp_lastinput);

	log_debug("starting loop");

	while ((nev = kevent(kq, chlist, 4, evlist, 4, NULL)) > 0) {
		for (evi = 0; evi < nev; evi++) {
			explicit_bzero(buf, 1500); /* purely defensive; shouldn't be required */
			switch (evlist[evi].filter) {
			case EVFILT_SIGNAL:
				buf[format_station_capabilities_info(buf)] = '\0';
				log_info("%s", buf);
				break;
			case EVFILT_TIMER:
				clock_gettime(CLOCK_MONOTONIC, &now);
				if (now.tv_sec - tcp_lastinput.tv_sec > TCP_TIMEOUT) {
					log_debug("%lld seconds since last input",
					    now.tv_sec - tcp_lastinput.tv_sec);
					return;
				}
				LIST_FOREACH_SAFE(hep, &heard, entries, hetmp) {
					if (now.tv_sec - hep->lastheard.tv_sec > LOC_TIMEOUT) {
						log_debug("heard entry %s expiring after %lld seconds",
						    ax25_ntoa(&hep->addr),
						    now.tv_sec - hep->lastheard.tv_sec);
						LIST_REMOVE(hep, entries);
						free(hep);
					}
				}
				if (next_beacon.tv_sec < now.tv_sec) {
					send_station_capabilities(0);
					next_beacon.tv_sec = now.tv_sec + 18; //00;
				}
				break;
			case EVFILT_READ:
				if (evlist[evi].ident == tap) {
					if ((nr = read(tap, buf, 1500)) == -1 || nr == 0)
						fatal("read tap");
					if (ax25_input(buf, nr) == -1)
						/* error occured writing to APRS-IS; let's reconnect */
						return;
				} else if (evlist[evi].ident == tcp) {
					clock_gettime(CLOCK_MONOTONIC, &tcp_lastinput);
					if (usetls) {
						if ((nr = tls_read(tls_ctx, buf, TNC2_MAXLINE)) == -1) {
							log_warnx("tls_read: %s", tls_error(tls_ctx));
							return;
						}
					} else {
						if (((nr = read(tcp, buf, TNC2_MAXLINE)) == -1) || nr == 0)
							return;
					}
					aprsis_input(buf, nr);
				}
				break;
			}
		}
	}
}

int
main(int argc, char **argv)
{
	char ch, *filter, *interface, *pass, *port, *server;
	const char *errstr;
	int debug, verbose;

	debug = 0; /* stay in foreground */
	verbose = 0; /* debug level logging */
	pass = "-1"; /* APRS-IS login passcode */
	filter = NULL; /* APRS-IS filter; see aprsis-filter(7) */
	interface = NULL; /* local axtap interface name */
	server = "rotate.aprs2.net"; /* APRS-IS server hostname */
	port = "14580"; /* APRS-IS server port */
	usetls = 0;
	bidir = 0;

	/* Check for root privileges. */
	if (geteuid())
		fatalx("need root privileges");

	while ((ch = getopt(argc, argv, "Dvtbi:p:f:")) != -1) {
		switch (ch) {
		case 'D':
			debug = 1;
			break;
		case 'v':
			verbose = 1;
			break;
		case 't':
			usetls = 1;
			server = "ssl.aprs2.net";
			port = "24580";
			break;
		case 'b':
			bidir = 1;
			break;
		case 'i':
			interface = optarg;
			break;
		case 'p':
			pass = optarg;
			break;
		case 'f':
			filter = optarg;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (argc < 1)
		usage();

	log_init(debug, LOG_DAEMON);
	log_setverbose(verbose);

	log_debug("log init");

	call = argv[0];
	ncall = malloc(AX25_ADDR_LEN);
	memcpy(ncall, ax25_aton(call), AX25_ADDR_LEN);

	if (argc > 1)
		server = argv[1];
	if (argc > 2)
		port = argv[2];

	if (!debug)
		daemonize();

	LIST_INIT(&heard);
	clock_gettime(CLOCK_MONOTONIC, &next_beacon);
	next_beacon.tv_sec += (CAPS_BEACON_INTERVAL / 2);

	/* the path for the tap device is unknown until we open it */
	aprsis_local_open(interface);
	if (tap == -1)
		fatal("tap open");

	if (usetls) {
		if (unveil("/etc/ssl/hamcert.pem", "r") == -1)
			fatal("unveil");
		if (unveil(aprsis_tls_cert_file(NULL), "r") == -1)
			fatal("unveil");
		if (unveil(aprsis_tls_key_file(NULL), "r") == -1)
			fatal("unveil");
		if (pledge("stdio rpath inet dns", NULL) == -1)
			fatal("pledge");
	} else {
		/* no filesystem visibility */
		if (unveil("/", "") == -1)
			fatal("unveil");
		if (pledge("stdio inet dns", NULL) == -1)
			fatal("pledge");
	}

	for (;;) {
		if (aprsis_remote_open(server, port, pass, filter) == -1) {
			log_warnx("connection failed, reconnecting in 30 seconds...");
			sleep(30);
			continue;
		}
		aprsis_loop();
		if (usetls) {
			if (tls_close(tls_ctx) == -1)
				log_warnx("tls_close: %s", tls_error(tls_ctx));
			tls_free(tls_ctx);
		}
		close(tcp);
		aprsis_input(NULL, -1); /* reset the buffer */
		log_warnx("disconnected from server, reconnecting in 30 seconds...");
		sleep(30);
	}
}
