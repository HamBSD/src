
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
static void	 send_station_capabilities(void);
static char	*aprsis_pass(void);
static int	 forbidden_gate_path_address(const unsigned char *);
static int	 ax25_input(const unsigned char *, const size_t);
static int	 tnc2_output(const unsigned char *, const size_t);
static void	 ax25_output(const unsigned char *, const size_t);
static void	 tnc2_input(const unsigned char *, const size_t);
static void	*get_in_addr(struct sockaddr *);
static void	 aprsis_login_str(char *, char *, char *);
static int	 aprsis_remote_write(const char *, const size_t);
static int	 aprsis_remote_open(char *, char *, char *, char *);
static void	 aprsis_local_open(char *);
static int	 aprsis_local_shuffle(char *, char *, int);
static void	 aprsis_loop(void);
int		 main(int, char **);

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

static void
send_station_capabilities()
{
	unsigned char pkt[22];
	memcpy(pkt, ax25_aton("APBSDI"), AX25_ADDR_LEN);
	memcpy(AX25_ADDR_PTR(pkt, 1), ax25_aton("MM0ROR-10"), AX25_ADDR_LEN);
	AX25_ADDR_PTR(pkt, 1)->ax25_addr_octet[6] |= AX25_LAST_MASK;
	pkt[14] = 0x03;
	pkt[15] = 0xf0;
	pkt[16] = '<';
	pkt[17] = 'I';
	pkt[18] = 'G';
	pkt[19] = 'A';
	pkt[20] = 'T';
	pkt[21] = 'E';
	ax25_output(pkt, 22);
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

static const unsigned char ax25_nogate[] = { 'N' << 1, 'O' << 1, 'G' << 1, 'A' << 1, 'T' << 1, 'E' << 1 };
static const unsigned char ax25_rfonly[] = { 'R' << 1, 'F' << 1, 'O' << 1, 'N' << 1, 'L' << 1, 'Y' << 1 };
static const unsigned char ax25_tcpip[]  = { 'T' << 1, 'C' << 1, 'P' << 1, 'I' << 1, 'P' << 1, ' ' << 1 };
static const unsigned char ax25_tcpxx[]  = { 'T' << 1, 'C' << 1, 'P' << 1, 'X' << 1, 'X' << 1, ' ' << 1 };
static const unsigned char *aprsis_forbidden_gate_addresses[] = {
    ax25_nogate,
    ax25_rfonly,
    ax25_tcpip,
    ax25_tcpxx,
    NULL
};

static int
forbidden_gate_path_address(const unsigned char *pa)
{
	int i;
	for (i = 0 ;; i++) {
		if (aprsis_forbidden_gate_addresses[i] == NULL)
			break;
		if (memcmp(pa, aprsis_forbidden_gate_addresses[i], 6) == 0)
			return 1;
	}
	/* TODO: q constructs? */
	return 0;
}

static int
ax25_input(const unsigned char *pkt_ax25, const size_t len_ax25) {
	unsigned char pkt_tnc2[TNC2_MAXLINE];
	size_t tnc2_len;

	tnc2_len = ax25_to_tnc2(pkt_tnc2, pkt_ax25, len_ax25);

	switch (tnc2_len) {
	case 0:
		/* Packet should be dropped */
		return 0;
	case 1:
		/* This was a general IGate query */
		send_station_capabilities();
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
		return tnc2_output(pkt_tnc2, tnc2_len);
	}
}

static int
tnc2_output(const unsigned char *s, const size_t len)
{
	log_debug("snd: %s", s); /* TODO: strvis */
	aprsis_remote_write(s, len);
	aprsis_remote_write("\r\n", 2);
	return len + 2;
}


static void
ax25_output(const unsigned char *pkt, const size_t len)
{
	if (write(tap, pkt, len) == -1)
		fatal("ax25_output: write");
}

static void
tnc2_input(const unsigned char *pkt_tnc2, size_t tnc2_len)
{
	unsigned char pkt_ax25[1024];
	const unsigned char *payload = NULL;
	int i, tp;

	memcpy(pkt_ax25, ax25_aton("APBSDI"), AX25_ADDR_LEN);
	memcpy(AX25_ADDR_PTR(pkt_ax25, 1), ncall, AX25_ADDR_LEN);
	AX25_ADDR_PTR(pkt_ax25, 1)->ax25_addr_octet[6] |= AX25_LAST_MASK;
	pkt_ax25[14] = 0x03;
	pkt_ax25[15] = 0xf0;
	pkt_ax25[16] = '}';

	/* Identify the start of the payload */
	for (tp = 0; tp < tnc2_len; tp++) {
		if (pkt_tnc2[tp] == ':') {
			payload = &pkt_tnc2[tp];
			break;
		}
	}

	if (payload == NULL) {
		log_debug("dropping packet: contained no payload (no colon)");
		return;
	}

	for (tp = 0; &pkt_tnc2[tp] < payload; tp++) {
		if (pkt_tnc2[tp] == ',') {
			memcpy(&pkt_ax25[17], pkt_tnc2, tp);
			break;
		}
	}

	if (&pkt_tnc2[tp] == payload) {
		log_debug("dropping packet: never found a comma in the header");
		return;
	}

	memcpy(&pkt_ax25[17 + tp], payload, tnc2_len - (payload - pkt_tnc2));

	ax25_output(pkt_ax25, 15 + tp + (tnc2_len - (payload - pkt_tnc2)));
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
	strlcat(login, "\n", TNC2_MAXLINE);
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

		/* the aprs2.net CA certificate is unknown */
		tls_config_insecure_noverifycert(tls_config);

		/* ssl.aprs2.net isn't in the names for the servers */
		tls_config_insecure_noverifyname(tls_config);

		if (tls_configure(tls_ctx, tls_config) == -1)
			fatalx("tls_configure: %s", tls_error(tls_ctx));
	}

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ((rv = getaddrinfo(server, port, &hints, &servinfo)) != 0) {
		fatalx("getaddrinfo: %s\n", gai_strerror(rv));
	}

	for (p = servinfo; p != NULL; p = p->ai_next) {
		if ((tcp = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
			log_warn("socket");
			continue;
		}
		if (connect(tcp, p->ai_addr, p->ai_addrlen) == -1) {
			close(tcp);
			log_warn("connect");
			continue;
		}
		break;
	}

	if (p == NULL)
		fatal("connect");

	nodelay = 1;
	setsockopt(tcp, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));

	inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr), as, sizeof(as));

	freeaddrinfo(servinfo);

	log_debug("opened connection to %s", as);

	if (usetls) {
		if (tls_connect_socket(tls_ctx, tcp, server) == -1)
			fatalx("tls_connect_socket: %s", tls_error(tls_ctx));
		if (tls_handshake(tls_ctx) == -1)
			fatalx("tls_handshake: %s", tls_error(tls_ctx));
		log_debug("established tls session");
	}

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
		if (strlen(interface) < 2)
			fatalx("interface name too short");
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
	memcpy(ifr.ifr_addr.sa_data, ax25_aton(call), AX25_ADDR_LEN);

	sock = socket(AF_INET, SOCK_DGRAM, 0);

	if (ioctl(sock, SIOCSIFLLADDR, &ifr) == -1)
		fatal("SIOCSIFLLADDR");
	
}

/*
 * Once a newline is found in the buffer, swap the CRLF (or just LF)
 * for NUL to terminate the string and pass it to tnc2_input. Any
 * remaining data in the buffer gets shuffled to the front and the
 * new position in the buffer is returned.
 */
static int
aprsis_local_shuffle(char *buf, char *ep, int pos)
{
	int ei = ep - buf;
	if (buf[ei - 1] == '\r')
		buf[ei - 1] = '\0';
	buf[ei++] = '\0'; /* move index to start of new packet */
	log_debug("rcv: %s\n", buf);
	if (ei > 10 && buf[0] != '#')
		/* a reasonable minimum length and not in-band signalling */
		tnc2_input(buf, ei);
	memmove(buf, &buf[ei], pos - ei);
	pos -= ei;
	return pos;
}

static void
aprsis_loop(void)
{
	struct kevent chlist[2];
	struct kevent evlist[2];
	int evi, kq, nr, nev, r_pos;
	char r_buf[TNC2_MAXLINE], *r_ep;
	unsigned char l_buf[1500];

	r_pos = 0;
	bzero(r_buf, TNC2_MAXLINE);
	bzero(l_buf, 1500);

	if ((kq = kqueue()) == -1)
		fatal("kqueue");

	EV_SET(&chlist[0], tcp, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, 0);
	EV_SET(&chlist[1], tap, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, 0);

	log_debug("starting loop");

	while ((nev = kevent(kq, chlist, 2, evlist, 2, NULL)) > 0) {
		for (evi = 0; evi < nev; evi++) {
			if (evlist[evi].ident == tap) {
				log_debug("got a tap event");
				if ((nr = read(tap, l_buf, 1500)) == -1 || nr == 0)
					fatal("read tap");
				if (ax25_input(l_buf, nr) == -1)
					/* error occured writing to APRS-IS; let's reconnect */
					return;
			} else if (evlist[evi].ident == tcp) {
				log_debug("got a tcp event");
				if (usetls) {
					if (((nr = tls_read(tls_ctx, &r_buf[r_pos], TNC2_MAXLINE - r_pos)) == -1)) {
						log_warnx("tls_read: %s", tls_error(tls_ctx));
						return;
					}
				} else {
					if (((nr = read(tcp, &r_buf[r_pos], TNC2_MAXLINE - r_pos)) == -1) || nr == 0)
						return;
				}
				r_pos += nr;
				if ((r_ep = strchr(r_buf, '\n')) != NULL)
					r_pos = aprsis_local_shuffle(r_buf, r_ep, r_pos);
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
		while (aprsis_remote_open(server, port, pass, filter) == -1) {
			log_warnx("connection failed, reconnecting in 30 seconds...");
			sleep(30);
		}
		aprsis_loop();
		log_warnx("disconnected from server, reconnecting in 30 seconds...");
	}
}
