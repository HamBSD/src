
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

#include "log.h"

/*
 * Much of the APRS-IS protocol has been based on the details found at:
 * http://www.aprs-is.net/Connecting.aspx
 */

#define TNC2_MAXLINE 512

struct sockaddr_ax25 {
	u_int8_t		sax_len;
	sa_family_t		sax_family;
	struct ax25_addr	sax_addr;
	int8_t			sax_pathlen;
	struct ax25_addr	sax_path[AX25_MAX_DIGIS];
};

int			 tap; /* file descriptor for tap device */
int			 tcp; /* file descriptor for tcp connection */
int			 usetls; /* command line flag -t */
struct tls		*tls_ctx; /* tls context for tls connection */

static __dead void usage(void);
static void	 signal_handler(int sig);
static void	 daemonize(void);
static char	*call_strip_ssid(char *);
static char	*aprsis_pass(char *);
static int	 forbidden_gate_path_address(caddr_t);
static int	 ax25_input(char *, int);
static void	 ax25_output(char *, int);
static char	*tnc2_hdr_to_ax25(struct sockaddr_ax25 *, struct sockaddr_ax25 *, char *);
static void	 tnc2_input(char *);
static int	 tnc2_output(char *, int);
static void	*get_in_addr(struct sockaddr *);
static void	 aprsis_login_str(char *, char *, char *, char *);
static int	 aprsis_remote_write(char *, ssize_t);
static int	 aprsis_remote_open(char *, char *, char *, char *, char *);
static void	 aprsis_local_open(char *, char *);
static int	 aprsis_local_shuffle(char *, char *, int);
static void	 aprsis_loop(void);
int		 main(int, char **);

static __dead void
usage(void)
{
	extern char *__progname;

	fprintf(stderr, "usage: %s [-D] [-i axtapN] [-p passcode] [-f filter] callsign [server [port]]\n",
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
call_strip_ssid(char *call)
{
	static char result[7];
	int i;
	char *ep;

	for (i = 0 ; call[i] != '\0' && call[i] != '-' && i < 7 ; i++ )
		result[i] = call[i];
	result[i] = '\0';
	return result;
}

static char *
aprsis_pass(char *call)
{
	static char pass[6];
	char *cp;
	int16_t hash;

	cp = call_strip_ssid(call);
	hash = 0x73e2;
	while (cp != '\0') {
		hash ^= (toupper(*(cp++)) << 8);
		if (cp != '\0')
			hash ^= (toupper(*(cp++)));
	}
	snprintf(pass, 6, "%d", hash);
	return pass;
}

static char ax25_nogate[] = { 'N' << 1, 'O' << 1, 'G' << 1, 'A' << 1, 'T' << 1, 'E' << 1 };
static char ax25_rfonly[] = { 'R' << 1, 'F' << 1, 'O' << 1, 'N' << 1, 'L' << 1, 'Y' << 1 };
static char ax25_tcpip[]  = { 'T' << 1, 'C' << 1, 'P' << 1, 'I' << 1, 'P' << 1, ' ' << 1 };
static char ax25_tcpxx[]  = { 'T' << 1, 'C' << 1, 'P' << 1, 'X' << 1, 'X' << 1, ' ' << 1 };
static caddr_t aprsis_forbidden_gate_addresses[] = {
    ax25_nogate,
    ax25_rfonly,
    ax25_tcpip,
    ax25_tcpxx,
    NULL
};

static int
forbidden_gate_path_address(caddr_t pa)
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
ax25_input(char *pkt, int len)
{
	char dst[10], src[10], tl[TNC2_MAXLINE];
	int dn, ahlen, tllen;
	strlcpy(dst, ax25_ntoa((struct ax25_addr *)&pkt[0]), 10);
	strlcpy(src, ax25_ntoa((struct ax25_addr *)&pkt[7]), 10);
	snprintf(tl, TNC2_MAXLINE, "%s>%s", src, dst);
	for (dn = 0; dn < AX25_MAX_DIGIS; ++dn) {
		if (forbidden_gate_path_address(&pkt[7 * (dn + 1)])) {
			log_info("a packet was dropped with forbidden entry in path");
			return 0;
		}
		if (pkt[(7 * (dn + 1)) + 6] & AX25_LAST_MASK)
			break;
		strlcat(tl, ",", TNC2_MAXLINE);
		strlcat(tl, ax25_ntoa((struct ax25_addr *)&pkt[7 * (dn + 2)]), TNC2_MAXLINE);
	}
	strlcat(tl, ":", TNC2_MAXLINE);
	ahlen = 7 * (dn + 2) + 2;
	tllen = strlen(tl);
	if (tllen + (len - ahlen) + 1 < TNC2_MAXLINE) {
		memcpy(&tl[tllen], &pkt[ahlen], len - ahlen);
		tllen += len - ahlen;
		tl[tllen++] = '\n';
		return tnc2_output(tl, tllen);
	}
	log_warnx("a packet was dropped because the TNC2 representation exceeded TNC2_MAXLINE");
	return 1;
}

static void
ax25_output(char *pkt, int len)
{
	if (write(tap, pkt, len) == -1)
		fatal("ax25_output: write");
}

static char *
tnc2_hdr_to_ax25(struct sockaddr_ax25 *saddr, struct sockaddr_ax25 *daddr,
    char *s)
{
	char as[10];
	struct ax25_addr *addr;
	int dn, h;
	char *bp, *ep, *pp;

	if ((pp = strchr(s, ':')) == NULL)
		return NULL;
	bp = ep = s;
	for (dn = -2 ; ep != pp && dn < AX25_MAX_DIGIS ; dn++) {
		for (ep = bp; ep < pp; ep++)
			if (*ep == '>' || *ep == ',')
				break;
		bzero(as, 10);
		if (ep - bp < 3 || ep - bp > 9)
			return NULL;
		memcpy(as, bp, ep - bp);
		if ((h = (as[ep - bp - 1] == '*')))
			as[ep - bp - 1] = '\0';
		if ((addr = ax25_aton(as)) == NULL)
			return NULL;
		saddr->sax_path[dn].ax25_addr_octet[6] |= AX25_RESERVED_MASK;
		if (h)
			saddr->sax_path[dn].ax25_addr_octet[6] |= AX25_CR_MASK;
		switch (dn) {
		case -2:
			/* source address */
			memcpy(&saddr->sax_addr, addr, sizeof(struct ax25_addr));
			break;
		case -1:
			/* destination address */
			memcpy(&daddr->sax_addr, addr, sizeof(struct ax25_addr));
			daddr->sax_addr.ax25_addr_octet[6] |= AX25_CR_MASK;
			break;
		default:
			/* digi path */
			memcpy(&saddr->sax_path[dn], addr, sizeof(struct ax25_addr));
			break;
		}
		bp = ep + 1;
	}
	if (dn == 0) {
		saddr->sax_addr.ax25_addr_octet[6] |= AX25_LAST_MASK;
	} else {
		saddr->sax_path[dn - 1].ax25_addr_octet[6] |= AX25_LAST_MASK;
	}
	saddr->sax_pathlen = dn;
	return pp + 1;
}

static void
tnc2_input(char *s)
{
	char pkt[1024], *payload;
	struct sockaddr_ax25 saddr, daddr;
	int dn, len;
	if ((payload = tnc2_hdr_to_ax25(&saddr, &daddr, s)) == NULL)
		return;
	memcpy(pkt, &daddr.sax_addr, sizeof(struct ax25_addr));
	memcpy(&pkt[7], &saddr.sax_addr, sizeof(struct ax25_addr));
	for (dn = 0; dn < saddr.sax_pathlen; dn++)
		memcpy(&pkt[14 + (7 * dn)], &saddr.sax_path[dn], sizeof(struct ax25_addr));
	pkt[14 + (7 * dn)] = 0x03;
	pkt[15 + (7 * dn)] = 0xf0;
	len = 16 + (7 * dn) + strlcpy(&pkt[16 + (7 * dn)], payload, 1024 - 16);
	ax25_output(pkt, len);
}

static int
tnc2_output(char *s, int len)
{
	log_debug("snd: %s", s); /* TODO: ensure this is printable */
	return aprsis_remote_write(s, len);
}

static void *
get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET)
		return &(((struct sockaddr_in*)sa)->sin_addr);
	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

static void
aprsis_login_str(char *login, char *call, char *pass, char *filter)
{
	memset(login, 0, 512);
	strlcpy(login, "user ", 512);
	strlcat(login, call, 512);
	strlcat(login, " pass ", 512);
	strlcat(login, pass, 512);
	strlcat(login, " vers HamBSD-aprsisd 0.0-dev", 512);
	if (filter != NULL) {
		strlcat(login, " filter ", 512);
		strlcat(login, filter, 512);
	}
	strlcat(login, "\n", 512);
}

/*
 * Constructs a filesystem path to the TLS client certificate for a given
 * callsign. The provided buffer must be at least MAXPATHLEN in size.
 */
static char *
aprsis_tls_cert_file(char *buf, char *call)
{
	static char sbuf[MAXPATHLEN];
	if (buf == NULL)
		buf = (char *)sbuf;
	snprintf(buf, MAXPATHLEN, "/etc/ssl/%s.crt", call_strip_ssid(call));
	return buf;
}

/*
 * Constructs a filesystem path to the TLS client key for a given
 * callsign. The provided buffer must be at least MAXPATHLEN in size.
 */
static char *
aprsis_tls_key_file(char *buf, char *call)
{
	static char sbuf[MAXPATHLEN];
	if (buf == NULL)
		buf = (char *)sbuf;
	snprintf(buf, MAXPATHLEN, "/etc/ssl/private/%s.key", call_strip_ssid(call));
	return buf;
}

static int
aprsis_remote_write(char *buf, ssize_t len)
{
	while (len > 0) {
		ssize_t ret;
		if (usetls) {
			ret = tls_write(tls_ctx, buf, len);
			if (ret == TLS_WANT_POLLIN || ret == TLS_WANT_POLLOUT)
				continue;
			if (ret == -1) {
				log_warnx("tls_write: %s", tls_error(tls_ctx));
				return -1;
			}
		} else {
			if (write(tcp, buf, len) == -1) {
				log_warn("write");
				return -1;
			}
		}
		buf += ret;
		len -= ret;
	}
	return 0;
}

static int
aprsis_remote_open(char *server, char *port, char *call, char *pass,
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

		aprsis_tls_cert_file(cert_file, call);
		log_debug("certificate file: %s", cert_file);
		aprsis_tls_key_file(key_file, call);
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
		pass = aprsis_pass(call);

	login = malloc(512);
	aprsis_login_str(login, call, pass, filter);
	aprsis_remote_write(login, strlen(login));
	log_debug("login string sent");

	free(login);

	log_info("connected to %s", as);
	return 0;
}

static void
aprsis_local_open(char *interface, char *lladdr)
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
	memcpy(ifr.ifr_addr.sa_data, ax25_aton(lladdr), AX25_ADDR_LEN);

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
		tnc2_input(buf);
	memmove(buf, &buf[ei], pos - ei);
	pos -= ei;
	return pos;
}

static void
aprsis_loop(void)
{
	struct kevent chlist[2];
	struct kevent evlist[2];
	int evi, kq, l_nr, nev, r_pos, r_nr;
	char r_buf[TNC2_MAXLINE], l_buf[1500], *r_ep;

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
				if ((l_nr = read(tap, l_buf, 1500)) == -1 || l_nr == 0)
					fatal("read tap");
				if (ax25_input(l_buf, l_nr) == -1)
					return;
				bzero(l_buf, 1500);
			} else if (evlist[evi].ident == tcp) {
				log_debug("got a tcp event");
				if (usetls) {
					if (((r_nr = tls_read(tls_ctx, &r_buf[r_pos], TNC2_MAXLINE - r_pos)) == -1)) {
						log_warnx("tls_read: %s", tls_error(tls_ctx));
						return;
					}
				} else {
					if (((r_nr = read(tcp, &r_buf[r_pos], TNC2_MAXLINE - r_pos)) == -1) || r_nr == 0)
						return;
				}
				r_pos += r_nr;
				if ((r_ep = strchr(r_buf, '\n')) != NULL)
					r_pos = aprsis_local_shuffle(r_buf, r_ep, r_pos);
			}
		}
	}
}

int
main(int argc, char **argv)
{
	char *call, ch, *filter, *interface, *pass, *port, *server;
	const char *errstr;
	int debug, verbose;

	debug = 0; /* stay in foreground */
	verbose = 0; /* debug level logging */
	pass = "-1"; /* APRS-IS login passcode */
	filter = NULL; /* APRS-IS filter; see: http://www.aprs-is.net/javAPRSFilter.aspx */
	interface = NULL; /* local axtap interface name */
	server = "rotate.aprs2.net"; /* APRS-IS server hostname */
	port = "14580"; /* APRS-IS server port */
	usetls = 0;


	while ((ch = getopt(argc, argv, "Dvti:p:f:")) != -1) {
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
	if (argc > 1)
		server = argv[1];
	if (argc > 2)
		port = argv[2];

	if (!debug)
		daemonize();

	/* the path for the tap device is unknown until we open it */
	aprsis_local_open(interface, call);
	if (tap == -1)
		fatal("tap open");

	if (usetls) {
		if (unveil("/etc/ssl/hamcert.pem", "r") == -1)
			fatal("unveil");
		if (unveil(aprsis_tls_cert_file(NULL, call_strip_ssid(call)), "r") == -1)
			fatal("unveil");
		if (unveil(aprsis_tls_key_file(NULL, call_strip_ssid(call)), "r") == -1)
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
		while (aprsis_remote_open(server, port, call, pass, filter) == -1) {
			log_warnx("connection failed, reconnecting in 30 seconds...");
			sleep(30);
		}
		aprsis_loop();
		log_warnx("disconnected from server, reconnecting in 30 seconds...");
	}
}
