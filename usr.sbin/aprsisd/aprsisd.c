
#include <ctype.h>
#include <err.h>
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
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <net/if.h>
#include <net/if_tun.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netax25/if_ax25.h>

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

int isd, tap;

static __dead void usage(void);
static void daemonize(void);
static void signal_handler(int sig);
static char *aprsis_pass(char *);
static int ax25_input(char *, int);
static void ax25_output(char *, int);
static char *tnc2_hdr_to_ax25(struct sockaddr_ax25 *, struct sockaddr_ax25 *, char *);
static void tnc2_input(char *);
static int tnc2_output(char *);
static void aprsis_login_str(char *, char *, char *, char *);
static void aprsis_remote_open(char *, char *, char *, char *, char *);
static void aprsis_local_open(char *, char *);
static int aprsis_local_shuffle(char *, char *, int);
static void aprsis_loop(void);
int main(int, char **);

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
		syslog(LOG_DAEMON | LOG_INFO, "caught hangup signal");
		break;
	case SIGTERM:
		syslog(LOG_DAEMON | LOG_WARNING, "caught terminate signal, shutting down");
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
aprsis_pass(char *call)
{
	static char pass[6];
	char *cp, *ep;
	int16_t hash;

	cp = call;
	if ((ep = strchr(call, '-')) == NULL)
		ep = cp + strlen(call);
	hash = 0x73e2;
	while (cp < ep) {
		hash ^= (toupper(*(cp++)) << 8);
		if (cp < ep)
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


int
forbidden_gate_path_address(caddr_t pa)
{
	int i;
	for (i = 0 ;; i++) {
		if (aprsis_forbidden_gate_addresses[i] == NULL)
			break;
		if (memcmp(pa, aprsis_forbidden_gate_addresses[i], 6) == 0)
			return 0;
	}
	/* TODO: q constructs? */
	return 1;
}

/*
 * TODO: things get really messed up if the packet buf isn't null terminated!!!!
 */
static int
ax25_input(char *pkt, int len)
{
	char dst[10], src[10], tl[TNC2_MAXLINE];
	int dn;
	strlcpy(dst, ax25_ntoa((struct ax25_addr *)&pkt[0]), 10);
	strlcpy(src, ax25_ntoa((struct ax25_addr *)&pkt[7]), 10);
	snprintf(tl, TNC2_MAXLINE, "%s>%s", src, dst);
	for (dn = 0; dn < AX25_MAX_DIGIS; ++dn) {
		if (forbidden_gate_path_address(&pkt[7 * (dn + 1)]))
			return 0;
		if (pkt[(7 * (dn + 1)) + 6] & AX25_LAST_MASK)
			break;
		strlcat(tl, ",", TNC2_MAXLINE);
		strlcat(tl, ax25_ntoa((struct ax25_addr *)&pkt[7 * (dn + 2)]), TNC2_MAXLINE);
	}
	strlcat(tl, ":", TNC2_MAXLINE);
	strlcat(tl, &pkt[7 * (dn + 2) + 2], TNC2_MAXLINE);
	strlcat(tl, "\n", TNC2_MAXLINE);
	return tnc2_output(tl);
}

static void
ax25_output(char *pkt, int len)
{
	if (write(tap, pkt, len) == -1)
		err(1, "ax25_output: write");
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
tnc2_output(char *s)
{
	int len = strlen(s);
	printf("snd: %s", s);
	return write(isd, s, len);
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

static void
aprsis_remote_open(char *server, char *port, char *call, char *pass,
    char *filter)
{
	struct addrinfo hints, *servinfo, *p;
	int nodelay, rv;
	char *login, as[INET6_ADDRSTRLEN];

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ((rv = getaddrinfo(server, port, &hints, &servinfo)) != 0) {
		syslog(LOG_DAEMON | LOG_ERR, "getaddrinfo: %s\n", gai_strerror(rv));
		return;
	}

	for (p = servinfo; p != NULL; p = p->ai_next) {
		if ((isd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
			syslog(LOG_DAEMON | LOG_WARNING, "socket: %m");
			continue;
		}
		if (connect(isd, p->ai_addr, p->ai_addrlen) == -1) {
			close(isd);
			syslog(LOG_DAEMON | LOG_WARNING, "connect: %m");
			continue;
		}
		break;
	}

	if (p == NULL)
		err(1, "connect");

	nodelay = 1;
	setsockopt(isd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));

	inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr), as, sizeof(as));
	syslog(LOG_DAEMON | LOG_INFO, "connected to %s", as);

	freeaddrinfo(servinfo);

	if (strcmp(pass, "please") == 0)
		pass = aprsis_pass(call);
	login = malloc(512);
	aprsis_login_str(login, call, pass, filter);
	if (write(isd, login, strlen(login)) == -1)
		err(1, "write");

	free(login);

	syslog(LOG_INFO | LOG_DAEMON, "connected to %s", as);
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
			err(1, "interface name too short");
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
		err(1, "SIOCSIFLLADDR");
	
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
	printf("rcv: %s\n", buf);
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
		err(1, "kqueue");

	EV_SET(&chlist[0], isd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, 0);
	EV_SET(&chlist[1], tap, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, 0);

	while ((nev = kevent(kq, chlist, 2, evlist, 2, NULL)) > 0) {
		for (evi = 0; evi < nev; evi++) {
			if (evlist[evi].ident == tap) {
				if ((l_nr = read(tap, l_buf, 1500)) == -1 || l_nr == 0)
					err(1, "read tap");
				if (ax25_input(l_buf, l_nr) == -1)
					return;
				bzero(l_buf, 1500);
			} else if (evlist[evi].ident == isd) {
				if (((r_nr = read(isd, &r_buf[r_pos], TNC2_MAXLINE - r_pos)) == -1) || r_nr == 0) {
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
	int daemon;

	daemon = 1;
	pass = "-1";
	filter = NULL;
	interface = NULL;
	server = "rotate.aprs2.net";
	port = "14580";

	while ((ch = getopt(argc, argv, "Di:p:f:")) != -1) {
		switch (ch) {
		case 'D':
			daemon = 0;
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
	call = argv[0];
	if (argc > 1)
		server = argv[1];
	if (argc > 2)
		port = argv[2];

	aprsis_local_open(interface, call);
	if (tap == -1)
		err(1, "tap open");

	if (daemon)
		daemonize();

	if (unveil(NULL, NULL) == -1)
		err(1, "unveil");
	if (pledge("stdio inet rpath dns", NULL) == -1)
		err(1, "pledge");

	for (;;) {
		aprsis_remote_open(server, port, call, pass, filter);
		aprsis_loop();
		syslog(LOG_DAEMON | LOG_INFO, "reconnecting in 30 seconds...");
		sleep(30);
	}
}
