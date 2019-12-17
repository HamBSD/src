
#include <err.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <termios.h>
#include <unistd.h>
#include <util.h>
#include <vis.h>

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include "log.h"

static __dead void
usage(void)
{
	extern char *__progname;

	fprintf(stderr, "usage: %s [-D] [-T] server [port]\n", __progname);
	exit(1);
}

static void
signal_handler(int sig)
{
	switch (sig) {
	case SIGTERM:
		errx(1, "caught terminate signal");
		exit(0);
		break;
	}
}

static void
daemonize(void)
{
	daemon(0, 0);
	signal(SIGCHLD, SIG_IGN); /* ignore child */
	signal(SIGTSTP, SIG_IGN); /* ignore tty signals */
	signal(SIGTTOU, SIG_IGN);
	signal(SIGTTIN, SIG_IGN);
	signal(SIGHUP, signal_handler); /* catch hangup signal */
	signal(SIGTERM, signal_handler); /* catch kill signal */
}

static void
rkiss_loop(int lfd, int rfd, int debug)
{
	int evi, kq, nev, nr;
	struct kevent chlist[2];
	struct kevent evlist[2];
	char buffer[1000], vpkt[4001];

	if ((kq = kqueue()) == -1)
		fatal("kqueue");

	EV_SET(&chlist[0], lfd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, 0);
	EV_SET(&chlist[1], rfd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, 0);

	while ((nev = kevent(kq, chlist, 2, evlist, 2, NULL)) > 0) {
		for (evi = 0; evi < nev; evi++) {
			nr = read(evlist[evi].ident, buffer, 1000);
			if (evlist[evi].ident == lfd) {
				if (debug) {
					strvisx(vpkt, buffer, nr, 0);
					log_debug("data arrived from host: %s", vpkt);
				}
				write(rfd, buffer, nr);
			} else {
				if (nr == 0) {
					return;
				} else {
					if (debug) {
						strvisx(vpkt, buffer, nr, 0);
						log_debug("data arrived from tnc: %s", vpkt);
					}
					write(lfd, buffer, nr);
				}
			}
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

static int
rkiss_tcp_open(char *server, char *port) {
	struct addrinfo hints, *servinfo, *p;
	int optval, rfd, rv;
	char *login, as[INET6_ADDRSTRLEN];

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ((rv = getaddrinfo(server, port, &hints, &servinfo)) != 0)
		errx(1, "getaddrinfo: %s\n", gai_strerror(rv));

	for (p = servinfo; p != NULL; p = p->ai_next) {
		if ((rfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
			log_warn("socket");
			continue;
		}
		if (connect(rfd, p->ai_addr, p->ai_addrlen) == -1) {
			log_warn("connect");
			continue;
		}
		break;
	}

	if (p == NULL)
		return -1;

	optval = 1;
	if ((setsockopt(rfd, IPPROTO_TCP, TCP_NODELAY, &optval, sizeof(optval))) == -1) {
		log_warn("setsockopt nodelay");
		if ((close(rfd)) == -1)
			log_warn("close");
		return -1;
	}
	optval = 1;
	if ((setsockopt(rfd, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval))) == -1) {
		log_warn("setsockopt keepalive");
		if ((close(rfd)) == -1)
			log_warn("close");
		return -1;
	}

	inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr), as, sizeof(as));

	freeaddrinfo(servinfo);

	return rfd;
}

static int rkiss_pty_open(void) {
	struct termios tty;
	int ldisc, mfd, sfd;
	char name[16];

	if (openpty(&mfd, &sfd, name, NULL, NULL) == -1)
		fatal("openpty");
	log_info("pty is %s", name);
	if (fcntl(mfd, F_SETFL, O_NONBLOCK) < 0)
		fatal("ptym: fcntl");
	if (fcntl(sfd, F_SETFL, O_NONBLOCK) < 0)
		fatal("ptys: fcntl");
	if ((tcgetattr(sfd, &tty)) == -1)
		fatal("tcgetattr");
	cfmakeraw(&tty);
	if (tcsetattr(sfd, TCSANOW, &tty) == -1)
		fatal("tcsetattr");
	ldisc = KISSDISC;
	if (ioctl(sfd, TIOCSETD, &ldisc) == -1)
		fatal("tiocsetd");
	return mfd;
}

int
main(int argc, char *argv[])
{
	int daemon, debug, lfd, mode, rfd;
	char ch, *server, *port;

	daemon = 1;
	debug = 0;
	mode = 0;
	port = "8001";

	while ((ch = getopt(argc, argv, "dDT")) != -1) {
		switch (ch) {
		case 'D':
			daemon = 0;
			debug = 1;
			break;
		case 'T':
			mode = 0; /* TCP */
			break;
		default:
			usage();
			/* NOTREACHED */
		}
	}
	argc -= optind;
	argv += optind;

	log_init(debug, LOG_DAEMON);

	switch (argc) {
	case 2:
		port = argv[1];
		/* FALLTHROUGH */
	case 1:
		server = argv[0];
		break;
	default:
		usage();
	}

	if (daemon)
		daemonize();

	log_info("startup");

	lfd = rkiss_pty_open();

	pledge("stdio inet dns", NULL);

	for (;;) {
		if ((rfd = rkiss_tcp_open(server, port)) == -1)
			log_warnx("unable to connect to tnc");
		else
			rkiss_loop(lfd, rfd, debug);
		sleep(30);
	}
}
