
extern char *call;
extern unsigned char *ncall;
extern int bidir;

/* "No line may exceed 512 bytes including the CR/LF sequence."
 * The CR/LF will be sent by tnc2_output so we use 509 for bounds
 * checking while building up the TNC2 format string, leaving room
 * for CR/LF. */
#define TNC2_MAXLINE 510

/* The following macros provide pointers to structures inside
 * AX.25 packets:
 *  p is the pointer to the start of the packet
 *  n is the number of digipeater hops plus 2 */
#define AX25_ADDR_PTR(p, n)	 ((struct ax25_addr *)(&p[AX25_ADDR_LEN * n]))
#define AX25_CTRL(p, n)		 (p[(AX25_ADDR_LEN * (n + 1))])
#define AX25_PID(p, n)		 (p[(AX25_ADDR_LEN * (n + 1)) + 1])
#define AX25_INFO_PTR(p, n)	 (&p[(AX25_ADDR_LEN * (n + 1)) + 2])

struct sockaddr_ax25 {
	u_int8_t		sax_len;
	sa_family_t		sax_family;
	struct ax25_addr	sax_addr;
	int8_t			sax_pathlen;
	struct ax25_addr	sax_path[AX25_MAX_DIGIS];
};

