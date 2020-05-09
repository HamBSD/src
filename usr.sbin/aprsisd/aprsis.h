
extern char *call;
extern unsigned char *ncall;
extern int bidir;

/* "No line may exceed 512 bytes including the CR/LF sequence."
 * The CR/LF will be sent by tnc2_output so we use 509 for bounds
 * checking while building up the TNC2 format string, leaving room
 * for CR/LF. */
#define TNC2_MAXLINE 510

