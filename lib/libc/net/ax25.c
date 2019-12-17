#include <ctype.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <stdio.h>

#include <sys/types.h>
#include <netax25/if_ax25.h>

/*
 * Convert the network representation of an AX.25 address to a human readable
 * callsign and SSID. This function is not thread safe, as it returns the
 * result in a statically assigned buffer.
 */
char *
ax25_ntoa(struct ax25_addr *axp)
{
	static char buf[10];
	int i, ssid;
	ssid = (axp->ax25_addr_octet[6] & AX25_SSID_MASK) >> 1;
	bzero(buf, 10);
	for (i = 0; i < 6; i++) {
		if (axp->ax25_addr_octet[i] == 0x40)
			break;
		buf[i] = axp->ax25_addr_octet[i] >> 1;
	}
	if (ssid == 0) {
		buf[i] = '\0';
	} else {
		snprintf(&buf[i], 10, "-%d", ssid);
	}
	return buf;
}

/*
 * Convert a human readable callsign and SSID to the network representation of
 * an AX.25 address. This function is not thread safe, as it returns the result
 * in a statically assigned buffer.
 */
struct ax25_addr *
ax25_aton(const char *s)
{
	static struct ax25_addr ax;
	char ssid[3];
	int i;
	memcpy(&ax, "\x40\x40\x40\x40\x40\x40\x00", sizeof(struct ax25_addr));
	for (i = 0; ; i++) {
		if (s[i] == '\0') {
			ax.ax25_addr_octet[6] = 0;
			break;
		}
		if (s[i] == '-') {
			if (isdigit(s[++i])) {
				bzero(ssid, 3);
				ssid[0] = s[i];
				if (isdigit(s[++i]))
					ssid[1] = s[i];
				ax.ax25_addr_octet[6] = atoi(ssid) << 1;
				if ((ax.ax25_addr_octet[6] & ~AX25_SSID_MASK) != 0) {
					/* non AX.25 SSID */
					return NULL;
				}
				break;
			} else {
				/* callsign is malformed */
				return NULL;
			}
		}
		ax.ax25_addr_octet[i] = toupper(s[i]) << 1;
	}
	return &ax;
}

