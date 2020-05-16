
#include <assert.h>
#include <ctype.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <netax25/if_ax25.h>

#include "aprsis.h"
#include "log.h"
#include "tnc2.h"

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
ax25_validate(const struct ax25_addr *a)
{
	int c, i;
	for (i = 0; i < 6; i++)
		/* portability note: on OpenBSD isupper and isdigit
		 * always use the C locale, so this will only match
		 * ascii A-Z and 0-9 but other platforms may use
		 * locales matching more characters. */
		if (!isupper(a->ax25_addr_octet[i] >> 1) &&
		    !isdigit(a->ax25_addr_octet[i] >> 1) &&
		    (a->ax25_addr_octet[i] >> 1) != ' ')
			return 0;
	return 1;
}

size_t
ax25_to_tnc2(unsigned char *pkt_tnc2, const unsigned char *pkt_ax25, const size_t ax25_len) {
	unsigned char *abuf;
	const unsigned char *ibp, *iep;
	int al, ai; /* length and index for address strings */
	int pi; /* current address index in rf header, or byte index in 3rd-party header */
	int empty_path = 0; /* there are no digipeaters in the rf header */
	int tp = 0; /* current length of pkt_tnc2 */

	bzero(pkt_tnc2, TNC2_MAXLINE);

	log_debug("ax25_input: %zu bytes", ax25_len);

	if (!ax25_validate(AX25_ADDR_PTR(pkt_ax25, 1))) {
		log_debug("dropping packet: invalid ax.25 address");
		return 0;
	}
	abuf = ax25_ntoa(AX25_ADDR_PTR(pkt_ax25, 1));
	al = strnlen(abuf, 10);
	if (tp + al + 3 > TNC2_MAXLINE) { /* 3: used hop, path sep, null terminator */
		log_debug("dropping packet: can't fit this address into the TNC2 string");
		return 0;
	}
	for (ai = 0; ai < al; ai++)
		pkt_tnc2[tp++] = abuf[ai];
	pkt_tnc2[tp++] = '>';

	if ((AX25_ADDR_PTR(pkt_ax25, 1)->ax25_addr_octet[6] & AX25_LAST_MASK) != 0) {
		/* The source address was the last address */
		empty_path = 1;
	}

	for (pi = 0;; pi++) {
		if (pi == 1)
			/* We already did the source address above */
			pi++;
		if (pi > AX25_MAX_DIGIS + 1) {
			log_debug("dropping packet: there are more digis in the path than we care to handle");
			return 0;
		}
		if (AX25_ADDR_LEN * (pi + 1) > ax25_len) {
			log_debug("dropping packet: ran out of packet looking for the last address");
			return 0;
		}
		if (pi != 0) {
			/* We're looking at the path now */
			pkt_tnc2[tp++] = ',';
			if (forbidden_gate_path_address(AX25_ADDR_PTR(pkt_ax25, pi)->ax25_addr_octet)) {
				log_debug("dropping packet: a packet was dropped with forbidden entry in path");
				return 0;
			}
		}
		if (!ax25_validate(AX25_ADDR_PTR(pkt_ax25, pi))) {
			log_debug("dropping packet: invalid ax.25 address");
			return 0;
		}
		abuf = ax25_ntoa(AX25_ADDR_PTR(pkt_ax25, pi));
		al = strnlen(abuf, 10);
		if (tp + al + 3 > TNC2_MAXLINE) /* 3 = used hop, path sep, null terminator */
			/* We can't fit this address into the TNC2 string */
			return 0;
		for (ai = 0; ai < al; ai++)
			pkt_tnc2[tp++] = abuf[ai];
		if (pi > 1 && (AX25_ADDR_PTR(pkt_ax25, pi)->ax25_addr_octet[6] & AX25_CR_MASK) != 0)
			/* This hop has been used */
			pkt_tnc2[tp++] = '*';
		if (empty_path) {
			/* There is no path, so we must fix the path index */
			pi++;
			break;
		}
		if ((AX25_ADDR_PTR(pkt_ax25, pi)->ax25_addr_octet[6] & AX25_LAST_MASK) != 0)
			/* This is the last address */
			break;
	}

	if (AX25_CTRL(pkt_ax25, pi) != 0x03 || AX25_PID(pkt_ax25, pi) != 0xf0) {
		log_debug("dropping packet: due to non-APRS control/PID");
		return 0;
	}

	if (strncmp(ax25_ntoa(AX25_ADDR_PTR(pkt_ax25, 1)), call, 10) != 0) {
		/* This packet is not from this station, add a q construct */
		if (tp + al + 6 > TNC2_MAXLINE) /* ",qAR,call:" = 6 + strlen(call) */
			/* We can't fit the q construct into the TNC2 string */
			return 0;
		pkt_tnc2[tp++] = ',';
		pkt_tnc2[tp++] = 'q';
		pkt_tnc2[tp++] = 'A';
		if (bidir)
			pkt_tnc2[tp++] = 'R';
		else
			pkt_tnc2[tp++] = 'O';
		pkt_tnc2[tp++] = ',';
		al = strnlen(call, 10);
		for (ai = 0; ai < al; ai++)
			pkt_tnc2[tp++] = call[ai];
	}

	pkt_tnc2[tp++] = ':';

	/* The absolute maximum that tp can be at this point is 122.
	 * TNC_MAXLINE is above 500 so up until now we didn't have to
	 * perform bounds checking, assuming no bugs in the above
	 * code.
	 *
	 * The largest callsign with SSID will be 9 bytes as an ASCII
	 * string. There is a source address, destination address, and
	 * a maximum of 8 digipeaters. Each digipeater may also be
	 * followed by an asterisk if it's "used", and every address
	 * is followed by a one byte seperator.
	 *
	 *   10 addresses x 9 bytes = 90
	 *   8 digipeaters x 1 byte =  8
	 *   10 addresses x 1 byte  = 10
	 *
	 * Following this path, there is a 3 byte q Construct
	 * (e.g. qAR), a one byte seperator, and another address with
	 * a maximum of 9 bytes. Finally, a single colon marks the end
	 * of the header.
	 *
	 *   3 bytes + 1 byte + 9 bytes + 1 byte = 14
	 *
	 *   90 + 8 + 10 + 14 = 122 absolute maximum
	 */
	assert(tp <= 122);

	/* Now do the information part */
	ibp = AX25_INFO_PTR(pkt_ax25, pi);
	iep = pkt_ax25 + ax25_len;

	/* We truncate packets at the first \r or \n to avoid injection
	 * attacks.
	 * http://lists.tapr.org/pipermail/aprssig_lists.tapr.org/2020-May/048517.html */
	for (pi = 0; pi < (iep - ibp); pi++) {
		if (ibp[pi] == '\r' || ibp[pi] == '\n') {
			log_debug("truncating packet: contained either cr or lf");
			iep = ibp + pi;
		}
	}

	if (iep - ibp == 0) {
		log_debug("dropped packet: zero length information part");
		return 0;
	}

	if (*ibp == '?') {
		/* This is a general query */
		if (iep - ibp >= 7 && memcmp(ibp, "?IGATE?", 7) == 0) {
			log_debug("dropped packet: general igate query, but we'll reply on the local interface");
			return 1;
		}
		log_debug("dropped packet: general query");
		return 0;
	}

	if (*ibp == '}') {
		/* This packet has a 3rd-party header */
		ibp++;
		/* Assuming that callsigns are at least 3 characters, the minimum length
		 * for a header would be 8 bytes, add one byte to have some payload in it
		 * and we'll say drop anything less than 9 bytes. This also covers the
		 * search for TCPIP in the header so we don't need to check again before
		 * that. */
		if (iep - ibp < 9) {
			log_debug("dropped packet: 3rd-party traffic too short");
			return 0;
		}
		for (pi = 0; (pi < iep - ibp) && ibp[pi + 6] != ':'; pi++) {
			if (memcmp(&ibp[pi + 5], ",TCPIP", 6) == 0) {
				log_debug("dropped packet: 3rd-party header contained TCPIP");
				return 0;
			}
		}
		if (pi == iep - ibp) {
			log_debug("dropped packet: 3rd-party traffic contained no colon");
			return 0;
		}
		log_debug("third party header: stripping rf header");
		tp = 0;
		/* TODO: could really do with some more validation here */
	}

	if (tp + (iep - ibp) > TNC2_MAXLINE) {
		log_debug("dropping packet: information part too long");
		return 0;
	}
	memcpy(&pkt_tnc2[tp], ibp, iep - ibp);
	tp += iep - ibp;

	return tp;
}
