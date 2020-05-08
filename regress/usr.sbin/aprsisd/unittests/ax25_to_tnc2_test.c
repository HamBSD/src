/*	$OpenBSD: rde_sets_test.c,v 1.7 2019/12/17 11:57:16 claudio Exp $ */

/*
 * Copyright (c) 2020 Iain R. Learmonth <irl@hambsd.org>
 * Copyright (c) 2018 Claudio Jeker <claudio@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include <sys/types.h>
#include <sys/socket.h>

#include <netax25/if_ax25.h>

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aprsis.h"
#include "tnc2.h"

int bidir;
char *call = "MB7UAR-2";

char *log_message;

void
log_debug(char *msg)
{
	log_message = msg;
}

const unsigned char good[] = {
	'A' << 1, 'P' << 1, 'B' << 1, 'S' << 1, 'D' << 1, 'I' << 1, 0x00,	// To APBSDI
	'M' << 1, 'M' << 1, '0' << 1, 'R' << 1, 'O' << 1, 'R' << 1, 14 << 1,	// From MM0ROR-14
	'M' << 1, 'B' << 1, '7' << 1, 'V' << 1, 'X' << 1, ' ' << 1, AX25_CR_MASK,	// Via MB7VX (used)
	'W' << 1, 'I' << 1, 'D' << 1, 'E' << 1, '1' << 1, ' ' << 1, (1 << 1) | AX25_LAST_MASK,	// Via WIDE1-1 (last)
	0x03, 0xf0,								// APRS packet
	'>', 'P', 'a', 'c', 'k', 'e', 't', ' ', 'r', 'a', 'd', 'i', 'o',	// Status: Packet radio
	0xff
};
const unsigned char good_tnc2_rxonly[] = "MM0ROR-14>APBSDI,MB7VX*,WIDE1-1,qAO,MB7UAR-2:>Packet radio";
const unsigned char good_tnc2_bidir[] =  "MM0ROR-14>APBSDI,MB7VX*,WIDE1-1,qAR,MB7UAR-2:>Packet radio";

const unsigned char nogate_1_used_in_path[] = {
	'A' << 1, 'P' << 1, 'B' << 1, 'S' << 1, 'D' << 1, 'I' << 1, 0x00,	// To APBSDI
	'M' << 1, 'M' << 1, '0' << 1, 'R' << 1, 'O' << 1, 'R' << 1, 14 << 1,	// From MM0ROR-14
	'N' << 1, 'O' << 1, 'G' << 1, 'A' << 1, 'T' << 1, 'E' << 1, (1 << 1) | AX25_CR_MASK,	// Via NOGATE-1 (used)
	'W' << 1, 'I' << 1, 'D' << 1, 'E' << 1, '1' << 1, ' ' << 1, (1 << 1) | AX25_LAST_MASK,	// Via WIDE1-1 (last)
	0x03, 0xf0,								// APRS packet
	'>', 'P', 'a', 'c', 'k', 'e', 't', ' ', 'r', 'a', 'd', 'i', 'o',	// Status: Packet radio
	0xff
};

const unsigned char tcpip_in_path[] = {
	'A' << 1, 'P' << 1, 'B' << 1, 'S' << 1, 'D' << 1, 'I' << 1, 0x00,	// To APBSDI
	'M' << 1, 'M' << 1, '0' << 1, 'R' << 1, 'O' << 1, 'R' << 1, 14 << 1,	// From MM0ROR-14
	'W' << 1, 'I' << 1, 'D' << 1, 'E' << 1, '1' << 1, ' ' << 1, 1 << 1,	// Via WIDE1-1
	'T' << 1, 'C' << 1, 'P' << 1, 'I' << 1, 'P' << 1, ' ' << 1, AX25_LAST_MASK,	// Via TCPIP (last)
	0x03, 0xf0,								// APRS packet
	'>', 'P', 'a', 'c', 'k', 'e', 't', ' ', 'r', 'a', 'd', 'i', 'o',	// Status: Packet radio
	0xff
};

const unsigned char max_digis[] = {
	'A' << 1, 'P' << 1, 'B' << 1, 'S' << 1, 'D' << 1, 'I' << 1, 0x00,	// To APBSDI
	'M' << 1, 'M' << 1, '0' << 1, 'R' << 1, 'O' << 1, 'R' << 1, 14 << 1,	// From MM0ROR-14
	'W' << 1, 'I' << 1, 'D' << 1, 'E' << 1, '1' << 1, ' ' << 1, 1 << 1,	// Via WIDE1-1
	'W' << 1, 'I' << 1, 'D' << 1, 'E' << 1, '2' << 1, ' ' << 1, 1 << 1,	// Via WIDE2-1
	'W' << 1, 'I' << 1, 'D' << 1, 'E' << 1, '3' << 1, ' ' << 1, 1 << 1,	// Via WIDE3-1
	'W' << 1, 'I' << 1, 'D' << 1, 'E' << 1, '4' << 1, ' ' << 1, 1 << 1,	// Via WIDE4-1
	'W' << 1, 'I' << 1, 'D' << 1, 'E' << 1, '5' << 1, ' ' << 1, 1 << 1,	// Via WIDE5-1
	'W' << 1, 'I' << 1, 'D' << 1, 'E' << 1, '6' << 1, ' ' << 1, 1 << 1,	// Via WIDE6-1
	'W' << 1, 'I' << 1, 'D' << 1, 'E' << 1, '7' << 1, ' ' << 1, 1 << 1,	// Via WIDE7-1
	'W' << 1, 'I' << 1, 'D' << 1, 'E' << 1, '8' << 1, ' ' << 1, (1 << 1) | AX25_LAST_MASK,	// Via WIDE8-1 (last)
	0x03, 0xf0,								// APRS packet
	'>', 'P', 'a', 'c', 'k', 'e', 't', ' ', 'r', 'a', 'd', 'i', 'o',	// Status: Packet radio
	0xff
};

const unsigned char max_digis_tnc2[] = "MM0ROR-14>APBSDI,WIDE1-1,WIDE2-1,WIDE3-1,WIDE4-1,WIDE5-1,WIDE6-1,WIDE7-1,WIDE8-1,qAO,MB7UAR-2:>Packet radio";

const unsigned char too_many_digis[] = {
	'A' << 1, 'P' << 1, 'B' << 1, 'S' << 1, 'D' << 1, 'I' << 1, 0x00,	// To APBSDI
	'M' << 1, 'M' << 1, '0' << 1, 'R' << 1, 'O' << 1, 'R' << 1, 14 << 1,	// From MM0ROR-14
	'W' << 1, 'I' << 1, 'D' << 1, 'E' << 1, '1' << 1, ' ' << 1, 1 << 1,	// Via WIDE1-1
	'W' << 1, 'I' << 1, 'D' << 1, 'E' << 1, '2' << 1, ' ' << 1, 1 << 1,	// Via WIDE2-1
	'W' << 1, 'I' << 1, 'D' << 1, 'E' << 1, '3' << 1, ' ' << 1, 1 << 1,	// Via WIDE3-1
	'W' << 1, 'I' << 1, 'D' << 1, 'E' << 1, '4' << 1, ' ' << 1, 1 << 1,	// Via WIDE4-1
	'W' << 1, 'I' << 1, 'D' << 1, 'E' << 1, '5' << 1, ' ' << 1, 1 << 1,	// Via WIDE5-1
	'W' << 1, 'I' << 1, 'D' << 1, 'E' << 1, '6' << 1, ' ' << 1, 1 << 1,	// Via WIDE6-1
	'W' << 1, 'I' << 1, 'D' << 1, 'E' << 1, '7' << 1, ' ' << 1, 1 << 1,	// Via WIDE7-1
	'W' << 1, 'I' << 1, 'D' << 1, 'E' << 1, '8' << 1, ' ' << 1, 1 << 1,	// Via WIDE8-1
	'W' << 1, 'I' << 1, 'D' << 1, 'E' << 1, '9' << 1, ' ' << 1, (1 << 1) | AX25_LAST_MASK,	// Via WIDE9-1 (last)
	0x03, 0xf0,								// APRS packet
	'>', 'P', 'a', 'c', 'k', 'e', 't', ' ', 'r', 'a', 'd', 'i', 'o',	// Status: Packet radio
	0xff
};

const unsigned char truncated[] = {
	'A' << 1, 'P' << 1, 'B' << 1, 'S' << 1, 'D' << 1, 'I' << 1, 0x00,	// To APBSDI
	'M' << 1, 'M' << 1, '0' << 1, 'R' << 1, 'O' << 1, 'R' << 1, 14 << 1,	// From MM0ROR-14
	'W' << 1, 'I' << 1, 'D' << 1, 'E' << 1, '1' << 1, ' ' << 1, 1 << 1,	// Via WIDE1-1
	0xff
};

const unsigned char not_aprs_control[] = {
	'A' << 1, 'P' << 1, 'B' << 1, 'S' << 1, 'D' << 1, 'I' << 1, 0x00,	// To APBSDI
	'M' << 1, 'M' << 1, '0' << 1, 'R' << 1, 'O' << 1, 'R' << 1, 14 << 1,	// From MM0ROR-14
	'M' << 1, 'B' << 1, '7' << 1, 'V' << 1, 'X' << 1, ' ' << 1, AX25_CR_MASK,	// Via MB7VX (used)
	'W' << 1, 'I' << 1, 'D' << 1, 'E' << 1, '1' << 1, ' ' << 1, (1 << 1) | AX25_LAST_MASK,	// Via WIDE1-1 (last)
	0x01, 0xf0,								// Not APRS control
	'>', 'P', 'a', 'c', 'k', 'e', 't', ' ', 'r', 'a', 'd', 'i', 'o',	// Status: Packet radio
	0xff
};

const unsigned char not_aprs_pid[] = {
	'A' << 1, 'P' << 1, 'B' << 1, 'S' << 1, 'D' << 1, 'I' << 1, 0x00,	// To APBSDI
	'M' << 1, 'M' << 1, '0' << 1, 'R' << 1, 'O' << 1, 'R' << 1, 14 << 1,	// From MM0ROR-14
	'M' << 1, 'B' << 1, '7' << 1, 'V' << 1, 'X' << 1, ' ' << 1, AX25_CR_MASK,	// Via MB7VX (used)
	'W' << 1, 'I' << 1, 'D' << 1, 'E' << 1, '1' << 1, ' ' << 1, (1 << 1) | AX25_LAST_MASK,	// Via WIDE1-1 (last)
	0x03, 0xf1,								// Not APRS PID
	'>', 'P', 'a', 'c', 'k', 'e', 't', ' ', 'r', 'a', 'd', 'i', 'o',	// Status: Packet radio
	0xff
};

const unsigned char no_information[] = {
	'A' << 1, 'P' << 1, 'B' << 1, 'S' << 1, 'D' << 1, 'I' << 1, 0x00,	// To APBSDI
	'M' << 1, 'M' << 1, '0' << 1, 'R' << 1, 'O' << 1, 'R' << 1, (14 << 1) | AX25_LAST_MASK,	// From MM0ROR-14
	0x03, 0xf0,								// APRS packet
	0xff
};

const unsigned char third_party[] = {
	'A' << 1, 'P' << 1, 'B' << 1, 'S' << 1, 'D' << 1, 'I' << 1, 0x00,	// To APBSDI
	'M' << 1, 'M' << 1, '0' << 1, 'R' << 1, 'O' << 1, 'R' << 1, (14 << 1) | AX25_LAST_MASK,	// From MM0ROR-14
	0x03, 0xf0,								// APRS packet
	'}', 'M', 'M', '0', 'Y', 'S', 'O', '>', 'A', 'P', 'R', 'S', ',',	// Third party data: MM0YSO>APRS,
	'L', 'O', 'R', 'A', '*', ':', 'H', 'e', 'l', 'l', 'o',			// LORA*:Hello
	0xff
};

const unsigned char third_party_tnc2[] = "MM0YSO>APRS,LORA*:Hello";

const unsigned char comment_injection_attack[] = {
	'A' << 1, 'P' << 1, 'B' << 1, 'S' << 1, 'D' << 1, 'I' << 1, 0x00,	// To APBSDI
	'M' << 1, 'M' << 1, '0' << 1, 'R' << 1, 'O' << 1, 'R' << 1, (14 << 1) | AX25_LAST_MASK,	// From MM0ROR-14
	0x03, 0xf0,								// APRS packet
	'>', 'P', 'a', 'c', 'k', 'e', 't', ' ', 'r', 'a', 'd', 'i', 'o',	// Status: Packet radio
	'\r', '#', 'f', 'i', 'l', 't', 'e', 'r', ' ', 'm', '/', '1',		// \r#filter m/1
	0xff
};

const unsigned char comment_injection_attack_tnc2[] = "MM0ROR-14>APBSDI,qAO,MB7UAR-2:>Packet radio";

void
test_for_drop(const char *name, const unsigned char *pkt_ax25, const char* expected_log)
{
	int len_ax25, len_tnc2;
	unsigned char pkt_tnc2[TNC2_MAXLINE];
	for (len_ax25 = 0; pkt_ax25[len_ax25] != 0xff; ++len_ax25);
	len_tnc2 = ax25_to_tnc2(pkt_tnc2, pkt_ax25, len_ax25);

	if (len_tnc2 != 0) {
		pkt_tnc2[len_tnc2] = '\0';
		printf("produced: %s\n", pkt_tnc2);
		errx(1, "%s should have been dropped but wasn't", name);
	}
	if (strcmp(log_message, expected_log) != 0) {
		errx(1,
		    "%s was not converted as expected\nexpected:%s\ngot:%s",
		    name, expected_log, log_message);
	}
}

void
test_convert(const char *name, const unsigned char *pkt_ax25, const char* expected)
{
	int len_ax25, len_tnc2;
	unsigned char pkt_tnc2[TNC2_MAXLINE];
	for (len_ax25 = 0; pkt_ax25[len_ax25] != 0xff; ++len_ax25);
	len_tnc2 = ax25_to_tnc2(pkt_tnc2, pkt_ax25, len_ax25);

	if (len_tnc2 == 0)
		errx(1, "%s was unexpectedly dropped: %s", name, log_message);
	if (strlen(expected) != len_tnc2 || memcmp(pkt_tnc2, expected, len_tnc2) != 0) {
		pkt_tnc2[len_tnc2] = '\0';
		errx(1,
		    "%s was dropped but for the wrong reason\nexpected:%s|\n     got:%s|",
		    name, expected, pkt_tnc2);
	}
}

int
main(int argc, char **argv)
{
	/* Test a good packet, which should get a qAO construct as a receive-only IGate. */
	bidir = 0;
	test_convert("RXGOOD", good, good_tnc2_rxonly);

	/* Test a good packet, which should get a qAR construct as a receive-only IGate. */
	bidir = 1;
	test_convert("BIGOOD", good, good_tnc2_bidir);

	/* Test that a packet with NOGATE-1 (used) in its path gets dropped */
	test_for_drop("NOGATE-1*", nogate_1_used_in_path,
	    "dropping packet: a packet was dropped with forbidden entry in path");

	/* Test that a packet with TCPIP in its path gets dropped */
	test_for_drop("TCPIP", tcpip_in_path,
	    "dropping packet: a packet was dropped with forbidden entry in path");

	/* Test 8 digis in path. */
	bidir = 0;
	test_convert("WIDE8-1", max_digis, max_digis_tnc2);

	/* Test that a packet with 9 digipeaters in its path gets dropped */
	test_for_drop("WIDE9-1", too_many_digis,
	    "dropping packet: there are more digis in the path than we care to handle");

	/* Test that a truncated packet with incomplete header gets dropped */
	test_for_drop("TRUNC", truncated,
	    "dropping packet: ran out of packet looking for the last address");

	/* Test that a packet with bad control value gets dropped */
	test_for_drop("BADCTL", not_aprs_control,
	    "dropping packet: due to non-APRS control/PID");

	/* Test that a packet with bad control value gets dropped */
	test_for_drop("BADPID", not_aprs_pid,
	    "dropping packet: due to non-APRS control/PID");

	/* Test that a packet with no information part is dropped */
	test_for_drop("NOINFO", no_information, "dropped packet: zero length information part");

	/* Test that a 3rd party header is stripped (doesn't include q construct yet, should break in future) */
	test_convert("3RDPARTY", third_party, third_party_tnc2);

	/* TODO: Test that a 3rd party header with TCPIP (or other forbidden value) in the path is dropped */

	/* TODO: Test that generic queries are dropped */

	/* TODO: Test that an IGATE query generates a response */

	/* TODO: Test that a maximum length header is OK */

	/* TODO: Test that a maxmimum length packet is OK */

	/* TODO: Test that a too long packet is dropped */

	/* Test that a status report containing a comment injection attack is truncated */
	test_convert("INJECT", comment_injection_attack, comment_injection_attack_tnc2);

	printf("OK\n");
	return 0;
}
