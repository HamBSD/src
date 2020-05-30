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

#include <err.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "aprs.h"

void
test_convert(const char *name, const struct aprs_object *ao, const unsigned char* expected)
{
	int len_info;
	unsigned char info[256];

	len_info = aprs_compose_pos_info(info, ao);

	if (memcmp(info, expected, len_info) != 0) {
		info[len_info] = '\0';
		errx(1,
		    "%s was not converted as expected\nexpected:%s|\n     got:%s|",
		    name, expected, info);
	}
}

int
main(int argc, char **argv)
{
	struct aprs_object ao;

	aprs_obj_init(&ao);
	aprs_obj_item(&ao, 1); /* No timestamp */
	aprs_obj_comment(&ao, "Test 001234");
	aprs_obj_pos(&ao, 49058334, -72029167, 0);
	aprs_obj_sym(&ao, "/-");
	test_convert("POSTEST", &ao, "!4903.50N/07201.75W-Test 001234");

	aprs_obj_init(&ao);
	aprs_obj_item(&ao, 1); /* No timestamp */
	aprs_obj_comment(&ao, "Test /A=001234");
	aprs_obj_pos(&ao, 49058334, -72029167, 0);
	aprs_obj_sym(&ao, "/-");
	test_convert("POSALT", &ao, "!4903.50N/07201.75W-Test /A=001234");

	aprs_obj_init(&ao);
	aprs_obj_item(&ao, 1); /* No timestamp */
	aprs_obj_pos(&ao, 49058334, -72029167, 4);
	aprs_obj_sym(&ao, "/-");
	test_convert("POSAMB", &ao, "!49  .  N/072  .  W-");

	aprs_obj_init(&ao);
	aprs_obj_pos(&ao, 49058334, -72029167, 0);
	aprs_obj_sym(&ao, "/>");
	aprs_obj_comment(&ao, "Test1234");
	aprs_obj_timestamp(&ao, 776700);
	test_convert("POT", &ao, "/092345z4903.50N/07201.75W>Test1234");

	printf("OK\n");
	return 0;
}
