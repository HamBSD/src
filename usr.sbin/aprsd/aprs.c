/*
 * aprsd - automatic packet reporting system daemon
 *
 * Written by Iain R. Learmonth <irl@fsfe.org> for the public domain.
 */

#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "aprs.h"

static char 	*aprs_lat_ntoa(const long long, int amb);
static char 	*aprs_lon_ntoa(const long long, int amb);

int
aprs_obj_init(struct aprs_object *ao)
{
	memset(ao, 0x00, sizeof(*ao));
	return 0;
}

int
aprs_obj_comment(struct aprs_object *ao, const char *comment)
{
	int i;
	for (i = 0; i < 254; i++) {
		if (isprint(comment[i])) {
			ao->ao_comment[i] = comment[i];
		} else if (comment[i] == '\0') {
			ao->ao_comment[i] = '\0';
			return 0;
		} else {
			return -1;
		}
	}
	return -1;
}

int
aprs_obj_name(struct aprs_object *ao, const char *name)
{
	int i;
	for (i = 0; i < 10; i++) {
		if (isprint(name[i])) {
			ao->ao_name[i] = name[i];
		} else if (name[i] == '\0') {
			ao->ao_name[i] = '\0';
			break;
		} else {
			return -1;
		}
	}
	return 0;
}

int
aprs_obj_pos(struct aprs_object *ao, const long long lat, const long long lon, int amb)
{
	if (lat >= -90000000 && lat <= 90000000 &&
	    lon >= -180000000 && lon <= 180000000 &&
	    amb >= 0 && amb <= 4) {
		ao->ao_lat = lat;
		ao->ao_lon = lon;
		ao->ao_posamb = amb;
		return 0;
	} else {
		return -1;
	}
}

int
aprs_obj_sym(struct aprs_object *ao, const char *symbol)
{
	int i;
	for (i = 0; i < 2; i++) {
		if (isprint(symbol[i])) {
			ao->ao_symbol[i] = symbol[i];
		} else {
			return -1;
		}
	}
	return 0;
}

void
aprs_obj_item(struct aprs_object *ao, int item)
{
	if (item)
		ao->ao_flags |= OBJECTF_ITEM;
	else
		ao->ao_flags &= ~OBJECTF_ITEM;
}

void
aprs_obj_dead(struct aprs_object *ao, int dead)
{
	if (dead)
		ao->ao_flags |= OBJECTF_DEAD;
	else
		ao->ao_flags &= ~OBJECTF_DEAD;
}

int
aprs_obj_timestamp(struct aprs_object *ao, time_t ts)
{
	ao->ao_timestamp.tv_sec = ts;
	return 0;
}

static char *
aprs_lat_ntoa(const long long udeg, int amb)
{
	static char buf[9];
	long long u;
	long deg, rem, umnt, mnt, dmt;
	int north;
	if (udeg < 0) {
		u = udeg * -1;
		north = 0;
	} else {
		u = udeg;
		north = 1;
	}
	deg = u / 1000000;
	snprintf(buf, 3, "%02ld", deg);
	umnt = u % 1000000 * 60;
	mnt = umnt / 1000000;
	snprintf(&buf[2], 3, "%02ld", mnt);
	buf[4] = '.';
	dmt = umnt % 1000000;
	snprintf(&buf[5], 3, "%02ld", dmt);
	if (amb > 0) buf[6] = ' ';
	if (amb > 1) buf[5] = ' ';
	if (amb > 2) buf[3] = ' ';
	if (amb > 3) buf[2] = ' ';
	if (north) {
		buf[7] = 'N';
	} else {
		buf[7] = 'S';
	}
	buf[8] = '\0';
	return buf;
}

static char *
aprs_lon_ntoa(const long long udeg, int amb)
{
	static char buf[10];
	long long u;
	long deg, rem, umnt, mnt, dmt;
	int east;
	if (udeg < 0) {
		u = udeg * -1;
		east = 0;
	} else {
		u = udeg;
		east = 1;
	}
	deg = u / 1000000;
	snprintf(buf, 4, "%03ld", deg);
	umnt = u % 1000000 * 60;
	mnt = umnt / 1000000;
	snprintf(&buf[3], 3, "%02ld", mnt);
	buf[5] = '.';
	dmt = umnt % 1000000;
	snprintf(&buf[6], 3, "%02ld", dmt);
	if (amb > 0) buf[7] = ' ';
	if (amb > 1) buf[6] = ' ';
	if (amb > 2) buf[4] = ' ';
	if (amb > 3) buf[3] = ' ';
	if (east) {
		buf[8] = 'E';
	} else {
		buf[8] = 'W';
	}
	buf[9] = '\0';
	return buf;
}

ssize_t
aprs_compose_base_report(char *buf, const struct aprs_object *ao)
{
	char *lat, *lon;
	ssize_t len_base;

	lat = aprs_lat_ntoa(ao->ao_lat, ao->ao_posamb);
	lon = aprs_lon_ntoa(ao->ao_lon, ao->ao_posamb);

	/*************************************************
	 * Base Report
	 *************************************************
	 * Field 		Size (Bytes) 	Example Data
	 * Latitude 	8 		5709.88N
	 * Symbol Table 	1 		/
	 * Longitude 	9 		00209.67W
	 * Symbol Code 	1 		*
	 * Data Extension 	0 or 7 		088/036
	 * Comment	 	0 or more 	Hello
	 *************************************************
	 */

	memcpy(&buf[0], lat, 8);
	buf[8] = ao->ao_symbol[0];
	memcpy(&buf[9], lon, 9);
	buf[18] = ao->ao_symbol[1];
	/* TODO: Data extensions */
	strlcpy(&buf[19], ao->ao_comment, 128);
	return 19 + strlen(ao->ao_comment);
}

/*
 * Composes an APRS position report information field. The length of the
 * composed information data is returned. The provided buf must be at least 256
 * bytes in size.
 */
ssize_t
aprs_compose_pos_info(char *buf, const struct aprs_object *ao)
{
	struct timespec now;
	ssize_t len_info;

	explicit_bzero(buf, 256);

	buf[0] = ((ao->ao_flags & OBJECTF_ITEM) == 0) ? '/' : '!'; /* Data Type Identifier */
	len_info = 1;

	if ((ao->ao_flags & OBJECTF_ITEM) == 0) {
		/* Timestamp */
		clock_gettime(CLOCK_REALTIME, &now);
		strftime(&buf[1], 7, "%d%H%M", gmtime(&ao->ao_timestamp.tv_sec));
		len_info += 6;
		buf[len_info++] = 'z';
	}

	len_info += aprs_compose_base_report(&buf[len_info], ao);

	assert(len_info <= 256);

	return len_info;
}

/*
 * Composes an APRS item/object report information field. The length of the
 * composed information data is returned. The provided buf must be at least 256
 * bytes in size.
 */
ssize_t
aprs_compose_obj_info(char *buf, const struct aprs_object *ao)
{
	struct timespec now;
	ssize_t len_info;

	explicit_bzero(buf, 256);

	buf[0] = ((ao->ao_flags & OBJECTF_ITEM) == 0) ? ';' : ')'; /* Data Type Identifier */

	/* Object Name */
	for (len_info = 1; len_info < 10; len_info++) {
		if (ao->ao_name[len_info - 1] == '\0')
			break;
		buf[len_info] = ao->ao_name[len_info - 1];
	}

	if ((ao->ao_flags & OBJECTF_ITEM) == 0) {
		for (; len_info < 10; len_info++)
			buf[len_info] = ' ';
		buf[len_info++] = ((ao->ao_flags & OBJECTF_DEAD) == 0) ? '*' : '_';
		/* Timestamp */
		clock_gettime(CLOCK_REALTIME, &now);
		strftime(&buf[len_info], 7, "%d%H%M", gmtime(&ao->ao_timestamp.tv_sec));
		len_info += 6;
		buf[len_info++] = 'z';
	} else {
		len_info = 1 + strlen(ao->ao_name);
		buf[len_info++] = ((ao->ao_flags & OBJECTF_DEAD) == 0) ? '!' : '_';
	}

	len_info += aprs_compose_base_report(&buf[len_info], ao);

	assert(len_info <= 256);

	return len_info;
}
