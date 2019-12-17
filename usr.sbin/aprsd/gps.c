
#include <string.h>
#include <err.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/sensors.h>

#include "gps.h"

static struct sensordev *
gps_find_sensor(char *name)
{
	int mib[3];
	static struct sensordev sd;
	size_t sdlen;

	mib[0] = CTL_HW;
	mib[1] = HW_SENSORS;
	sdlen = sizeof(sd);
	for (mib[2] = 0; ; mib[2]++) {
		if (sysctl(mib, 3, &sd, &sdlen, NULL, 0) == -1) {
			if (errno == ENXIO)
				continue;
			if (errno == ENOENT)
				break;
			err(1, "sysctl");
		}
		if (strcmp(name, sd.xname) == 0)
			return &sd;
	}
	return NULL;
}

int
gps_get_position(struct gps_position *pos, char *sensor_name)
{
	struct sensor s;
	struct sensordev *sd;
	int mib[5];
	int lat, lon;
	size_t slen;

	lat = lon = 0;
	slen = sizeof(s);
	if ((sd = gps_find_sensor(sensor_name)) == NULL)
		return 0;
	mib[0] = CTL_HW;
	mib[1] = HW_SENSORS;
	mib[2] = sd->num;
	mib[3] = SENSOR_ANGLE;
	for (mib[4] = 0; mib[4] < sd->maxnumt[mib[3]]; mib[4]++) {
		if (sysctl(mib, 5, &s, &slen, NULL, 0) == -1)
			continue;
		if (s.type == SENSOR_ANGLE && strcmp("Latitude", s.desc) == 0 &&
		    s.status == SENSOR_S_OK) {
			lat = 1;
			pos->lat = s.value;
		} else if (s.type == SENSOR_ANGLE && strcmp("Longitude", s.desc) == 0 &&
		    s.status == SENSOR_S_OK) {
			lon = 1;
			pos->lon = s.value;
		}
	}
	return lat + lon;
}
