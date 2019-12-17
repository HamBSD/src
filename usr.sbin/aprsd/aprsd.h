
#define APRS_MAXLEN 256

#define BEACONT_PON 1 /* position beacon, no timestamp */
#define BEACONT_POT 2 /* position beacon, with timestamp */
#define BEACONT_OBJ 3 /* object beacon */

#define BEACONF_LATSET	0x01	/* a fixed latitude is defined */
#define BEACONF_LONSET	0x02	/* a fixed longitude is defined */
#define BEACONF_POSSET (BEACONF_LATSET | BEACONF_LONSET)
#define BEACONF_ALTSET	0x04	/* a fixed altitude is defined */
#define BEACONF_SOUTH	0x08	/* the fixed latitude is negative */
#define BEACONF_WEST	0x10	/* the fixed longitude in negative */

struct beacon_config {
	long long latitude;
	long long longitude;
	long altitude;
	int type;
	int interval;
	int flags;
	char *comment;
	char *name;
	char *sensor;
};

#define MAX_BEACONS 20

struct aprsd_config {
	int num_beacons;
	struct beacon_config *beacons[MAX_BEACONS];
};

/* parse.y */
int parse_config(char *, struct aprsd_config *);
