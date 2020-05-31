
#define APRS_MAXLEN 256

#define MAX_ENTITIES 20

struct aprsd_config {
	int			 net_cycle;
	int			 num_entities;
	struct aprs_object	*station;
	struct aprs_object	*entities[MAX_ENTITIES];
	char			 mycall[10];
};

/* parse.y */
int parse_config(char *, struct aprsd_config *);
