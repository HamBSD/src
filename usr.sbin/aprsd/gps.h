
struct gps_position {
	long long lat;
	long long lon;
};

int gps_get_position(struct gps_position *, char *);
