
#define OBJECTF_ITEM 0x01
#define OBJECTF_DEAD 0x02

struct aprs_object {
	struct timespec	 ao_timestamp;
	struct timespec	 ao_nexttime;
	long long	 ao_lon;
	long long	 ao_lat;
	int		 ao_posamb;
	int		 ao_flags;	/* OBJECTF_* */
	char		 ao_source[9];
	char		 ao_name[10];
	char		 ao_comment[254];
	char		 ao_symbol[2];
};

int aprs_obj_comment(struct aprs_object *, const char *);
void aprs_obj_dead(struct aprs_object *, int);
int aprs_obj_init(struct aprs_object *);
void aprs_obj_item(struct aprs_object *, int);
int aprs_obj_name(struct aprs_object *, const char *);
int aprs_obj_pos(struct aprs_object *, const long long, const long long, int);
int aprs_obj_sym(struct aprs_object *ao, const char *symbol);
int aprs_obj_timestamp(struct aprs_object *, time_t);

ssize_t		 aprs_compose_pos_info(char *, const struct aprs_object *);
ssize_t		 aprs_compose_obj_info(char *, const struct aprs_object *);
