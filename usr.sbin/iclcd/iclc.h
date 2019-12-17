
#define ICLC_IDENT_QRT 1

#define ICLC_MAXCALL 42

struct iclc_ident_frame_hdr {
	struct ether_addr	fr_dhost;
	struct ether_addr	fr_shost;
	u_int16_t		fr_et;
	u_int8_t		fr_subtype;
	u_int8_t		fr_version;
	u_int8_t		fr_flags;
	u_int8_t		fr_calllen;
	u_int8_t		fr_call[ICLC_MAXCALL];
};

struct iclc_ident {
	char			call[ICLC_MAXCALL];
	struct ether_addr	hwaddr;
	time_t			first_heard;
	time_t			last_heard;
	int			flags;
	SLIST_ENTRY(iclc_ident)	entries;
};
SLIST_HEAD(iclc_idents_list, iclc_ident) iclc_idents;

