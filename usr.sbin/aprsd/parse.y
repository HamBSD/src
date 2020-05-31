/*	$OpenBSD: parse.y,v 1.18 2003/12/25 23:23:51 henning Exp $ */

/*
 * Copyright (c) 2019 Iain R. Learmonth.
 * Copyright (c) 2002, 2003 Henning Brauer <henning@openbsd.org>
 * Copyright (c) 2001 Markus Friedl.  All rights reserved.
 * Copyright (c) 2001 Daniel Hartmeier.  All rights reserved.
 * Copyright (c) 2001 Theo de Raadt.  All rights reserved.
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

%{
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "aprs.h"
#include "aprsd.h"

static struct aprsd_config	*conf;
static struct aprs_object	*curentity;
static FILE			*fin = NULL;
static int			 lineno = 1;
static int			 errors = 0;
static int			 pdebug = 1;
char				*infile;

int	 yyerror(const char *, ...);
int	 yyparse(void);
int	 kw_cmp(const void *, const void *);
int	 lookup(char *);
int	 lgetc(FILE *);
int	 lungetc(int);
int	 findeol(void);
int	 yylex(void);

TAILQ_HEAD(symhead, sym)	 symhead = TAILQ_HEAD_INITIALIZER(symhead);
struct sym {
	TAILQ_ENTRY(sym)	 entries;
	int			 used;
	int			 persist;
	char			*nam;
	char			*val;
};

int	 symset(const char *, const char *, int);
char	*symget(const char *);

typedef struct {
	union {
		long long	 number;
		char		*string;
		struct in_addr	 addr;
	} v;
	int lineno;
} YYSTYPE;

%}

%token	ALTITUDE BEACON COMMENT FIXED ITEM
%token	SENSOR STATION SYMBOL
%token	<v.string>	STRING
%type	<v.number>	number
%type	<v.string>	string
%%

grammar		: /* empty */
		| grammar '\n'
		| grammar conf_main '\n'
		| grammar varset '\n'
		| grammar error '\n'		{ errors++; }
		;

number		: STRING			{
			long long	 llval;
			const char	*errstr;

			llval = strtonum($1, -180000001, 180000001, &errstr);
			if (errstr != NULL) {
				yyerror("error in number %s: %s", $1, errstr);
				YYERROR;
			} else
				$$ = llval;
		}
		;

string		: string STRING				{
			if (asprintf(&$$, "%s %s", $1, $2) == -1)
				err(1, "string: asprintf");
			free($1);
			free($2);
		}
		| STRING
		;

varset		: STRING '=' string		{
			//if (conf->opts & BGPD_OPT_VERBOSE)
			//	printf("%s = \"%s\"\n", $1, $3);
			if (symset($1, $3, 0) == -1)
				err(1, "cannot store variable");
		}
		;

conf_main	: station
		| item
		;

station		: STATION {
	 		/* check if station was already defined */
			if (conf->station != NULL) {
				yyerror("found more than one station definition");
				YYERROR;
			}
			curentity = malloc(sizeof(struct aprs_object));
			if (curentity == NULL)
				err(1, "malloc");
			aprs_obj_init(curentity);
			aprs_obj_item(curentity, 1);
		} obj_sym obj_pos obj_com {
			conf->station = curentity;
		}
		;

item		: ITEM string {
			curentity = malloc(sizeof(struct aprs_object));
			if (curentity == NULL)
				err(1, "malloc");
			aprs_obj_init(curentity);
			aprs_obj_name(curentity, $2);
			aprs_obj_item(curentity, 1);
		} obj_sym obj_pos obj_com {
			conf->entities[conf->num_entities++] = curentity;
		}
		;

obj_sym		: SYMBOL string {
			if (strlen($2) != 2 || aprs_obj_sym(curentity, $2) == -1) {
				yyerror("error in parsing station symbol");
				YYERROR;
			}
		}
		| /* EMPTY */
		;

obj_pos		: FIXED number number number {
			if (aprs_obj_pos(curentity, $2, $3, $4) == -1) {
				yyerror("error in parsing station position with ambiguity");
				YYERROR;
			}
		}
		| FIXED number number {
			if (aprs_obj_pos(curentity, $2, $3, 0) == -1) {
				yyerror("error in parsing station position");
				YYERROR;
			}
		}
		| SENSOR string {
			/* if (aprs_obj_sensor(curentity, $2) == -1) {
				yyerror("error in parsing sensor for station position");
				YYERROR;
			} */
		}
		;

obj_com		: COMMENT string {
			if (aprs_obj_comment(curentity, $2) == -1) {
				yyerror("error in parsing comment for station");
				YYERROR;
			}
		}
		| /* EMPTY */
		;

%%

struct keywords {
	const char	*k_name;
	int		 k_val;
};

int
yyerror(const char *fmt, ...)
{
	va_list		 ap;
	char		*nfmt;

	errors = 1;
	va_start(ap, fmt);
	if (asprintf(&nfmt, "%s:%d: %s", infile, yylval.lineno, fmt) == -1)
		err(1, "yyerror asprintf");
	printf(nfmt, ap);
	va_end(ap);
	free(nfmt);
	return (0);
}

int
kw_cmp(const void *k, const void *e)
{
	return (strcmp(k, ((const struct keywords *)e)->k_name));
}

int
lookup(char *s)
{
	/* this has to be sorted always */
	static const struct keywords keywords[] = {
		{ "altitude",		ALTITUDE },
		{ "comment",		COMMENT },
		{ "fixed",		FIXED },
		{ "item",		ITEM },
		{ "sensor",		SENSOR },
		{ "station",		STATION },
		{ "symbol",		SYMBOL },
	};
	const struct keywords	*p;

	p = bsearch(s, keywords, sizeof(keywords)/sizeof(keywords[0]),
	    sizeof(keywords[0]), kw_cmp);

	if (p) {
		if (pdebug > 1)
			fprintf(stderr, "%s: %d\n", s, p->k_val);
		return (p->k_val);
	} else {
		if (pdebug > 1)
			fprintf(stderr, "string: %s\n", s);
		return (STRING);
	}
}

#define MAXPUSHBACK	128

char	*parsebuf;
int	 parseindex;
char	 pushback_buffer[MAXPUSHBACK];
int	 pushback_index = 0;

int
lgetc(FILE *f)
{
	int	c, next;

	if (parsebuf) {
		/* Read character from the parsebuffer instead of input. */
		if (parseindex >= 0) {
			c = parsebuf[parseindex++];
			if (c != '\0')
				return (c);
			parsebuf = NULL;
		} else
			parseindex++;
	}

	if (pushback_index)
		return (pushback_buffer[--pushback_index]);

	while ((c = getc(f)) == '\\') {
		next = getc(f);
		if (next != '\n') {
			if (isspace(next))
				yyerror("whitespace after \\");
			ungetc(next, f);
			break;
		}
		yylval.lineno = lineno;
		lineno++;
	}
	if (c == '\t' || c == ' ') {
		/* Compress blanks to a single space. */
		do {
			c = getc(f);
		} while (c == '\t' || c == ' ');
		ungetc(c, f);
		c = ' ';
	}

	return (c);
}

int
lungetc(int c)
{
	if (c == EOF)
		return (EOF);
	if (parsebuf) {
		parseindex--;
		if (parseindex >= 0)
			return (c);
	}
	if (pushback_index < MAXPUSHBACK-1)
		return (pushback_buffer[pushback_index++] = c);
	else
		return (EOF);
}

int
findeol(void)
{
	int	c;

	parsebuf = NULL;
	pushback_index = 0;

	/* skip to either EOF or the first real EOL */
	while (1) {
		c = lgetc(fin);
		if (c == '\n') {
			lineno++;
			break;
		}
		if (c == EOF)
			break;
	}
	//return (ERROR);
	return 250;
}

int
yylex(void)
{
	char	 buf[8096];
	char	*p, *val;
	int	 endc, c;
	int	 token;

top:
	p = buf;
	while ((c = lgetc(fin)) == ' ')
		; /* nothing */

	yylval.lineno = lineno;
	if (c == '#')
		while ((c = lgetc(fin)) != '\n' && c != EOF)
			; /* nothing */
	if (c == '$' && parsebuf == NULL) {
		while (1) {
			if ((c = lgetc(fin)) == EOF)
				return (0);

			if (p + 1 >= buf + sizeof(buf) - 1) {
				yyerror("string too long");
				return (findeol());
			}
			if (isalnum(c) || c == '_') {
				*p++ = (char)c;
				continue;
			}
			*p = '\0';
			lungetc(c);
			break;
		}
		val = symget(buf);
		if (val == NULL) {
			yyerror("macro '%s' not defined", buf);
			return (findeol());
		}
		parsebuf = val;
		parseindex = 0;
		goto top;
	}

	switch (c) {
	case '\'':
	case '"':
		endc = c;
		while (1) {
			if ((c = lgetc(fin)) == EOF)
				return (0);
			if (c == endc) {
				*p = '\0';
				break;
			}
			if (c == '\n') {
				lineno++;
				continue;
			}
			if (p + 1 >= buf + sizeof(buf) - 1) {
				yyerror("string too long");
				return (findeol());
			}
			*p++ = (char)c;
		}
		yylval.v.string = strdup(buf);
		if (yylval.v.string == NULL)
			err(1, "yylex: strdup");
		return (STRING);
	}

#define allowed_in_string(x) \
	(isalnum(x) || (ispunct(x) && x != '(' && x != ')' && \
	x != '{' && x != '}' && x != '<' && x != '>' && \
	x != '!' && x != '=' && x != '/' && x != '#' && \
	x != ','))

	if (isalnum(c) || c == ':' || c == '_' || c == '-') {
		do {
			*p++ = c;
			if ((unsigned)(p-buf) >= sizeof(buf)) {
				yyerror("string too long");
				return (findeol());
			}
		} while ((c = lgetc(fin)) != EOF && (allowed_in_string(c)));
		lungetc(c);
		*p = '\0';
		token = lookup(buf);
		yylval.v.string = strdup(buf);
		if (yylval.v.string == NULL)
			err(1, "yylex: strdup");
		return (token);
	}
	if (c == '\n') {
		yylval.lineno = lineno;
		lineno++;
	}
	if (c == EOF)
		return (0);
	return (c);
}

int
parse_config(char *filename, struct aprsd_config *xconf)
{
	struct sym	*sym, *next;

	/*if ((conf = calloc(1, sizeof(struct beacon_config))) == NULL)
		err(1, "calloc");*/

	conf = xconf;

	lineno = 1;
	errors = 0;

	if (strcmp(filename, "-") == 0) {
		fin = stdin;
		infile = "stdin";
	} else {
		if ((fin = fopen(filename, "r")) == NULL) {
			warn("%s", filename);
			return (1);
		}
		infile = filename;
	}

	yyparse();

	/* Free macros and check which have not been used. */
	for (sym = TAILQ_FIRST(&symhead); sym != NULL; sym = next) {
		next = TAILQ_NEXT(sym, entries);
		if (!sym->used)
			fprintf(stderr, "warning: macro '%s' not "
			    "used\n", sym->nam);
		if (!sym->persist) {
			free(sym->nam);
			free(sym->val);
			TAILQ_REMOVE(&symhead, sym, entries);
			free(sym);
		}
	}

	/* TODO: we would merge the configs and free the local one here */

	return (errors ? -1 : 0);
}

int
symset(const char *nam, const char *val, int persist)
{
	struct sym	*sym;

	for (sym = TAILQ_FIRST(&symhead); sym && strcmp(nam, sym->nam);
	    sym = TAILQ_NEXT(sym, entries))
		;	/* nothing */

	if (sym != NULL) {
		if (sym->persist == 1)
			return (0);
		else {
			free(sym->nam);
			free(sym->val);
			TAILQ_REMOVE(&symhead, sym, entries);
			free(sym);
		}
	}
	if ((sym = calloc(1, sizeof(*sym))) == NULL)
		return (-1);

	sym->nam = strdup(nam);
	if (sym->nam == NULL) {
		free(sym);
		return (-1);
	}
	sym->val = strdup(val);
	if (sym->val == NULL) {
		free(sym->nam);
		free(sym);
		return (-1);
	}
	sym->used = 0;
	sym->persist = persist;
	TAILQ_INSERT_TAIL(&symhead, sym, entries);
	return (0);
}

int
cmdline_symset(char *s)
{
	char	*sym, *val;
	int	 ret;

	if ((val = strrchr(s, '=')) == NULL)
		return (-1);

	if ((sym = malloc(strlen(s) - strlen(val) + 1)) == NULL)
		err(1, "cmdline_symset: malloc");

	strlcpy(sym, s, strlen(s) - strlen(val) + 1);

	ret = symset(sym, val + 1, 1);
	free(sym);

	return (ret);
}

char *
symget(const char *nam)
{
	struct sym	*sym;

	TAILQ_FOREACH(sym, &symhead, entries)
		if (strcmp(nam, sym->nam) == 0) {
			sym->used = 1;
			return (sym->val);
		}
	return (NULL);
}
