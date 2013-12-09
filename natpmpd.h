/*
 * Copyright (c) 2014 Matt Dainty <matt@bodgit-n-scarper.com>
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

#ifndef _NATPMPD_H
#define _NATPMPD_H

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/queue.h>

#include <netinet/in.h>

#include <net/if.h>

#include <event.h>
#include <netdb.h>

#define SALIGN			 (sizeof(long) - 1)
#define SA_RLEN(sa)		 ((sa)->sa_len ? (((sa)->sa_len + SALIGN) & ~SALIGN) : (SALIGN + 1))

#define	IN6ADDR_V4MAPPED_INIT \
	{{{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	    0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00 }}}

#define	IN6_IS_ADDR_V4MAPPED_ANY(a) \
	((*(const u_int32_t *)(const void *)(&(a)->s6_addr[0]) == 0) && \
	 (*(const u_int32_t *)(const void *)(&(a)->s6_addr[4]) == 0) && \
	 (*(const u_int32_t *)(const void *)(&(a)->s6_addr[8]) == ntohl(0x0000ffff)) && \
	 (*(const u_int32_t *)(const void *)(&(a)->s6_addr[12]) == 0))

#define NATPMPD_USER		 "_natpmpd"
#define CONF_FILE		 "/etc/natpmpd.conf"

#define NATPMPD_SERVER_PORT 	 5351
#define NATPMPD_CLIENT_PORT	 5350

#define NATPMPD_ANCHOR		 "natpmpd"

#define NATPMPD_MAX_VERSION	 0

#define NATPMPD_SUCCESS		 0
#define NATPMPD_BAD_VERSION	 1
#define NATPMPD_NOT_AUTHORISED	 2
#define NATPMPD_NETWORK_FAILURE	 3
#define NATPMPD_NO_RESOURCES	 4
#define NATPMPD_BAD_OPCODE	 5

#define NATPMPD_MAX_DELAY	 10

#define NATPMPD_MAX_PACKET_SIZE	 16

struct address {
	struct sockaddr_storage	 ss;
	in_port_t		 port;
};

struct listen_addr {
	TAILQ_ENTRY(listen_addr)	 entry;
	struct sockaddr_storage		 sa;
	int				 fd;
	struct event			 ev;
};

struct ntp_addr {
	struct ntp_addr		*next;
	struct sockaddr_storage	 ss;
};

struct ntp_addr_wrap {
	char			*name;
	struct ntp_addr		*a;
	u_int8_t		 pool;
};

struct natpmpd {
	u_int8_t		 sc_flags;
#define NATPMPD_F_VERBOSE	 0x01;

	const char		*sc_confpath;
	struct in6_addr		 sc_address;
	TAILQ_HEAD(listen_addrs, listen_addr)		 listen_addrs;
	u_int8_t					 listen_all;
	char			 sc_interface[IF_NAMESIZE];
	struct timeval		 sc_starttime;
	int			 sc_delay;
	struct event		 sc_announce_ev;
	struct event		 sc_expire_ev;
};

/* prototypes */
/* log.c */
void		 log_init(int);
void		 vlog(int, const char *, va_list);
void		 log_warn(const char *, ...);
void		 log_warnx(const char *, ...);
void		 log_info(const char *, ...);
void		 log_debug(const char *, ...);
void		 fatal(const char *);
void		 fatalx(const char *);
const char *	 log_sockaddr(struct sockaddr *);

/* parse.y */
struct natpmpd	*parse_config(const char *, u_int);
int		 host(const char *, struct ntp_addr **);
int		 host_dns(const char *, struct ntp_addr **);

/* filter.c */
void		 init_filter(char *, char *, int);
int		 prepare_commit(void);
int		 add_rdr(u_int8_t, struct sockaddr *, struct sockaddr *);
int		 do_commit(void);
int		 do_rollback(void);
void		 expire_rules(int, short, void *);

#endif
