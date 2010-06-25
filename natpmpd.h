#ifndef _NATPMPD_H
#define _NATPMPD_H

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/queue.h>

#include <netinet/in.h>

#include <net/if.h>

#include <event.h>
#include <netdb.h>

#define NATPMPD_USER		 "_natpmp"
#define CONF_FILE		 "/etc/natpmpd.conf"

#define NATPMPD_SERVER_PORT 	 5351
#define NATPMPD_CLIENT_PORT	 5350

#define NATPMPD_MAX_VERSION	 0

#define NATPMPD_SUCCESS		 0
#define NATPMPD_BAD_VERSION	 1
#define NATPMPD_NOT_AUTHORISED	 2
#define NATPMPD_METWORK_FAILURE	 3
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
	in_addr_t		 sc_address;
	TAILQ_HEAD(listen_addrs, listen_addr)		 listen_addrs;
	u_int8_t					 listen_all;
	char		 	 sc_interface[IF_NAMESIZE];
	struct timeval		 sc_starttime;
	int			 sc_delay;
	struct event		 sc_announce_ev;
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

#endif
