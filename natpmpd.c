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

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <net/pfvar.h>

#include <arpa/inet.h>

#include <stdio.h>
#include <netdb.h>
#include <errno.h>
#include <event.h>
#include <signal.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <unistd.h>
#include <assert.h>
#include <pwd.h>
#include <ifaddrs.h>

#include "natpmpd.h"

struct mapping {
	u_int32_t		 proto;
	struct sockaddr_storage	 dst;
	struct sockaddr_storage	 rdr;
	struct event		 ev;
	u_int8_t		*nonce;
	LIST_ENTRY(mapping)	 entry;
};

struct common_header {
	u_int8_t		 version;
	u_int8_t		 opcode;
};

struct natpmp_request {
	u_int8_t		 version;
	u_int8_t		 opcode;
	/* The following only appears in mapping requests */
	u_int16_t		 reserved;
	u_int16_t		 port[2];
	u_int32_t		 lifetime;
};

struct natpmp_response {
	u_int8_t			 version;
	u_int8_t			 opcode;
	u_int16_t			 result;
	u_int32_t			 sssoe;
	/* The following only appears in response to valid requests */
	union {
		struct {
			u_int32_t	 address;
		} announce;
		struct {
			u_int16_t	 port[2];
			u_int32_t	 lifetime;
		} mapping;
	} data;
};

/* Common PCP header */
struct pcp_header {
	u_int8_t		 version;
	u_int8_t		 opcode;
	u_int8_t		 reserved;
	u_int8_t		 result;
	u_int32_t		 lifetime;
	union {
		struct in6_addr	 addr;
		u_int32_t	 sssoe;
	} data;
};

/* MAP opcode has this struct following the header */
struct pcp_map {
	u_int8_t		 nonce[12];
	u_int8_t		 protocol;
	u_int8_t		 reserved[3];
	u_int16_t		 port[2];
	struct in6_addr		 addr;
};

/* PEER opcode has this struct following the MAP opcode */
struct pcp_peer {
	u_int16_t		 port;
	u_int16_t		 reserved;
	struct in6_addr		 addr;
};

/* Common PCP option header */
struct pcp_option_header {
	u_int8_t		 code;
	u_int8_t		 reserved;
	u_int16_t		 length;
};

/* FILTER option has this struct following the header */
struct pcp_option_filter {
	u_int8_t		 reserved;
	u_int8_t		 prefix;
	u_int16_t		 port;
	struct in6_addr		 addr;
};

/* List of trusted third parties */
struct pcp_third_party {
	struct in6_addr			 addr;
	TAILQ_ENTRY(pcp_third_party)	 entry;
};

struct pcp_filter {
	u_int8_t		 prefix;
	u_int16_t		 port;
	struct in6_addr		 addr;
	TAILQ_ENTRY(pcp_filter)	 entry;
};

TAILQ_HEAD(pcp_filters, pcp_filter);

struct pcp_option {
	struct pcp_option_header		*header;
	union {
		u_int8_t			*raw;
		struct in6_addr			*addr;
		struct pcp_option_filter	*filter;
	} data;
	TAILQ_ENTRY(pcp_option)			 entry;
};

struct pcp_option_rule {
	unsigned int	 code;	/* Option code */
	unsigned int	 min;	/* Minimum length */
	unsigned int	 max;	/* Maximum length */
	unsigned int	 count;	/* Maximum number of occurences */
	unsigned int	 valid;	/* Bitmask of valid opcodes */
};

void		 handle_signal(int, short, void *);
__dead void	 usage(void);
struct mapping	*init_mapping(void);
void		 expire_mapping(int, short, void *);
void		 announce_address(int, short, void *);
void		 route_handler(int, short, void *);
void		 common_handler(int, short, void *);
int		 natpmp_remove_mapping(u_int8_t, struct sockaddr_in *);
int		 natpmp_create_mapping(u_int8_t, struct sockaddr_in *,
		     struct sockaddr_in *, u_int32_t);
ssize_t		 natpmp_mapping(struct natpmp_response *, u_int8_t,
		     struct sockaddr_in *, struct sockaddr_in *, u_int32_t,
		     struct natpmpd *);
void		 natpmp_handler(struct natpmpd *, int, u_int8_t *, ssize_t,
		     struct sockaddr *);
u_int8_t	 pcp_map(u_int8_t, struct in6_addr, u_int16_t,
		     struct in6_addr *, u_int16_t *, u_int32_t *, u_int8_t *,
		     unsigned int, struct pcp_filters *);
void		 pcp_handler(struct natpmpd *, int, u_int8_t *, ssize_t,
		     struct sockaddr *);
void		 check_interface(struct natpmpd *);
int		 rebuild_rules(void);
u_int32_t	 sssoe(struct natpmpd *);

struct timeval timeouts[NATPMPD_MAX_DELAY] = {
	{  0,      0 },
	{  0, 250000 },
	{  0, 500000 },
	{  1,      0 },
	{  2,      0 },
	{  4,      0 },
	{  8,      0 },
	{ 16,      0 },
	{ 32,      0 },
	{ 64,      0 },
};

LIST_HEAD(, mapping) mappings = LIST_HEAD_INITIALIZER(mappings);

/* XXX This (empty) list should move elsewhere eventually */
TAILQ_HEAD(, pcp_third_party) third_party = TAILQ_HEAD_INITIALIZER(third_party);

/* Table of supported PCP options */
struct pcp_option_rule pcp_options[] = {
	{ PCP_OPTION_THIRD_PARTY,    16, 16, 1, 0x06 },
	{ PCP_OPTION_PREFER_FAILURE,  0,  0, 1, 0x02 },
	{ PCP_OPTION_FILTER,         20, 20, 0, 0x02 },
};

struct in6_addr		 all_nodes = IN6ADDR_LINKLOCAL_ALLNODES_INIT;
struct sockaddr_in	 all_nodes4;
struct sockaddr_in6	 all_nodes6;

void
handle_signal(int sig, short event, void *arg)
{
	struct mapping	*m;

	log_info("exiting on signal %d", sig);

	/* Remove every mapping and then rebuild the ruleset which should
	 * hopefully result in an empty anchor after we're gone
	 */
	for (m = LIST_FIRST(&mappings); m != NULL; m = LIST_NEXT(m, entry)) {
		if (evtimer_pending(&m->ev, NULL))
			evtimer_del(&m->ev);
		LIST_REMOVE(m, entry);
		if (m->nonce)
			free(m->nonce);
		free(m);
	}

	if (rebuild_rules() == -1)
		log_warn("unable to rebuild ruleset");

	exit(0);
}

/* __dead is for lint */
__dead void
usage(void)
{
	extern char	*__progname;

	fprintf(stderr, "usage: %s [-dnv] [-f file]\n", __progname);
	exit(1);
}

struct mapping *
init_mapping(void)
{
	struct mapping	*m;

	if ((m = calloc(1, sizeof(struct mapping))) == NULL)
		return (NULL);

	LIST_INSERT_HEAD(&mappings, m, entry);

	return (m);
}

void
expire_mapping(int fd, short event, void *arg)
{
	struct mapping	*m = (struct mapping *)arg;

	log_info("expiring mapping");

	/*
	 * TODO Draft says we should send TCP RST packets to both client and
	 *      remote peer in the case of any active states when this expiry
	 *      event fires.  How hard is that to do with pf?
	 */

	LIST_REMOVE(m, entry);
	if (m->nonce)
		free(m->nonce);
	free(m);

	if (rebuild_rules() == -1)
		log_warn("unable to rebuild ruleset");
}

int
rebuild_rules(void)
{
	struct mapping	*m;

	if (prepare_commit() == -1)
		goto fail;
	for (m = LIST_FIRST(&mappings); m != NULL; m = LIST_NEXT(m, entry))
		if (add_rdr(m->proto, (struct sockaddr *)&m->dst,
		    (struct sockaddr *)&m->rdr) == -1)
			goto fail;
	if (do_commit() == -1) {
		if (errno != EBUSY)
			goto fail;
		usleep(5000);
		if (do_commit() == -1)
			goto fail;
	}
	return (0);

fail:
	do_rollback();
	return (-1);
}

u_int32_t
sssoe(struct natpmpd *env)
{
	struct timeval	 tv;

	gettimeofday(&tv, NULL);

	return (tv.tv_sec - env->sc_starttime.tv_sec);
}

void
announce_address(int fd, short event, void *arg)
{
	struct natpmpd		*env = (struct natpmpd *)arg;
	u_int8_t		 packet[NATPMPD_MAX_PACKET_SIZE];
	struct natpmp_response	*r;
	struct listen_addr	*la;

	/* Create the address announce packet */
	assert(sizeof(struct natpmp_response) <= NATPMPD_MAX_PACKET_SIZE);
	r = (struct natpmp_response *)packet;
	memset(r, 0, sizeof(struct natpmp_response));

	r->version = NATPMPD_MAX_VERSION;
	r->opcode = 0x80;
	r->result = NATPMP_SUCCESS;
	r->sssoe = htonl(sssoe(env));
	r->data.announce.address =
	    *(const u_int32_t *)(&(&env->sc_address)->s6_addr[12]);

	/* Loop through all of our listening addresses and send the packet */
	for (la = TAILQ_FIRST(&env->listen_addrs); la;
	    la = TAILQ_NEXT(la, entry)) {
		if (la->sa.ss_family != AF_INET)
			continue;
		if (sendto(la->fd, packet, 12, 0,
		    (struct sockaddr *)&all_nodes4, sizeof(all_nodes4)) < 0)
			log_warn("sendto");
	}

	env->sc_delay++;

	/* If we haven't sent 10 announcements yet, queue up another */
	if (env->sc_delay < NATPMPD_MAX_DELAY)
		evtimer_add(&env->sc_announce_ev, &timeouts[env->sc_delay]);
}

void
route_handler(int fd, short event, void *arg)
{
	struct natpmpd			*env = (struct natpmpd *)arg;
	char				 msg[RTM_MAXSIZE];
	struct rt_msghdr		*rtm = (struct rt_msghdr *)&msg;
	struct ifa_msghdr		*ifam;
	struct if_announcemsghdr	*ifan;
	ssize_t				 len;
	char				*cp;
	int				 i;

	len = read(fd, msg, sizeof(msg));

	if (rtm->rtm_version != RTM_VERSION)
		return;

	switch (rtm->rtm_type) {
	case RTM_NEWADDR:
		/* FALLTHROUGH */
	case RTM_DELADDR:
		ifam = (struct ifa_msghdr *)rtm;
		cp = ((char *)(ifam + 1));
		/* We only care about matching the interface name */
		for (i = 1; ifam->ifam_addrs && i <= RTA_IFP; i <<= 1)
			if (i & ifam->ifam_addrs) {
				if (i == RTA_IFP && strcmp(env->sc_interface,
				    ((struct sockaddr_dl *)cp)->sdl_data) == 0)
					check_interface(env);
				cp += SA_RLEN((struct sockaddr *)cp);
			}
		break;
	case RTM_IFANNOUNCE:
		ifan = (struct if_announcemsghdr *)rtm;
		/* Interface got destroyed (PPPoE, etc.) */
		if (ifan->ifan_what == IFAN_DEPARTURE
		    && strcmp(env->sc_interface, ifan->ifan_name) == 0)
			check_interface(env);
		break;
	default:
		return;
		/* NOTREACHED */
	}
}

void
common_handler(int fd, short event, void *arg)
{
	struct natpmpd		*env = (struct natpmpd *)arg;
	struct sockaddr_storage	 ss;
	u_int8_t		 request[NATPMPD_MAX_PACKET_SIZE+1];
	struct common_header	*header = (struct common_header *)&request;
	socklen_t		 slen;
	ssize_t			 len;

	slen = sizeof(ss);
	if ((len = recvfrom(fd, request, sizeof(request), 0,
	    (struct sockaddr *)&ss, &slen)) < 1 )
		return;

	/* Need at least 2 bytes to be able to do anything useful */
	if ((size_t)len < sizeof(struct common_header))
		return;

	/* No opcode in a request should be greater than 127 */
	if (header->opcode & 0x80)
		return;

	switch (header->version) {
	case 0:
		/* NAT-PMP */
		natpmp_handler(env, fd, request, len, (struct sockaddr *)&ss);
		break;
	default:
		/* PCP */
		pcp_handler(env, fd, request, len, (struct sockaddr *)&ss);
		break;
	}
}

int
natpmp_remove_mapping(u_int8_t proto, struct sockaddr_in *rdr)
{
	struct sockaddr_in	*sa;
	struct mapping		*m;
	int			 count;

	count = 0;
	for (m = LIST_FIRST(&mappings); m; m = LIST_NEXT(m, entry)) {
		sa = (struct sockaddr_in *)&m->rdr;
		if ((m->proto == proto)
		    && (memcmp(&sa->sin_addr, &rdr->sin_addr, sizeof(struct in_addr)) == 0)
		    && ((rdr->sin_port == 0)
			|| (sa->sin_port == rdr->sin_port))) {

			/* Remove the expiry timer */
			if (evtimer_pending(&m->ev, NULL))
				evtimer_del(&m->ev);

			/* Remove the mapping */
			LIST_REMOVE(m, entry);
			free(m);

			count++;
		}
	}

	return (count);
}

int
natpmp_create_mapping(u_int8_t proto, struct sockaddr_in *rdr,
    struct sockaddr_in *dst, u_int32_t lifetime)
{
	struct mapping		*m;
	struct mapping		*r;
	struct timeval		 tv;
	struct sockaddr_in	*sa;

	memset(&tv, 0, sizeof(tv));
	tv.tv_sec = lifetime;

	/* Check for any mapping for the given internal address and port.
	 * Remember any matching mapping where the internal address and port
	 * match, but for a different protocol
	 */
	for (m = LIST_FIRST(&mappings), r = NULL; m; m = LIST_NEXT(m, entry)) {
		if ((m->proto != proto) &&
		    (memcmp(&m->rdr, rdr, sizeof(rdr)) == 0))
			r = m;
		if ((m->proto == proto) &&
		    (memcmp(&m->rdr, rdr, sizeof(rdr)) == 0))
			break;
	}

	if (m != NULL) {
		/*
		 * Update the requested external port from the live mapping 
		 * if it differs.
		 */
		if (memcmp(&m->dst, dst, sizeof(dst)) != 0) {
			fprintf(stderr, "Existing mapping with different port\n");
			sa = (struct sockaddr_in *)&m->dst;
			dst->sin_port = sa->sin_port;
		}

		/* Refresh the expiry timer */
		if (evtimer_pending(&m->ev, NULL))
			evtimer_del(&m->ev);
		evtimer_add(&m->ev, &tv);

		return (0);
	}

	if((m = init_mapping()) == NULL)
		fatal("init_mapping");

	/* If we found a "related" mapping use the port from that as per the
	 * draft, otherwise conjure up a random one
	 */
	if (r != NULL) {
		sa = (struct sockaddr_in *)&r->dst;
		dst->sin_port = sa->sin_port;
	} else
		/* Check for collisions? */
		dst->sin_port = htons(IPPORT_HIFIRSTAUTO +
		    arc4random_uniform(IPPORT_HILASTAUTO - IPPORT_HIFIRSTAUTO));

	m->proto = proto;
	memcpy(&m->dst, dst, sizeof(dst));
	memcpy(&m->rdr, rdr, sizeof(rdr));

	evtimer_set(&m->ev, expire_mapping, m);
	evtimer_add(&m->ev, &tv);

	return (1);
}

ssize_t
natpmp_mapping(struct natpmp_response *response, u_int8_t proto,
    struct sockaddr_in *rdr, struct sockaddr_in *dst, u_int32_t lifetime,
    struct natpmpd *env)
{
	int				 count;
	char				 rdr_ip[INET_ADDRSTRLEN];
	char				 dst_ip[INET_ADDRSTRLEN];

	inet_ntop(AF_INET, &rdr->sin_addr, rdr_ip, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &dst->sin_addr, dst_ip, INET_ADDRSTRLEN);

	log_info("%s request, %s:%d -> %s:%d, expires in %d seconds",
	    (proto == IPPROTO_UDP) ? "UDP" : "TCP",
	    dst_ip, ntohs(dst->sin_port), rdr_ip, ntohs(rdr->sin_port),
	    ntohl(lifetime));

	/* From the spec:
	 *
	 * +---------------+---------------+---------------+
	 * |   rdr port    |   dst port    |   lifetime    |
	 * +-------+-------+-------+-------+-------+-------+
	 * |  = 0  |  > 0  |  = 0  |  > 0  |  = 0  |  > 0  |
	 * +-------+-------+-------+-------+-------+-------+
	 * |       |   *   |   *   |       |       |   *   | Map random port
	 * |       |   *   |       |   *   |       |   *   | Map preferred port
	 * |       |   *   |       |       |   *   |       | Delete one
	 * |   *   |       |   *   |       |   *   |       | Delete all
	 * +-------+-------+-------+-------+-------+-------+
	 */
	count = 0;
	if (rdr->sin_port > 0) {
		if (lifetime > 0) {
			/* Create mapping with preferred or random port */
			count = natpmp_create_mapping(proto, rdr, dst,
			    ntohl(lifetime));

			response->data.mapping.port[0] = rdr->sin_port;
			response->data.mapping.port[1] = dst->sin_port;
			response->data.mapping.lifetime = lifetime;
		} else {
			/* Delete single mapping */
			count = natpmp_remove_mapping(proto, rdr);

			if (count > 1)
				log_warn("%d mappings removed", count);
			else
				log_info("mapping removed");

			response->data.mapping.port[0] = rdr->sin_port;
			response->data.mapping.port[1] = 0;
			response->data.mapping.lifetime = 0;
		}
	} else {
		/* Delete all mappings */
		count = natpmp_remove_mapping(proto, rdr);

		log_info("%d mappings removed", count);

		response->data.mapping.port[0] = 0;
		response->data.mapping.port[1] = 0;
		response->data.mapping.lifetime = 0;
	}

	if (count)
		if (rebuild_rules() == -1)
			log_warn("unable to rebuild ruleset");

	return (16);
}

void
natpmp_handler(struct natpmpd *env, int fd, u_int8_t *request_storage,
    ssize_t len, struct sockaddr *sock)
{
	struct natpmp_request	*request;
	struct natpmp_response	*response;
	u_int8_t		 response_storage[NATPMP_MAX_PACKET_SIZE];
	struct sockaddr_in	 dst;
	struct sockaddr_in	 rdr;
	u_int8_t		 proto;

	/* Ignore NAT-PMP received over IPv6 */
	if (sock->sa_family != AF_INET)
		return;

	assert(sizeof(struct natpmp_request) <= NATPMPD_MAX_PACKET_SIZE);
	assert(sizeof(struct natpmp_response) <= NATPMPD_MAX_PACKET_SIZE);

	request = (struct natpmp_request *)request_storage;
	response = (struct natpmp_response *)&response_storage;
	response->version = NATPMPD_MAX_VERSION;
	response->sssoe = htonl(sssoe(env));

	if (request->version > NATPMP_MAX_VERSION) {
		log_warnx("bad version %d request from %s:%d",
		    request->version, log_sockaddr(sock),
		    ntohs(((struct sockaddr_in *)sock)->sin_port));

		response->opcode = 0x80;
		response->result = NATPMP_UNSUPP_VERSION;
		len = sendto(fd, response_storage, 8, 0,
		    (struct sockaddr *)sock, SA_LEN((struct sockaddr *)sock));
		return;
	}

	/* We don't have an external address */
	if (IN6_IS_ADDR_V4MAPPED_ANY(&env->sc_address))
		response->result = NATPMP_NETWORK_FAILURE;
	else
		response->result = NATPMP_SUCCESS;

	proto = 0;
	switch (request->opcode) {
	case NATPMP_OPCODE_ANNOUNCE:
		if (len != 2) {
			log_warn("address request, expected 2 bytes, got %d",
			    len);
			return;
		}

		response->data.announce.address =
		    *(const u_int32_t *)(&(&env->sc_address)->s6_addr[12]);
		len = 12;
		break;
	case NATPMP_OPCODE_MAP_UDP:
		proto = IPPROTO_UDP;
		/* FALLTHROUGH */
	case NATPMP_OPCODE_MAP_TCP:
		if (proto == 0)
			proto = IPPROTO_TCP;

		if (len != 12) {
			log_warn("mapping request, expected 12 bytes, got %d",
			    len);
			return;
		}

		memcpy(&rdr, sock, sizeof(rdr));
		memcpy(&rdr.sin_port, &request->port[0], sizeof(u_int16_t));

		memset(&dst, 0, sizeof(dst));
		dst.sin_family = AF_INET;
		dst.sin_addr.s_addr =
		    *(const u_int32_t *)(&(&env->sc_address)->s6_addr[12]);
		memcpy(&dst.sin_port, &request->port[1], sizeof(u_int16_t));

		/* FIXME work out here if rebuild_rules() failed so we can
		 * potentially return NATPMP_NOT_AUTHORISED
		 */
		len = natpmp_mapping(response, proto, &rdr, &dst,
		    request->lifetime, env);
		break;
	default:
		/* Unsupported opcodes get the whole request returned */
		memcpy(response, request, len);
		response->result = NATPMP_UNSUPP_OPCODE;
		break;
	}

	/* Set the MSB of the opcode to indicate a response */
	response->opcode = request->opcode | 0x80;

	len = sendto(fd, response_storage, len, 0, (struct sockaddr *)sock,
	    SA_LEN((struct sockaddr *)sock));
}

u_int8_t
pcp_map(u_int8_t protocol, struct in6_addr dst_addr, u_int16_t dst_port,
    struct in6_addr *src_addr, u_int16_t *src_port, u_int32_t *lifetime,
    u_int8_t *nonce, unsigned int flags, struct pcp_filters *filters)
{
	/* FIXME We don't support IPv6 for now */
	if (!IN6_IS_ADDR_V4MAPPED(src_addr)
	    || !IN6_IS_ADDR_V4MAPPED(&dst_addr))
		return (PCP_UNSUPP_FAMILY);

	if (protocol > 0)
		if (dst_port > 0)
			/* Specific port */
			switch (protocol) {
			case IPPROTO_TCP:
				/* FALLTHROUGH */
			case IPPROTO_UDP:
				break;
			default:
				return (PCP_UNSUPP_PROTOCOL);
				/* NOTREACHED */
			}
		else
			/* FIXME All ports */
			return (PCP_UNSUPP_PROTOCOL);
	else
		if (dst_port == 0)
			/* FIXME All protocols */
			return (PCP_UNSUPP_PROTOCOL);
		else
			return (PCP_MALFORMED_REQUEST);

	/* PREFER_FAILURE option and all ports is illegal */
	if (dst_port == 0 && flags & (1 << PCP_OPTION_PREFER_FAILURE))
		return (PCP_MALFORMED_OPTION);

	if (lifetime > 0)
		/* Create or renew existing mapping */
		return (PCP_SUCCESS);
	else {
		/* Delete mapping, but included PREFER_FAILURE and/or FILTER
		 * options
		 */
		if (flags & (1 << PCP_OPTION_PREFER_FAILURE) ||
		    !TAILQ_EMPTY(filters))
			return (PCP_MALFORMED_OPTION);

		/* Delete mapping */
		return (PCP_SUCCESS);
	}

	return (PCP_SUCCESS);
}

void
pcp_handler(struct natpmpd *env, int fd, u_int8_t *request_storage,
    ssize_t len, struct sockaddr *sock)
{
	struct pcp_header		*request = (struct pcp_header *)request_storage;
	struct pcp_map			*map = NULL;
#if 0
	struct pcp_peer			*peer;
#endif
	struct pcp_option_header	*oh;
	struct pcp_option		*option;
	TAILQ_HEAD(, pcp_option)	 options = TAILQ_HEAD_INITIALIZER(options);
	struct pcp_third_party		*tp;
	struct pcp_filter		*filter;
	struct pcp_filters		 filters = TAILQ_HEAD_INITIALIZER(filters);
	u_int8_t			 response_storage[PCP_MAX_PACKET_SIZE];
	struct pcp_header		*response = (struct pcp_header *)response_storage;
	struct in6_addr			 dst_addr = IN6ADDR_V4MAPPED_INIT, src_addr;
	size_t				 opcode, remaining, optlen;
	unsigned int			 counts[nitems(pcp_options)], i, flags = 0;
	u_int16_t			 src_port;
	u_int32_t			 lifetime;
	u_int8_t			 nonce[12];

	memset(response_storage, 0, sizeof(response_storage));
	memcpy(response_storage, request_storage,
	    (len < PCP_MAX_PACKET_SIZE) ? len : PCP_MAX_PACKET_SIZE);
	response->opcode |= 0x80;
	response->reserved = 0;
	response->lifetime = PCP_LONG_LIFETIME;

	/* Version negotiation */
	if (request->version < PCP_MIN_VERSION ||
	    request->version > PCP_MAX_VERSION) {
		log_debug("unsupported version");
		response->version = MAX(MIN(request->version,
		    PCP_MAX_VERSION), PCP_MIN_VERSION);
		response->result = PCP_UNSUPP_VERSION;
		goto send;
	}

	/* Less than 24 octets */
	if ((size_t)len < sizeof(struct pcp_header))
		return;

	/* Exceed 1100 octets or not a multiple of 4 octets */
	if (len > PCP_MAX_PACKET_SIZE || len % 4) {
		log_debug("malformed request");
		response->result = PCP_MALFORMED_REQUEST;
		goto send;
	}

	/* Grab the source address from the sending sockaddr */
	if (sock->sa_family == AF_INET)
		memcpy(&dst_addr.s6_addr[12],
		    &((struct sockaddr_in *)sock)->sin_addr,
		    sizeof(struct in_addr));
	else
		memcpy(&dst_addr, &((struct sockaddr_in6 *)sock)->sin6_addr,
		    sizeof(struct in6_addr));

	/* There's a NAT in the way */
	if (memcmp(&dst_addr, &(&request->data)->addr,
	    sizeof(struct in6_addr)) != 0) {
		log_debug("address mismatch");
		response->result = PCP_ADDRESS_MISMATCH;
		goto send;
	}

	log_debug("version %d, opcode %d, size %d, lifetime %d from %s",
	    request->version, request->opcode, len, ntohl(request->lifetime),
	    log_sockaddr(sock));

	/* Calculate opcode size and set up pointers into the response
	 * packet which by now has a copy of the request packet
	 */
	switch (request->opcode) {
	case PCP_OPCODE_ANNOUNCE:
		opcode = sizeof(struct pcp_header);
		break;
	case PCP_OPCODE_MAP:
		opcode = sizeof(struct pcp_header) + sizeof(struct pcp_map);
		map = (struct pcp_map *)(response_storage + sizeof(struct pcp_header));
		break;
#if 0
	case PCP_OPCODE_PEER:
		opcode = sizeof(struct pcp_header) + sizeof(struct pcp_map)
		    + sizeof(struct pcp_peer);
		map = (struct pcp_map *)(response_storage
		    + sizeof(struct pcp_header));
		peer = (struct pcp_peer *)(response_storage
		    + sizeof(struct pcp_header) + sizeof(struct pcp_map));
		break;
#endif
	default:
		log_debug("unsupported opcode");
		response->result = PCP_UNSUPP_OPCODE;
		goto send;
		/* NOTREACHED */
	}

	/* Not enough octets for the opcode */
	if ((size_t)len < opcode) {
		log_debug("malformed request");
		response->result = PCP_MALFORMED_REQUEST;
		goto send;
	}

	/* Are there options? */
	remaining = len - opcode;
	if (remaining) {
		log_debug("options");
		oh = (struct pcp_option_header *)(request_storage + opcode);
		while (remaining) {
			/* Not enough room for option header? */
			if (remaining < sizeof(struct pcp_option_header)) {
				log_debug("malformed option");
				response->result = PCP_MALFORMED_OPTION;
				goto send;
			}
			remaining -= sizeof(struct pcp_option_header);

			/* Calculate option data length, (rounding up
			 * to the nearest whole 4 octets)
			 */
			optlen = (ntohs(oh->length) + 3) & ~0x03;

			/* Not enough room for option data? */
			if (remaining < optlen) {
				log_debug("malformed option");
				response->result = PCP_MALFORMED_OPTION;
				goto send;
			}
			remaining -= optlen;

			/* Find this option in our supported options */
			for (i = 0; i < nitems(pcp_options) &&
			    (oh->code & 0x7f) != (&pcp_options[i])->code; i++);

			/* We dropped off the end of the list and the option
			 * is unimplemented and mandatory, or the option is
			 * not valid for this opcode
			 *
			 * XXX Not quite sure what to return for the latter
			 */
			if ((i == nitems(pcp_options) && oh->code < 0x80) ||
			    !((&pcp_options[i])->valid & (1 << request->opcode))) {
				log_debug("unsupp option");
				response->result = PCP_UNSUPP_OPTION;
				goto send;
			}

			/* Track how many times we've seen this option,
			 * mandatory or optional
			 */
			counts[i]++;

			/* Option appears more times than it should or is the
			 * wrong size
			 */
			if (((&pcp_options[i])->count &&
			    counts[i] > (&pcp_options[i])->count) ||
			    (ntohs(oh->length) < (&pcp_options[i])->min) ||
			    (ntohs(oh->length) > (&pcp_options[i])->max)) {
				log_debug("malformed options");
				response->result = PCP_MALFORMED_OPTION;
				goto send;
			}

			/* Create list entry pointing to the option */
			if ((option = calloc(1, sizeof(struct pcp_option))) == NULL) {
				log_debug("no resources");
				response->result = PCP_NO_RESOURCES;
				response->lifetime = PCP_SHORT_LIFETIME;
				goto send;
			}

			option->header = oh;
			(&option->data)->raw = (optlen) ? (u_int8_t *)oh + sizeof(struct pcp_option_header) : NULL;

			log_debug("option %d, length %d", oh->code & 0x7f,
			    ntohs(oh->length));

			TAILQ_INSERT_TAIL(&options, option, entry);

			/* Advance to next option */
			oh += sizeof(struct pcp_option_header) + optlen;
		}
	}

	/* Now that we've sifted out and errored on options we don't support,
	 * iterate over the options we do
	 */
	for (option = TAILQ_FIRST(&options); option;
	    option = TAILQ_NEXT(option, entry))
		switch (option->header->code) {
		case PCP_OPTION_THIRD_PARTY:
			/* Address in option matches the source address */
			if (memcmp(&dst_addr, (&option->data)->addr,
			    sizeof(struct in6_addr)) == 0) {
				response->result = PCP_MALFORMED_REQUEST;
				goto send;
			}

			/* Search through list of trusted addresses */
			for (tp = TAILQ_FIRST(&third_party); tp &&
			    memcmp((&option->data)->addr, &tp->addr,
			    sizeof(struct in6_addr)); tp = TAILQ_NEXT(tp, entry));

			if (tp == NULL) {
				response->result = PCP_UNSUPP_OPTION;
				goto send;
			}

			memcpy(&dst_addr, (&option->data)->addr,
			    sizeof(struct in6_addr));

			break;
		case PCP_OPTION_PREFER_FAILURE:
			flags |= (1 << PCP_OPTION_PREFER_FAILURE);
			break;
		case PCP_OPTION_FILTER:
			/* Invalid prefix length */
			if ((IN6_IS_ADDR_V4MAPPED(&(&option->data)->filter->addr) &&
			    (&option->data)->filter->prefix &&
			    (&option->data)->filter->prefix < 96) ||
			    (&option->data)->filter->prefix > 128) {
				response->result = PCP_MALFORMED_OPTION;
				goto send;
			}

			if ((filter = calloc(1, sizeof(struct pcp_filter))) == NULL) {
				log_debug("no resources");
				response->result = PCP_NO_RESOURCES;
				response->lifetime = PCP_SHORT_LIFETIME;
				goto send;
			}

			filter->prefix = (&option->data)->filter->prefix;
			filter->port = (&option->data)->filter->port;
			memcpy(&filter->addr, &(&option->data)->filter->addr,
			    sizeof(struct in6_addr));

			TAILQ_INSERT_TAIL(&filters, filter, entry);

			break;
		default:
			fatalx("unimplemented option");
			/* NOTREACHED */
		}
	
	switch (request->opcode) {
	case PCP_OPCODE_ANNOUNCE:
		break;
	case PCP_OPCODE_MAP:
		/* Make copies of the things that may get changed */
		memcpy(&src_addr, &map->addr, sizeof(struct in6_addr));
		memcpy(&nonce, &map->nonce, sizeof(nonce));
		src_port = ntohs(map->port[1]);
		lifetime = ntohl(request->lifetime);

		if ((response->result = pcp_map(map->protocol, dst_addr,
		    ntohs(map->port[0]), &src_addr, &src_port, &lifetime,
		    nonce, flags, &filters)) != PCP_SUCCESS)
			goto send;

		/* Success, modify response packet */
		memset(&map->reserved, 0, 3);
		memcpy(&map->addr, &src_addr, sizeof(struct in6_addr));
		memcpy(&map->nonce, &nonce, sizeof(nonce));
		map->port[1] = htons(src_port);
		response->lifetime = htonl(lifetime);

		break;
	case PCP_OPCODE_PEER:
		/* FALLTHROUGH */
	default:
		fatalx("unimplemented opcode");
		/* NOTREACHED */
	}

	if (response->result != PCP_SUCCESS)
		fatalx("error without goto");

	/* Zero out the client IP address */
	memset(&(&response->data)->addr, 0, sizeof(struct in6_addr));

	/* Response length without any options */
	len = opcode;

	/* Append all of the options in the list to the response as we will
	 * have acted upon them
	 */
	while ((option = TAILQ_FIRST(&options))) {
		/* Before copying anything, set any reserved fields to 0 */
		option->header->reserved = 0;
		switch (option->header->code) {
		case PCP_OPTION_FILTER:
			(&option->data)->filter->reserved = 0;
			break;
		default:
			break;
		}

		/* Append option header to response */
		oh = (struct pcp_option_header *)(response_storage + len);
		memcpy(oh, option->header, sizeof(struct pcp_option_header));

		/* Calculate option data length, (rounding up to the nearest
		 * whole 4 octets), and append after option header
		 */
		optlen = (ntohs(oh->length) + 3) & ~0x03;
		memcpy(oh + sizeof(struct pcp_option_header),
		    (&option->data)->raw, optlen);

		/* Increase response length */
		len += sizeof(struct pcp_option_header) + optlen;
		
		TAILQ_REMOVE(&options, option, entry);
		free(option);
	}

send:
	/* Set epoch time */
	(&response->data)->sssoe = htonl(sssoe(env));

	/* Clean up any options */
	while ((option = TAILQ_FIRST(&options))) {
		TAILQ_REMOVE(&options, option, entry);
		free(option);
	}

	/* Clean up any filters */
	while ((filter = TAILQ_FIRST(&filters))) {
		TAILQ_REMOVE(&filters, filter, entry);
		free(filter);
	}

	/* In case of sending back a malformed packet, round up to the nearest
	 * whole 4 octets
	 */
	len = (len + 3) & ~0x03;

	len = sendto(fd, response_storage, len, 0, (struct sockaddr *)sock,
	    SA_LEN((struct sockaddr *)sock));
}

void
check_interface(struct natpmpd *env)
{
	struct ifaddrs	*ifaddr, *ifa;
	struct in6_addr	 addr;
	struct in6_addr  zero = IN6ADDR_V4MAPPED_INIT;

	if (getifaddrs(&ifaddr) == -1)
		fatal("getifaddrs");

	/* Breaks on the first address found on the interface
	 * for the given address family
	 */
	for (ifa = ifaddr; ifa; ifa = ifa->ifa_next)
		/* Interface name & address family matches */
		if (strcmp(ifa->ifa_name, env->sc_interface) == 0
		    && ifa->ifa_addr->sa_family == AF_INET)
			break;

	if (ifa)
		/* Address found */
		switch (ifa->ifa_addr->sa_family) {
		case AF_INET:
			/* Initialise the IPv6 address with the V4 mapped
			 * pattern and then copy the IPv4 address into the
			 * last 4 bytes
			 */
			memcpy(&addr, &zero, sizeof(struct in6_addr));
			memcpy(&addr.s6_addr[12],
			    &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr,
			    sizeof(struct in_addr));
			break;
		case AF_INET6:
			/* FALLTHROUGH */
		default:
			/* NOTREACHED */
			break;
		}
	else
		/* Address not found */
		memcpy(&addr, &zero, sizeof(struct in6_addr));

	/* Primary address hasn't changed */
	if (memcmp(&env->sc_address, &addr, sizeof(struct in6_addr)) == 0)
		goto free;

	memcpy(&env->sc_address, &addr, sizeof(struct in6_addr));

	/* If the address changed again while we were still announcing the
	 * old one, cancel the pending announcement before starting again
	 */
	if (evtimer_pending(&env->sc_announce_ev, NULL))
		evtimer_del(&env->sc_announce_ev);

	/* Don't announce an interface having 0.0.0.0 as an address */
	if (memcmp(&addr, &zero, sizeof(struct in6_addr)) == 0)
		goto free;

	env->sc_delay = 0;
	evtimer_add(&env->sc_announce_ev, &timeouts[env->sc_delay]);

free:
	freeifaddrs(ifaddr);
}

int
main(int argc, char *argv[])
{
	int			 c;
	int			 debug = 0;
	int			 noaction = 0;
	const char		*conffile = CONF_FILE;
	u_int			 flags = 0;
	unsigned char		 loop = 0;
	unsigned int		 loop6 = 0;
	struct passwd		*pw;
	struct event		 rt_ev;
	int			 rt_fd;
	unsigned int		 rtfilter;
	struct natpmpd		*env;
	struct listen_addr	*la;
	struct event		 ev_sighup;
	struct event		 ev_sigint;
	struct event		 ev_sigterm;

	log_init(1);	/* log to stderr until daemonized */

	while ((c = getopt(argc, argv, "df:nv")) != -1) {
		switch (c) {
		case 'd':
			debug = 1;
			break;
		case 'f':
			conffile = optarg;
			break;
		case 'n':
			noaction++;
			break;
		case 'v':
			flags |= NATPMPD_F_VERBOSE;
			break;
		default:
			usage();
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;
	if (argc > 0)
		usage();

	if ((env = parse_config(conffile, flags)) == NULL)
		exit(1);

	/* XXX Check for an interface and at least one address to listen on */

	if (noaction) {
		fprintf(stderr, "configuration ok\n");
		exit(0);
	}

	if (geteuid())
		errx(1, "need root privileges");

	if ((pw = getpwnam(NATPMPD_USER)) == NULL)
		errx(1, "unknown user %s", NATPMPD_USER);

	log_init(debug);

	if (!debug) {
		if (daemon(1, 0) == -1)
			err(1, "failed to daemonize");
	}

	gettimeofday(&env->sc_starttime, NULL);

	/* Create the IPv4 announcement sockaddr used by both NAT-PMP & PCP */
	memset(&all_nodes4, 0, sizeof(all_nodes4));
	(&all_nodes4)->sin_family = AF_INET;
	(&all_nodes4)->sin_len = sizeof(struct sockaddr_in);
	(&all_nodes4)->sin_addr.s_addr = htonl(INADDR_ALLHOSTS_GROUP);
	(&all_nodes4)->sin_port = htons(NATPMPD_CLIENT_PORT);

	/* Create the IPv6 announcement sockaddr used by PCP only */
	memset(&all_nodes6, 0, sizeof(all_nodes6));
	(&all_nodes6)->sin6_family = AF_INET6;
	(&all_nodes6)->sin6_len = sizeof(struct sockaddr_in6);
	memcpy(&(&all_nodes6)->sin6_addr, &all_nodes, sizeof(all_nodes));
	(&all_nodes6)->sin6_port = htons(NATPMPD_CLIENT_PORT);

	/* Initialise the packet filter and clear out our anchor */
	init_filter(NULL, NULL, 0);
	/* Perhaps not fail here and instead return the correct
	 * NATPMP_NOT_AUTHORISED and/or PCP_NOT_AUTHORISED
	 */
	if (rebuild_rules() == -1)
		fatal("rebuild_rules");

	for (la = TAILQ_FIRST(&env->listen_addrs); la; ) {
		switch (la->sa.ss_family) {
		case AF_INET:
			if (((struct sockaddr_in *)&la->sa)->sin_port == 0)
				((struct sockaddr_in *)&la->sa)->sin_port =
				    htons(NATPMPD_SERVER_PORT);
			break;
		case AF_INET6:
			if (((struct sockaddr_in6 *)&la->sa)->sin6_port == 0)
				((struct sockaddr_in6 *)&la->sa)->sin6_port =
				    htons(NATPMPD_SERVER_PORT);
			break;
		default:
			fatalx("king bula sez: af borked");
		}

		log_info("listening on %s:%d",
		    log_sockaddr((struct sockaddr *)&la->sa),
		    NATPMPD_SERVER_PORT);

		if ((la->fd = socket(la->sa.ss_family, SOCK_DGRAM, 0)) == -1)
			fatal("socket");

		if (fcntl(la->fd, F_SETFL, O_NONBLOCK) == -1)
			fatal("fcntl");

		switch (la->sa.ss_family) {
		case AF_INET:
			if (setsockopt(la->fd, IPPROTO_IP, IP_MULTICAST_IF,
			    &(((struct sockaddr_in *)&la->sa)->sin_addr),
			    sizeof(struct in_addr)) == -1)
				fatal("setsockopt");
			if (setsockopt(la->fd, IPPROTO_IP, IP_MULTICAST_LOOP,
			    &loop, sizeof(loop)) == -1)
				fatal("setsockopt");
			break;
		case AF_INET6:
			/* If the scope ID is non-zero, this seems to be the
			 * interface index which is required by the
			 * IPV6_MULTICAST_IF socket option. Skip any address
			 * which doesn't have a non-zero scope ID as otherwise
			 * we can't easily work out which interface to send
			 * the multicast announcements out of?
			 */
			if (setsockopt(la->fd, IPPROTO_IPV6, IPV6_MULTICAST_IF,
			    &((struct sockaddr_in6 *)&la->sa)->sin6_scope_id,
			    sizeof(((struct sockaddr_in6 *)&la->sa)->sin6_scope_id)) == -1)
				fatal("setsockopt");
			if (setsockopt(la->fd, IPPROTO_IPV6,
			    IPV6_MULTICAST_LOOP, &loop6, sizeof(loop6)) == -1)
				fatal("setsockopt");
			break;
		default:
			/* NOTREACHED */
			break;
		}

		if (bind(la->fd, (struct sockaddr *)&la->sa,
		    SA_LEN((struct sockaddr *)&la->sa)) == -1) {
			struct listen_addr	*nla;

			log_warn("bind on %s failed, skipping",
			    log_sockaddr((struct sockaddr *)&la->sa));
			close(la->fd);
			nla = TAILQ_NEXT(la, entry);
			TAILQ_REMOVE(&env->listen_addrs, la, entry);
			free(la);
			la = nla;
			continue;
		}

		la = TAILQ_NEXT(la, entry);
	}

	if ((rt_fd = socket(PF_ROUTE, SOCK_RAW, 0)) < 0)
		fatal("socket");

	/* Hopefully this is enough? */
	rtfilter = ROUTE_FILTER(RTM_NEWADDR) | ROUTE_FILTER(RTM_DELADDR) |
	    ROUTE_FILTER(RTM_IFANNOUNCE);
	if (setsockopt(rt_fd, PF_ROUTE, ROUTE_MSGFILTER,
	    &rtfilter, sizeof(rtfilter)) == -1)
		fatal("setsockopt");

	log_info("startup");

	if (chroot(pw->pw_dir) == -1)
		fatal("chroot");
	if (chdir("/") == -1)
		fatal("chdir(\"/\")");

	if (setgroups(1, &pw->pw_gid) ||
	    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
	    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
		fatal("cannot drop privileges");

	event_init();

	signal(SIGPIPE, SIG_IGN);
	signal_set(&ev_sighup, SIGHUP, handle_signal, env);
	signal_set(&ev_sigint, SIGINT, handle_signal, env);
	signal_set(&ev_sigterm, SIGTERM, handle_signal, env);
	signal_add(&ev_sighup, NULL);
	signal_add(&ev_sigint, NULL);
	signal_add(&ev_sigterm, NULL);

	for (la = TAILQ_FIRST(&env->listen_addrs); la; ) {
		event_set(&la->ev, la->fd, EV_READ|EV_PERSIST,
		    common_handler, env);
		event_add(&la->ev, NULL);
		la = TAILQ_NEXT(la, entry);
	}

	event_set(&rt_ev, rt_fd, EV_READ|EV_PERSIST, route_handler, env);
	event_add(&rt_ev, NULL);

	evtimer_set(&env->sc_announce_ev, announce_address, env);
	check_interface(env);

	event_dispatch();

	return (0);
}
