/*	$Id$ */

/*
 * Copyright (c) 2010 Matt Dainty <matt@bodgit-n-scarper.com>
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
#include <sys/ioctl.h>

#include <netinet/in.h>

#include <net/if.h>
#include <net/route.h>
#include <net/pfvar.h>

#include <arpa/inet.h>

#include <stdio.h>
#include <netdb.h>
#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <unistd.h>
#include <assert.h>

#include "natpmpd.h"

__dead void	 usage(void);
struct mapping	*init_mapping(void);
void		 expire_mapping(int, short, void *);
void		 announce_address(int, short, void *);
void		 route_handler(int, short, void *);
int		 natpmp_remove_mapping(u_int8_t, struct sockaddr_in *);
int		 natpmp_create_mapping(u_int8_t, struct sockaddr_in *,
		     struct sockaddr_in *, u_int32_t);
ssize_t		 natpmp_mapping(u_int8_t *, u_int8_t, struct sockaddr_in *,
		     struct sockaddr_in *, u_int32_t, struct natpmpd *);
void		 natpmp_handler(int, short, void *);
void		 check_interface(struct natpmpd *);
int		 rebuild_rules(void);
u_int32_t	 sssoe(struct natpmpd *);
ssize_t		 natpmp_address_packet(u_int8_t *, struct natpmpd *);
ssize_t		 natpmp_error_packet(u_int8_t *, u_int8_t, u_int16_t);

struct natpmpd	 natpmpd_env;

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

struct mapping {
	u_int32_t		 proto;
	struct sockaddr		 dst;
	struct sockaddr		 rdr;
	struct event		 ev;
	LIST_ENTRY(mapping)	 entry;
};

struct natpmp_request {
	u_int8_t		 version;
	u_int8_t		 opcode;
	/* The following only appears in mapping requests */
	u_int16_t		 reserved;
	u_int16_t		 port[2];
	u_int32_t		 lifetime;
};

LIST_HEAD(, mapping) mappings = LIST_HEAD_INITIALIZER(mappings);

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
	struct mapping *m;

	if ((m = calloc(1, sizeof(struct mapping))) == NULL)
		return (NULL);

	LIST_INSERT_HEAD(&mappings, m, entry);

	return (m);
}

void
expire_mapping(int fd, short event, void *arg)
{
	struct mapping *m = (struct mapping *)arg;

	log_info("expiring mapping");

	/*
	 * TODO Draft says we should send TCP RST packets to both client and
	 *      remote peer in the case of any active states when this expiry
	 *      event fires.  How hard is that to do with pf?
	 */

	LIST_REMOVE(m, entry);
	free(m);

	if (rebuild_rules() == -1)
		log_warn("unable to rebuild ruleset");
}

int
rebuild_rules(void)
{
	struct mapping *m;

	if (prepare_commit() == -1)
		goto fail;
	for (m = LIST_FIRST(&mappings); m != NULL; m = LIST_NEXT(m, entry))
		if (add_rdr(m->proto, &m->dst, &m->rdr) == -1)
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

ssize_t
natpmp_address_packet(u_int8_t *packet, struct natpmpd *env)
{
	struct natpmp_response {
		u_int8_t	 version;
		u_int8_t	 opcode;
		u_int16_t	 result;
		u_int32_t	 sssoe;
		u_int32_t	 address;
	};
	struct natpmp_response	*r;

	assert(sizeof(struct natpmp_response) <= NATPMPD_MAX_PACKET_SIZE);
	r = (struct natpmp_response *)packet;
	memset(r, 0, sizeof(struct natpmp_response));

	r->version = NATPMPD_MAX_VERSION;
	r->opcode = 0x80;
	r->result = NATPMPD_SUCCESS;
	r->sssoe = htonl(sssoe(env));
	r->address = env->sc_address.s_addr;

	return (sizeof(struct natpmp_response));
}

ssize_t
natpmp_error_packet(u_int8_t *packet, u_int8_t opcode, u_int16_t result)
{
	struct natpmp_response {
		u_int8_t	 version;
		u_int8_t	 opcode;
		u_int16_t	 result;
	};
	struct natpmp_response	*r;

	assert(sizeof(struct natpmp_response) <= NATPMPD_MAX_PACKET_SIZE);
	r = (struct natpmp_response *)packet;
	memset(r, 0, sizeof(struct natpmp_response));

	r->version = NATPMPD_MAX_VERSION;
	r->opcode = opcode | 0x80;
	r->result = result;

	return (sizeof(struct natpmp_response));
}

void
announce_address(int fd, short event, void *arg)
{
	struct natpmpd		*env = (struct natpmpd *)arg;
	struct sockaddr_in	 sock;
	u_int8_t		 packet[NATPMPD_MAX_PACKET_SIZE];
	ssize_t			 len;
	struct listen_addr	*la;

	/* Sending to 224.0.0.1:5350 */
	memset(&sock, 0, sizeof(sock));
	sock.sin_family = AF_INET;
	sock.sin_addr.s_addr = htonl(INADDR_ALLHOSTS_GROUP);
	sock.sin_port = htons(NATPMPD_CLIENT_PORT);

	/* Create the address announce packet */
	len = natpmp_address_packet(packet, env);

	/* Loop through all of our listening addresses and send the packet */
	for (la = TAILQ_FIRST(&env->listen_addrs); la;
	    la = TAILQ_NEXT(la, entry)) {
		if (sendto(la->fd, packet, len, 0,
		    (struct sockaddr *)&sock, sizeof(sock)) < 0)
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
	struct natpmpd		*env = (struct natpmpd *)arg;
	char			 msg[2048];
	struct rt_msghdr	*rtm = (struct rt_msghdr *)&msg;
	ssize_t			 len;

	len = read(fd, msg, sizeof(msg));

	if (rtm->rtm_version != RTM_VERSION)
		return;
	if (rtm->rtm_type != RTM_NEWADDR)
		return;

	check_interface(env);
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
		    (memcmp(&m->rdr, rdr, sizeof(m->rdr)) == 0))
			r = m;
		if ((m->proto == proto) &&
		    (memcmp(&m->rdr, rdr, sizeof(m->rdr)) == 0))
			break;
	}

	if (m != NULL) {
		/*
		 * Update the requested external port from the live mapping 
		 * if it differs.
		 */
		if (memcmp(&m->dst, dst, sizeof(m->dst)) != 0) {
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
	memcpy(&m->dst, dst, sizeof(m->dst));
	memcpy(&m->rdr, rdr, sizeof(m->rdr));

	evtimer_set(&m->ev, expire_mapping, m);
	evtimer_add(&m->ev, &tv);

	return (1);
}

ssize_t
natpmp_mapping(u_int8_t *packet, u_int8_t proto, struct sockaddr_in *rdr,
    struct sockaddr_in *dst, u_int32_t lifetime, struct natpmpd *env)
{
	struct natpmp_response {
		u_int8_t		 version;
		u_int8_t		 opcode;
		u_int16_t		 result;
		u_int32_t		 sssoe;
		u_int16_t		 port[2];
		u_int32_t		 lifetime;
	};
	struct natpmp_response		*r;
	int				 count;
	char				 rdr_ip[INET_ADDRSTRLEN];
	char				 dst_ip[INET_ADDRSTRLEN];

	assert(sizeof(struct natpmp_response) <= NATPMPD_MAX_PACKET_SIZE);
	r = (struct natpmp_response *)packet;
	memset(r, 0, sizeof(struct natpmp_response));

	inet_ntop(AF_INET, &rdr->sin_addr, rdr_ip, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &dst->sin_addr, dst_ip, INET_ADDRSTRLEN);

	r->version = NATPMPD_MAX_VERSION;
	r->opcode = (proto == IPPROTO_UDP) ? 0x81 : 0x82;
	r->result = NATPMPD_SUCCESS;
	r->sssoe = htonl(sssoe(env));

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

			r->port[0] = rdr->sin_port;
			r->port[1] = dst->sin_port;
			r->lifetime = lifetime;
		} else {
			/* Delete single mapping */
			count = natpmp_remove_mapping(proto, rdr);

			if (count > 1)
				log_warn("%d mappings removed", count);
			else
				log_info("mapping removed");

			r->port[0] = rdr->sin_port;
			r->port[1] = 0;
			r->lifetime = 0;
		}
	} else {
		/* Delete all mappings */
		count = natpmp_remove_mapping(proto, rdr);

		log_info("%d mappings removed", count);

		r->port[0] = 0;
		r->port[1] = 0;
		r->lifetime = 0;
	}

	if (count)
		if (rebuild_rules() == -1)
			log_warn("unable to rebuild ruleset");

	return (sizeof(struct natpmp_response));
}

void
natpmp_handler(int fd, short event, void *arg)
{
	struct natpmpd		*env = (struct natpmpd *)arg;
	struct sockaddr_storage	 ss;
	u_int8_t		 request_storage[NATPMPD_MAX_PACKET_SIZE];
	u_int8_t		 response_storage[NATPMPD_MAX_PACKET_SIZE];
	struct natpmp_request	*request;
	socklen_t		 slen;
	ssize_t			 len;
	struct sockaddr_in	 dst;
	struct sockaddr_in	 rdr;
	u_int8_t		 proto;

	slen = sizeof(ss);
	if ((len = recvfrom(fd, request_storage, sizeof(request_storage), 0,
	    (struct sockaddr *)&ss, &slen)) < 1 )
		return;

	/* Need at least 2 bytes to be able to do anything useful */
	if (len < 2)
		return;

	assert(sizeof(struct natpmp_request) <= NATPMPD_MAX_PACKET_SIZE);

	request = (struct natpmp_request *)&request_storage;

	/* No opcode in a request should be greater than 127 */
	if (request->opcode & 0x80)
		return;

	if (request->version > NATPMPD_MAX_VERSION) {
		len = natpmp_error_packet(response_storage, request->opcode,
		    NATPMPD_BAD_VERSION);
		len = sendto(fd, response_storage, len, 0, (struct sockaddr *)&ss, slen);
		return;
	}

	proto = 0;
	switch (request->opcode) {
	case 0:
		len = natpmp_address_packet(response_storage, env);
		break;
	case 1:
		proto = IPPROTO_UDP;
		/* FALLTHROUGH */
	case 2:
		if (proto == 0)
			proto = IPPROTO_TCP;

		memcpy(&rdr, &ss, sizeof(rdr));
		memcpy(&rdr.sin_port, &request->port[0], sizeof(u_int16_t));

		memset(&dst, 0, sizeof(dst));
		dst.sin_family = AF_INET;
		dst.sin_addr = env->sc_address;
		memcpy(&dst.sin_port, &request->port[1], sizeof(u_int16_t));

		len = natpmp_mapping(response_storage, proto, &rdr, &dst,
		    request->lifetime, env);
		break;
	default:
		len = natpmp_error_packet(response_storage, request->opcode,
		    NATPMPD_BAD_OPCODE);
		break;
	}

	len = sendto(fd, response_storage, len, 0, (struct sockaddr *)&ss, slen);
}

void
check_interface(struct natpmpd *env)
{
	struct sockaddr_in	*ifaddr;
	struct ifreq		 ifr;
	int			 s;

	memset(&ifr, 0, sizeof(struct ifreq));
	strncpy(ifr.ifr_name, env->sc_interface, IF_NAMESIZE);

	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		fatal("socket");

	if (ioctl(s, SIOCGIFADDR, &ifr) == -1)
		fatal("ioctl");

	close(s);

	if (ifr.ifr_addr.sa_family != AF_INET)
		return;
	ifaddr = (struct sockaddr_in *)&ifr.ifr_addr;

	/* Primary address hasn't changed */
	if (memcmp(&env->sc_address, &ifaddr->sin_addr,
	    sizeof(struct in_addr)) == 0)
		return;

	memcpy(&env->sc_address, &ifaddr->sin_addr, sizeof(struct in_addr));

	/* If the address changed again while we were still announcing the
	 * old one, cancel the pending announcement before starting again
	 */
	if (evtimer_pending(&env->sc_announce_ev, NULL))
		evtimer_del(&env->sc_announce_ev);
	env->sc_delay = 0;
	evtimer_add(&env->sc_announce_ev, &timeouts[env->sc_delay]);
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
	struct passwd		*pw;

	struct event rt_ev;
	int rt_fd;
	unsigned int rtfilter;
	struct natpmpd *env;
	struct listen_addr *la;

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

	/* Initialise the packet filter and clear out our anchor */
	init_filter(NULL, NULL, 0);
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

		if (setsockopt(la->fd, IPPROTO_IP, IP_MULTICAST_IF,
		    &(((struct sockaddr_in *)&la->sa)->sin_addr),
		    sizeof(struct in_addr)) == -1)
			fatal("setsockopt");

		if (setsockopt(la->fd, IPPROTO_IP, IP_MULTICAST_LOOP,
		    &loop, sizeof(loop)) == -1)
			fatal("setsockopt");

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
	rtfilter = ROUTE_FILTER(RTM_NEWADDR);
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

	for (la = TAILQ_FIRST(&env->listen_addrs); la; ) {
		event_set(&la->ev, la->fd, EV_READ|EV_PERSIST,
		    natpmp_handler, env);
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
