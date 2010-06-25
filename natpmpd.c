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

#include "natpmpd.h"

__dead void	 usage(void);
void		 announce_address(int, short, void *);
void		 check_interface(struct natpmpd *);

struct natpmpd	 natpmpd_env;

int debugsyslog = 0;

int dev;

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

/* __dead is for lint */
__dead void
usage(void)
{
	extern char	*__progname;

	fprintf(stderr, "usage: %s [-dnv] [-f file]\n", __progname);
	exit(1);
}

/*void
natpmp_parse(struct sockaddr_storage *ss)
{
}*/

void
announce_address(int fd, short event, void *arg)
{
	struct natpmpd		*env = (struct natpmpd *)arg;
	struct sockaddr_in	 sock_w;
	u_int8_t		 packet[NATPMPD_MAX_PACKET_SIZE];
	ssize_t			 len;
	struct timeval		 tv;
	u_int32_t		 sssoe;
	struct listen_addr	*la;

	memset(&sock_w, 0, sizeof(sock_w));
	sock_w.sin_family = AF_INET;
	sock_w.sin_addr.s_addr = htonl(INADDR_ALLHOSTS_GROUP);
	sock_w.sin_port = htons(NATPMPD_CLIENT_PORT);

	memset(&packet, 0, sizeof(packet));
	packet[1] |= 0x80;
	len = 12;

	gettimeofday(&tv, NULL);
	sssoe = htonl(tv.tv_sec - env->sc_starttime.tv_sec);
	memcpy(&packet[4], &sssoe, sizeof(sssoe));
	memcpy(&packet[8], &env->sc_address, 4);

	for (la = TAILQ_FIRST(&env->listen_addrs); la; ) {
		if (sendto(la->fd, packet, len, 0,
		    (struct sockaddr *)&sock_w, sizeof(sock_w)) < 0)
			log_warn("sendto");
		la = TAILQ_NEXT(la, entry);
	}

	env->sc_delay++;

	if (env->sc_delay < NATPMPD_MAX_DELAY)
		evtimer_add(&env->sc_announce_ev, &timeouts[env->sc_delay]);
}

void
rt_handler(int fd, short event, void *arg)
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

void
natpmp_recvmsg(int fd, short event, void *arg)
{
	struct natpmpd *env = (struct natpmpd *)arg;
	struct sockaddr_storage ss;
	u_int8_t packet[NATPMPD_MAX_PACKET_SIZE];
	socklen_t slen;
	ssize_t len;
	u_int8_t version;
	u_int8_t opcode;
	u_int16_t result;
	u_int32_t sssoe;
	struct timeval tv;
	int s;
	struct ifreq ifr;
	struct sockaddr_in *ifaddr;

	slen = sizeof(ss);
	if ((len = recvfrom(fd, packet, sizeof(packet), 0,
	    (struct sockaddr *)&ss, &slen)) < 1 )
		return;

	/* Need at least 2 bytes to be able to do anything useful */
	if (len < 2)
		return;

	version = packet[0];
	opcode = packet[1];
	result = NATPMPD_SUCCESS;

	/* No opcode should be greater than 127 */
	if (opcode & 0x80)
		return;

	packet[1] = opcode | 0x80;

	if (version > NATPMPD_MAX_VERSION) {
		packet[0] = NATPMPD_MAX_VERSION;
		result = NATPMPD_BAD_VERSION;
		len = 4;
	} else if (opcode > 2) {
		result = NATPMPD_BAD_OPCODE;
		len = 4;
	} else {
		gettimeofday(&tv, NULL);
		sssoe = htonl(tv.tv_sec - env->sc_starttime.tv_sec);

		switch (opcode) {
		case 0:
			memset(&ifr, 0, sizeof(struct ifreq));
			strncpy(ifr.ifr_name, env->sc_interface, IF_NAMESIZE);

			if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
				fatal("socket");

			if (ioctl(s, SIOCGIFADDR, &ifr) == -1)
				exit(1);

			ifaddr = (struct sockaddr_in *)&ifr.ifr_addr;
			fprintf(stderr, "According to SIOCGIFADDR device %s has IP %s\n", env->sc_interface, inet_ntoa(ifaddr->sin_addr));
			memcpy(&packet[8], &ifaddr->sin_addr.s_addr, 4);

			close(s);
			len = 12;
			break;
		case 1: // UDP
		case 2: // TCP
			/* XXX Just copy the packet data and say not allowed */
			memcpy(&packet[12], &packet[8], 4);
			memcpy(&packet[8], &packet[4], 4);
			result = NATPMPD_NOT_AUTHORISED;
			len = 16;
			break;
		}

		memcpy(&packet[4], &sssoe, sizeof(sssoe));
	}

	memcpy(&packet[2], &result, sizeof(result));
	
	len = sendto(fd, packet, len, 0, (struct sockaddr *)&ss, slen);
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
	if (env->sc_address == ifaddr->sin_addr.s_addr)
		return;

	/* If the address changed again while we were still announcing the
	 * old one, cancel the pending announcement before starting again
	 */
	if (evtimer_pending(&env->sc_announce_ev, NULL))
		evtimer_del(&env->sc_announce_ev);
	env->sc_address = ifaddr->sin_addr.s_addr;
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

	struct event rt_ev;
	int rt_fd;
	unsigned int rtfilter;
	struct natpmpd *env;
	struct listen_addr *la;
	struct pf_status status;

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
			debugsyslog = 1;
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

	if ((dev = open("/dev/pf", O_RDWR)) == -1)
		fatal("open /dev/pf");
	if (ioctl(dev, DIOCGETSTATUS, &status) == -1)
		fatal("DIOCGETSTATUS");
	if (!status.running)
		fatalx("pf is disabled");

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

		log_info("listening on %s",
		    log_sockaddr((struct sockaddr *)&la->sa));

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

	log_init(debug);

	gettimeofday(&env->sc_starttime, NULL);

	log_info("startup");

	event_init();

	for (la = TAILQ_FIRST(&env->listen_addrs); la; ) {
		event_set(&la->ev, la->fd, EV_READ|EV_PERSIST, natpmp_recvmsg, env);
		event_add(&la->ev, NULL);
		la = TAILQ_NEXT(la, entry);
	}

	event_set(&rt_ev, rt_fd, EV_READ|EV_PERSIST, rt_handler, env);
	event_add(&rt_ev, NULL);

	//env->sc_delay = 0;

	evtimer_set(&env->sc_announce_ev, announce_address, env);
	check_interface(env);

	event_dispatch();

	return (0);
}
