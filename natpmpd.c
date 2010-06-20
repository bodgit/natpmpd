#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <netinet/in.h>

#include <net/if.h>
#include <net/route.h>

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

struct natpmpd	 natpmpd_env;

struct event blurt_ev;
int s;
int debugsyslog = 0;

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

/* Need external interface to track address changes and address to listen on */
//#define ETHERNET_DEVICE "vic0"
#define ETHERNET_DEVICE "lo0"
#define LISTEN_ON "192.168.138.128"

/* __dead is for lint */
__dead void
usage(void)
{
	extern char	*__progname;

	fprintf(stderr, "usage: %s [-dnv] [-f file]\n", __progname);
	exit(1);
}

void
natpmp_parse(struct sockaddr_storage *ss)
{
}

void
blurt_address(int fd, short event, void *arg)
{
	struct natpmpd *env = (struct natpmpd *)arg;
	struct sockaddr_in sock_w;
	u_int8_t packet[NATPMPD_MAX_PACKET_SIZE];
	ssize_t len;
	struct timeval tv;
	u_int32_t sssoe;
	struct ifreq ifr;
	struct sockaddr_in *ifaddr;

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

	memset(&ifr, 0, sizeof(struct ifreq));
	strncpy(ifr.ifr_name, ETHERNET_DEVICE, IF_NAMESIZE);

	if (ioctl(s, SIOCGIFADDR, &ifr) == -1)
		exit(1);

	ifaddr = (struct sockaddr_in *)&ifr.ifr_addr;
	fprintf(stderr, "According to SIOCGIFADDR device %s has IP %s\n", ETHERNET_DEVICE, inet_ntoa(ifaddr->sin_addr));
	memcpy(&packet[8], &ifaddr->sin_addr.s_addr, 4);

	if (sendto(s, packet, len, 0, (struct sockaddr *)&sock_w, sizeof(sock_w)) < 0) {
		fprintf(stderr, "%d\n", errno);
		return;
	}

	/* Use INADDR_ALLHOSTS_GROUP:NATPMPD_CLIENT_PORT */
	//fprintf(stderr, "Announcement #%d to %s:%d\n", env->sc_delay, inet_ntoa(ntohl(INADDR_ALLHOSTS_GROUP)), NATPMPD_CLIENT_PORT);

	env->sc_delay++;

	if (env->sc_delay < NATPMPD_MAX_DELAY)
		evtimer_add(&blurt_ev, &timeouts[env->sc_delay]);
}

void
rt_handler(int fd, short event, void *arg)
{
	char msg[2048];
	struct rt_msghdr *rtm = (struct rt_msghdr *)&msg;
	struct if_msghdr ifm;
	ssize_t len;

	fprintf(stderr, "Routing whoop\n");

	len = read(fd, msg, sizeof(msg));

	if (len < (ssize_t)sizeof(struct rt_msghdr))
		return;

	if (rtm->rtm_version != RTM_VERSION)
		return;

	if (rtm->rtm_type != RTM_IFINFO)
		return;

	memcpy(&ifm, rtm, sizeof(ifm));
}

void
natpmp_recvmsg(int fd, short event, void *arg)
{
	struct sockaddr_storage ss;
	u_int8_t packet[NATPMPD_MAX_PACKET_SIZE];
	socklen_t slen;
	ssize_t len;
	u_int8_t version;
	u_int8_t opcode;
	u_int16_t result;

	slen = sizeof(ss);
	if ((len = recvfrom(fd, packet, sizeof(packet), 0,
	    (struct sockaddr *)&ss, &slen)) < 1 )
		return;

	fprintf(stderr, "Whoop, received %d byte(s)\n", (int)len);

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
	} else {
		switch (opcode) {
		case 0:
			break;
		case 1: /* UDP */
		case 2: /* TCP */
			break;
		default:
			result = NATPMPD_BAD_OPCODE;
			len = 4;
			break;
		}
	}
	
	len = sendto(fd, packet, len, 0, (struct sockaddr *)&ss, slen);
}

/*int
natpmp_bind(struct address *addr)
{
}*/

int
main(int argc, char *argv[])
{
	int			 c;
	int			 debug = 0;
	int			 noaction = 0;
	const char		*conffile = CONF_FILE;
	u_int			 flags = 0;

	int status;
	struct addrinfo hints;
	struct addrinfo *servinfo;
	struct event ev, rt_ev;
	int rt_fd;
	unsigned int rtfilter;
	struct natpmpd *env;

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

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;

	if ((status = getaddrinfo(LISTEN_ON, NATPMPD_SERVER_PORT, &hints, &servinfo)) != 0 ) {
		fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
		exit(1);
	}

	if ((s = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol)) == -1) {
		fprintf(stderr, "socket error: %s\n", gai_strerror(errno));
		exit(1);
	}

	if (fcntl(s, F_SETFL, O_NONBLOCK) == -1) {
		fprintf(stderr, "fcntl error: %s\n", gai_strerror(errno));
		exit(1);
	}

	if (bind(s, servinfo->ai_addr, servinfo->ai_addrlen) == -1) {
		fprintf(stderr, "bind error: %s\n", gai_strerror(errno));
		exit(1);
	}

	freeaddrinfo(servinfo);

	if ((rt_fd = socket(PF_ROUTE, SOCK_RAW, 0)) < 0)
		err(1, "no routing socket");

	rtfilter = ROUTE_FILTER(RTM_IFINFO);
	setsockopt(rt_fd, PF_ROUTE, ROUTE_MSGFILTER,
	    &rtfilter, sizeof(rtfilter));

	env = &natpmpd_env;
	env->sc_delay = 0;

	log_init(debug);

	gettimeofday(&env->sc_starttime, NULL);

	log_info("startup");

	event_init();

	event_set(&ev, s, EV_READ|EV_PERSIST, natpmp_recvmsg, env);
	event_add(&ev, NULL);

	event_set(&rt_ev, rt_fd, EV_READ|EV_PERSIST, rt_handler, env);
	event_add(&rt_ev, NULL);

	evtimer_set(&blurt_ev, blurt_address, env);
	evtimer_add(&blurt_ev, &timeouts[0]);

	event_dispatch();

	return (0);
}
