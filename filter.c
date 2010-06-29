#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <net/if.h>
#include <net/pfvar.h>

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

#include "natpmpd.h"

int add_addr(struct sockaddr *, struct pf_pool *);
int prepare_rule(u_int8_t, struct sockaddr *);

static struct pfioc_rule pfr;
static struct pfioc_trans pft;
static struct pfioc_trans_e pfte;
static int dev, rule_log;
static char *qname, *tagname;

int
add_addr(struct sockaddr *addr, struct pf_pool *pfp)
{
	if (addr->sa_family == AF_INET) {
		memcpy(&pfp->addr.v.a.addr.v4,
		    &((struct sockaddr_in *)addr)->sin_addr.s_addr, 4);
		memset(&pfp->addr.v.a.mask.addr8, 255, 4);
	}
	pfp->addr.type = PF_ADDR_ADDRMASK;
	return (0);
}

int
add_rdr(u_int8_t proto, struct sockaddr *dst, struct sockaddr *rdr)
{
	if (dst->sa_family != rdr->sa_family) {
		errno = EINVAL;
		return (-1);
	}

	if (prepare_rule(proto, dst) == -1)
		return (-1);

	if (add_addr(rdr, &pfr.rule.rdr) == -1)
		return (-1);

	pfr.rule.direction = PF_IN;
	pfr.rule.rdr.proxy_port[0] = ntohs(((struct sockaddr_in *)rdr)->sin_port);
	if (ioctl(dev, DIOCADDRULE, &pfr) == -1)
		return (-1);

	return (0);
}

int
do_commit(void)
{
	if (ioctl(dev, DIOCXCOMMIT, &pft) == -1)
		return (-1);

	return (0);
}

int
do_rollback(void)
{
	if (ioctl(dev, DIOCXROLLBACK, &pft) == -1)
		return (-1);

	return (0);
}

void
init_filter(char *opt_qname, char *opt_tagname, int opt_verbose)
{
	struct pf_status status;

	qname = opt_qname;
	tagname = opt_tagname;

	if (opt_verbose == 1)
		rule_log = PF_LOG;
	else if (opt_verbose == 2)
		rule_log = PF_LOG_ALL;

	dev = open("/dev/pf", O_RDWR);
	if (dev == -1)
		fatal("open /dev/pf");
	if (ioctl(dev, DIOCGETSTATUS, &status) == -1)
		fatal("ioctl");
	if (!status.running)
		fatalx("pf is disabled");
}

int
prepare_commit(void)
{
	memset(&pft, 0, sizeof(pft));
	pft.size = 1;
	pft.esize = sizeof(pfte);
	pft.array = &pfte;

	memset(&pfte, 0, sizeof(pfte));
	strlcpy(pfte.anchor, NATPMPD_ANCHOR, PF_ANCHOR_NAME_SIZE);
	pfte.type = PF_TRANS_RULESET;

	if (ioctl(dev, DIOCXBEGIN, &pft) == -1)
		return (-1);

	return (0);
}


int
prepare_rule(u_int8_t proto, struct sockaddr *dst)
{
	if ((dst->sa_family != AF_INET) ||
	    (proto != IPPROTO_UDP && proto != IPPROTO_TCP)) {
		errno = EPROTONOSUPPORT;
		return (-1);
	}

	memset(&pfr, 0, sizeof(pfr));
	strlcpy(pfr.anchor, NATPMPD_ANCHOR, PF_ANCHOR_NAME_SIZE);

	pfr.ticket = pfte.ticket;

	/* Generic for all rule types. */
	pfr.rule.af = dst->sa_family;
	pfr.rule.proto = proto;
	pfr.rule.src.addr.type = PF_ADDR_ADDRMASK;
	pfr.rule.dst.addr.type = PF_ADDR_ADDRMASK;
	pfr.rule.nat.addr.type = PF_ADDR_NONE;
	pfr.rule.rdr.addr.type = PF_ADDR_NONE;

	/*snprintf(label, PF_RULE_LABEL_SIZE, "%ld", expires);
	strlcpy(pfr.rule.label, label, PF_RULE_LABEL_SIZE);*/

	if (dst->sa_family == AF_INET) {
		memcpy(&pfr.rule.dst.addr.v.a.addr.v4,
		    &((struct sockaddr_in *)dst)->sin_addr.s_addr, 4);
		memset(&pfr.rule.dst.addr.v.a.mask.addr8, 255, 4);
		pfr.rule.dst.port[0] = ((struct sockaddr_in *)dst)->sin_port;
	}
	pfr.rule.dst.port_op = PF_OP_EQ;

	/*
	 * pass [quick] [log] inet proto $proto \
	 *     from $src to $dst port = $_port
	 *     [queue qname] [tag tagname]
	 */
	if (tagname != NULL)
		pfr.rule.action = PF_MATCH;
	else
		pfr.rule.action = PF_PASS;
	pfr.rule.quick = 1;
	pfr.rule.log = rule_log;
	pfr.rule.keep_state = PF_STATE_NORMAL;
	pfr.rule.rtableid = -1;
	if (qname != NULL)
		strlcpy(pfr.rule.qname, qname, sizeof(pfr.rule.qname));
	if (tagname != NULL) {
		pfr.rule.quick = 0;
		strlcpy(pfr.rule.tagname, tagname, sizeof(pfr.rule.tagname));
	}

	return (0);
}
