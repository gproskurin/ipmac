/*-
 * Copyright (c) 2010 Gennady Proskurin <gpr@mail.ru>
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/mbuf.h>
#include <sys/errno.h>

#include <sys/tree.h>

#include <net/ethernet.h>
#include <sys/types.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/libkern.h>

#include <netgraph/ng_message.h>
#include <netgraph/netgraph.h>
#include <netgraph/ng_parse.h>

#include "ng_ipmac.h"

static int ng_ipmac_mod_event(module_t mod, int event, void *data);

static ng_constructor_t		ng_ipmac_constructor;
static ng_rcvmsg_t		ng_ipmac_rcvmsg;
static ng_rcvdata_t		ng_ipmac_rcvdata;
static ng_newhook_t		ng_ipmac_newhook;
static ng_disconnect_t		ng_ipmac_disconnect;
static ng_shutdown_t		ng_ipmac_shutdown;


/* all data here stored in network order */
struct ipmac_node {
	in_addr_t		ip;
	struct			ether_addr mac;
	RB_ENTRY(ipmac_node)	link_byip;
};

static int
ip_cmp(struct ipmac_node *n1, struct ipmac_node *n2)
{
	return (n1->ip > n2->ip) ? 1 : (n1->ip < n2->ip ? -1 : 0); // XXX
}

typedef RB_HEAD(ipmac_byip, ipmac_node) tree_byip_t;
RB_PROTOTYPE_STATIC(ipmac_byip, ipmac_node, link_byip, ip_cmp);
RB_GENERATE_STATIC(ipmac_byip, ipmac_node, link_byip, ip_cmp);

struct ng_ipmac_cmdarg_node {
	in_addr_t		ip;
	struct ether_addr	mac;
};

static const struct ng_parse_struct_field ng_ipmac_fields_node[] = {
	{ "ip",		&ng_parse_ipaddr_type	},
	{ "mac",	&ng_parse_enaddr_type	},
	{ NULL }
};

static const struct ng_parse_struct_field ng_ipmac_fields_stat[] = {
	{ "pkt_in",		&ng_parse_uint32_type },
	{ "pkt_match",		&ng_parse_uint32_type },
	{ "pkt_mismatch", 	&ng_parse_uint32_type },
	{ "pkt_notfound",	&ng_parse_uint32_type },
	{ "pkt_unknown",	&ng_parse_uint32_type },
	{ "pkt_out",		&ng_parse_uint32_type },
	{ NULL }
};

static const struct ng_parse_type ng_parse_ipmac_node_struct_type = {
	&ng_parse_struct_type,
	&ng_ipmac_fields_node
};

static const struct ng_parse_type ng_parse_ipmac_stat_struct_type = {
	&ng_parse_struct_type,
	&ng_ipmac_fields_stat
};

struct ng_ipmac_stat {
	u_int32_t	pkt_in;
	u_int32_t	pkt_match;
	u_int32_t	pkt_mismatch;
	u_int32_t	pkt_notfound;
	u_int32_t	pkt_unknown;
	u_int32_t	pkt_out;
};

static void ng_ipmac_init_stat(struct ng_ipmac_stat *sp)
{
	sp->pkt_in = 0;
	sp->pkt_match = 0;
	sp->pkt_mismatch = 0;
	sp->pkt_notfound = 0;
	sp->pkt_unknown = 0;
	sp->pkt_out = 0;
}

struct ng_ipmac_node_private {
	tree_byip_t	tree_byip;
	hook_p		hook_in;
	hook_p		hook_match;
	hook_p		hook_mismatch;
	hook_p		hook_notfound;
	hook_p		hook_unknown;
	hook_p		hook_debug;
	struct ng_ipmac_stat stat;
};
typedef struct ng_ipmac_node_private *priv_p;

static void ng_ipmac_init_private(priv_p p)
{
	RB_INIT(&p->tree_byip);
	p->hook_in = NULL;
	p->hook_match = NULL;
	p->hook_mismatch = NULL;
	p->hook_notfound = NULL;
	p->hook_unknown = NULL;
	p->hook_debug = NULL;
	ng_ipmac_init_stat(&p->stat);
}

// Caller is responsible for locks, if necessary
static void ipmac_clear_trees(priv_p p)
{
	struct ipmac_node *cur = RB_MIN(ipmac_byip, &p->tree_byip);
	while (cur != NULL) {
		struct ipmac_node *next = RB_NEXT(ipmac_byip, &p->tree_byip, cur);
		RB_REMOVE(ipmac_byip, &p->tree_byip, cur);
		free(cur, M_NETGRAPH);
		cur = next;
	}
}

static void ng_ipmac_destroy_private(priv_p p)
{
	ipmac_clear_trees(p);
}

static const struct ng_cmdlist ng_ipmac_cmdlist[] = {
	{
		NGM_IPMAC_COOKIE,
		NGM_IPMAC_ADD,
		"add",
		&ng_parse_ipmac_node_struct_type,
		NULL,
	},
	{
		NGM_IPMAC_COOKIE,
		NGM_IPMAC_STAT,
		"stat",
		NULL,
		&ng_parse_ipmac_stat_struct_type
	},
	{
		NGM_IPMAC_COOKIE,
		NGM_IPMAC_LIST,
		"list",
		NULL,
		&ng_parse_ipmac_node_struct_type,
	},
	{
		NGM_IPMAC_COOKIE,
		NGM_IPMAC_CLEAR,
		"clear",
		NULL,
		NULL,
	},
	{ 0 }
};

static struct ng_type ng_ipmac_typestruct = {
	.version =	NG_ABI_VERSION,
	.name =		NG_IPMAC_NODE_TYPE,
	.mod_event =	ng_ipmac_mod_event,
	.constructor =	ng_ipmac_constructor,
	.rcvmsg =	ng_ipmac_rcvmsg,
	.newhook =	ng_ipmac_newhook,
	.rcvdata =	ng_ipmac_rcvdata,
	.shutdown =	ng_ipmac_shutdown,
	.disconnect =	ng_ipmac_disconnect,
	.cmdlist =	ng_ipmac_cmdlist,
};
NETGRAPH_INIT(ipmac, &ng_ipmac_typestruct);

static int
ng_ipmac_mod_event(module_t mod, int event, void *data)
{
	int error = 0;
	switch (event) {
		case MOD_LOAD:
			break;
		case MOD_UNLOAD:
			break;
		default:
			error = EOPNOTSUPP;
			break;
	}
	return (error);
}

static int
ng_ipmac_constructor(node_p node)
{
	priv_p priv;
	priv = (priv_p) malloc(sizeof(*priv), M_NETGRAPH, M_NOWAIT);
	if (priv==NULL)
		return ENOMEM;
	ng_ipmac_init_private(priv);
	NG_NODE_SET_PRIVATE(node, priv);
	return 0;
}

static int
ng_ipmac_rcvmsg(node_p node, item_p item, hook_p lasthook)
{
	struct ng_mesg *msg;
	int error = 0;
	const priv_p priv = NG_NODE_PRIVATE(node);

	NGI_GET_MSG(item, msg);
	switch (msg->header.cmd) {
		case NGM_IPMAC_ADD: {
			struct ipmac_node *newp;
			struct ng_ipmac_cmdarg_node *mp;
			if (msg->header.arglen != sizeof(struct ng_ipmac_cmdarg_node)) {
				error = EINVAL;
				break;
			}
			newp = (struct ipmac_node*) malloc(sizeof(struct ipmac_node), M_NETGRAPH, M_NOWAIT);
			if (newp==NULL) {
				error = ENOMEM;
				break;
			}
			mp = (struct ng_ipmac_cmdarg_node *) msg->data;

			newp->ip = mp->ip;
			bcopy(&mp->mac, &newp->mac, ETHER_ADDR_LEN);	// XXX byte order?

			if (RB_INSERT(ipmac_byip, &priv->tree_byip, newp) != NULL) {
				// ip already exists
				free(newp, M_NETGRAPH);
				return EEXIST;
			}

			break;
		}
		case NGM_IPMAC_STAT: {
			struct ng_ipmac_stat *p;
			struct ng_mesg *resp;
			NG_MKRESPONSE(resp, msg, sizeof(struct ng_ipmac_stat), M_NOWAIT);
			if (!resp) {
				error = ENOMEM;
				break;
			}
			p = (struct ng_ipmac_stat *) resp->data;
			p->pkt_in 		= priv->stat.pkt_in;
			p->pkt_match		= priv->stat.pkt_match;
			p->pkt_mismatch		= priv->stat.pkt_mismatch;
			p->pkt_notfound		= priv->stat.pkt_notfound;
			p->pkt_unknown		= priv->stat.pkt_unknown;
			p->pkt_out = p->pkt_match + p->pkt_mismatch + p->pkt_notfound + p->pkt_unknown;

			NG_RESPOND_MSG(error, node, item, resp);
			break;
		}
		case NGM_IPMAC_LIST: {
			struct ipmac_node *np;
			if (priv->hook_debug==NULL)
				break;
			RB_FOREACH(np, ipmac_byip, &priv->tree_byip) {
				struct ng_mesg *resp;
				struct ng_ipmac_cmdarg_node *p;
				//NG_MKMESSAGE(resp, NGM_IPMAC_COOKIE, NGM_IPMAC_LIST, sizeof(struct ng_ipmac_cmdarg_node), M_NOWAIT);
				NG_MKRESPONSE(resp, msg, sizeof(struct ng_ipmac_cmdarg_node), M_NOWAIT);
				if (!resp) {
					error = ENOMEM;
					break;
				}
				p = (struct ng_ipmac_cmdarg_node *) resp->data;
				p->ip = np->ip;
				bcopy(&np->mac, &p->mac, ETHER_ADDR_LEN);
				NG_RESPOND_MSG(error, node, item, resp); break; // XXX
				//NG_SEND_MSG_ID(error, node, resp, node->nd_ID, 0);
			}
			break;
		}
		case NGM_IPMAC_CLEAR:
			ipmac_clear_trees(priv);
			break;
		default:
			error = EINVAL;
			break;
	}
	NG_FREE_MSG(msg);
	return error;
}

static int
ng_ipmac_newhook(node_p node, hook_p newhook, const char *name)
{
	const priv_p p = NG_NODE_PRIVATE(node);

	if (!strcmp(name,NG_IPMAC_HOOK_IN) && (p->hook_in==NULL)) {
		p->hook_in = newhook;
		return 0;
	}
	if (!strcmp(name,NG_IPMAC_HOOK_MATCH) && (p->hook_match == NULL)) {
		p->hook_match = newhook;
		return 0;
	}
	if (!strcmp(name,NG_IPMAC_HOOK_MISMATCH) && (p->hook_mismatch == NULL)) {
		p->hook_mismatch = newhook;
		return 0;
	}
	if (!strcmp(name,NG_IPMAC_HOOK_NOTFOUND) && (p->hook_notfound == NULL)) {
		p->hook_notfound = newhook;
		return 0;
	}
	if (!strcmp(name,NG_IPMAC_HOOK_UNKNOWN) && (p->hook_unknown == NULL)) {
		p->hook_unknown = newhook;
		return 0;
	}
	if (!strcmp(name,NG_IPMAC_HOOK_DEBUG) && (p->hook_debug==NULL)) {
		p->hook_debug = newhook;
		return 0;
	}
	return (EINVAL);
}

static int
ng_ipmac_rcvdata(hook_p hook, item_p item)
{
	const node_p node = NG_HOOK_NODE(hook);
	const priv_p priv = NG_NODE_PRIVATE(node);
	struct mbuf *m;
	struct ipmac_node pkt;
	struct ipmac_node const *found_node;
	hook_p hook_out = NULL;
	struct ether_header const *pkt_eh;
	struct ip const *pkt_iph;

	if (hook != priv->hook_in) {
		NG_FREE_ITEM(item);
		return (0);
	}

	NGI_GET_M(item, m);
	++priv->stat.pkt_in;
	m = m_pullup(m, sizeof(struct ether_header) + sizeof(struct ip));
	pkt_eh = mtod(m, struct ether_header*);

	if (pkt_eh==NULL || pkt_eh->ether_type!=htons(ETHERTYPE_IP)) {
		++priv->stat.pkt_unknown;
		hook_out = priv->hook_unknown;
		goto out;
	}

	pkt_iph = (struct ip const *) ((const char*)pkt_eh + sizeof(struct ether_header)); // XXX
	pkt.ip = pkt_iph->ip_src.s_addr;
	//bcopy(&pkt_eh->ether_shost, &pkt.mac.octet, ETHER_ADDR_LEN); // not used

	found_node = RB_FIND(ipmac_byip, &priv->tree_byip, &pkt);

	if (found_node==NULL) {
		++priv->stat.pkt_notfound;
		hook_out = priv->hook_notfound;
		goto out;
	}
	// ip found in tree, compare mac
	if (!bcmp(pkt_eh->ether_shost, found_node->mac.octet, ETHER_ADDR_LEN)) {
		// mac and ip matches
		hook_out = priv->hook_match;
		++priv->stat.pkt_match;
	} else {
		// ip found, but mac does not match
		hook_out = priv->hook_mismatch;
		++priv->stat.pkt_mismatch;
	}

out:
	if (hook_out != NULL) {
		int error;
		NG_FWD_NEW_DATA(error, item, hook_out, m);
		return error;
	} else {
		NG_FREE_ITEM(item);
	}
	return (0);
}

static int
ng_ipmac_shutdown(node_p node)
{
	const priv_p priv = NG_NODE_PRIVATE(node);
	NG_NODE_SET_PRIVATE(node, NULL);
	NG_NODE_UNREF(node);
	ng_ipmac_destroy_private(priv);
	free(priv, M_NETGRAPH);
	return 0;
}

static int
ng_ipmac_disconnect(hook_p hook)
{
	return (EINVAL);
}

/**/
