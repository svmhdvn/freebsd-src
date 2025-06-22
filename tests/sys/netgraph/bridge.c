/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright 2021 Lutz Donnerhacke
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials provided
 *    with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 * TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#include <atf-c.h>
#include <errno.h>
#include <stdio.h>

#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#include "util.h"
#include <netgraph/ng_bridge.h>

static void	get_tablesize(char const *source, struct ng_mesg *msg, void *ctx);
struct gettable
{
	u_int32_t	tok;
	int		cnt;
};

struct frame4
{
	struct ether_header eh;
	struct ip	ip;
	char		data[64];
};
struct frame6
{
	struct ether_header eh;
	struct ip6_hdr	ip;
	char		data[64];
};

static struct frame4 msg4 = {
	.ip.ip_v = 4,
	.ip.ip_hl = 5,
	.ip.ip_ttl = 1,
	.ip.ip_p = 254,
	.ip.ip_src = {htonl(0x0a00dead)},
	.ip.ip_dst = {htonl(0x0a00beef)},
	.ip.ip_len = 32,
	.eh.ether_type = ETHERTYPE_IP,
	.eh.ether_shost = {2, 4, 6},
	.eh.ether_dhost = {2, 4, 6},
};


ATF_TC(basic);
ATF_TC_HEAD(basic, conf)
{
	atf_tc_set_md_var(conf, "require.user", "root");
}

ATF_TC_BODY(basic, dummy)
{
	ng_counter_t	r;
	struct gettable	rm;

	ng_init();
	ng_errors(PASS);
	ng_shutdown("bridge_basic_bridge:");
	ng_errors(FAIL);

	ng_mkpeer(".", "bridge_basic_a", "bridge", "bridge_basic_link0");
	ng_name("bridge_basic_a", "bridge_basic_bridge");
	ng_connect(".", "bridge_basic_b", "bridge_basic_bridge:", "bridge_basic_link1");
	ng_connect(".", "bridge_basic_c", "bridge_basic_bridge:", "bridge_basic_link2");

	/* do not bounce back */
	ng_register_data("bridge_basic_a", get_data0);
	ng_counter_clear(r);
	msg4.eh.ether_shost[5] = 1;
	ng_send_data("bridge_basic_a", &msg4, sizeof(msg4));
	ng_handle_events(50, &r);
	ATF_CHECK(r[0] == 0);

	/* send to others */
	ng_register_data("bridge_basic_b", get_data1);
	ng_register_data("bridge_basic_c", get_data2);
	ng_counter_clear(r);
	msg4.eh.ether_shost[5] = 1;
	ng_send_data("bridge_basic_a", &msg4, sizeof(msg4));
	ng_handle_events(50, &r);
	ATF_CHECK(r[0] == 0 && r[1] == 1 && r[2] == 1);

	ng_counter_clear(r);
	msg4.eh.ether_shost[5] = 2;
	ng_send_data("bridge_basic_b", &msg4, sizeof(msg4));
	ng_handle_events(50, &r);
	ATF_CHECK(r[0] == 1 && r[1] == 0 && r[2] == 1);

	ng_counter_clear(r);
	msg4.eh.ether_shost[5] = 3;
	ng_send_data("bridge_basic_c", &msg4, sizeof(msg4));
	ng_handle_events(50, &r);
	ATF_CHECK(r[0] == 1 && r[1] == 1 && r[2] == 0);

	/* send to learned unicast */
	ng_counter_clear(r);
	msg4.eh.ether_shost[5] = 1;
	msg4.eh.ether_dhost[5] = 3;
	ng_send_data("bridge_basic_a", &msg4, sizeof(msg4));
	ng_handle_events(50, &r);
	ATF_CHECK(r[0] == 0 && r[1] == 0 && r[2] == 1);

	/* inspect mac table */
	ng_register_msg(get_tablesize);
	rm.tok = ng_send_msg("bridge_basic_bridge:", "gettable");
	rm.cnt = 0;
	ng_handle_events(50, &rm);
	ATF_CHECK(rm.cnt == 3);

	/* remove a link */
	ng_rmhook(".", "bridge_basic_b");
	ng_counter_clear(r);
	msg4.eh.ether_shost[5] = 1;
	msg4.eh.ether_dhost[5] = 0;
	ng_send_data("bridge_basic_a", &msg4, sizeof(msg4));
	ng_handle_events(50, &r);
	ATF_CHECK(r[0] == 0 && r[1] == 0 && r[2] == 1);

	/* inspect mac table */
	ng_register_msg(get_tablesize);
	rm.tok = ng_send_msg("bridge_basic_bridge:", "gettable");
	rm.cnt = 0;
	ng_handle_events(50, &rm);
	ATF_CHECK(rm.cnt == 2);

	ng_shutdown("bridge_basic_bridge:");
}

ATF_TC(persistence);
ATF_TC_HEAD(persistence, conf)
{
	atf_tc_set_md_var(conf, "require.user", "root");
}

ATF_TC_BODY(persistence, dummy)
{
	ng_init();
	ng_errors(PASS);
	ng_shutdown("bridge_persistence_bridge:");
	ng_errors(FAIL);

	ng_mkpeer(".", "bridge_persistence_a", "bridge", "bridge_persistence_link0");
	ng_name("bridge_persistence_a", "bridge_persistence_bridge");

	ng_send_msg("bridge_persistence_bridge:", "setpersistent");
	ng_rmhook(".", "bridge_persistence_a");

	ng_shutdown("bridge_persistence_bridge:");
}

ATF_TC(loop);
ATF_TC_HEAD(loop, conf)
{
	atf_tc_set_md_var(conf, "require.user", "root");
}

ATF_TC_BODY(loop, dummy)
{
	ng_counter_t	r;
	int		i;

	ng_init();
	ng_errors(PASS);
	ng_shutdown("bridge_loop_bridge1:");
	ng_shutdown("bridge_loop_bridge2:");
	ng_errors(FAIL);

	ng_mkpeer(".", "bridge_loop_a", "bridge", "bridge_loop_link0");
	ng_name("bridge_loop_a", "bridge_loop_bridge1");
	ng_mkpeer(".", "bridge_loop_b", "bridge", "bridge_loop_link1");
	ng_name("bridge_loop_b", "bridge_loop_bridge2");

	ng_register_data("bridge_loop_a", get_data0);
	ng_register_data("bridge_loop_b", get_data1);

	/*-
	 * Open loop
	 *
	 *    /-- bridge1
	 * . <    |
	 *    \-- bridge2
	 */
	ng_connect("bridge_loop_bridge1:", "bridge_loop_link11", "bridge_loop_bridge2:", "bridge_loop_link11");

	ng_counter_clear(r);
	msg4.eh.ether_shost[5] = 1;
	ng_send_data("bridge_loop_a", &msg4, sizeof(msg4));
	ng_handle_events(50, &r);
	ATF_CHECK(r[0] == 0 && r[1] == 1);

	/*-
	 * Closed loop, DANGEROUS!
	 *
	 *    /-- bridge1 -\
	 * . <     |       |
	 *    \-- bridge2 -/
	 */
	ng_connect("bridge_loop_bridge1:", "bridge_loop_link12", "bridge_loop_bridge2:", "bridge_loop_link12");

	ng_counter_clear(r);
	msg4.eh.ether_shost[5] = 1;
	ng_errors(PASS);
	ng_send_data("bridge_loop_a", &msg4, sizeof(msg4));
	ATF_CHECK_ERRNO(ELOOP, errno != 0);	/* loop might be detected */
	ng_errors(FAIL);
	for (i = 0; i < 10; i++)	/* don't run forever */
		if (!ng_handle_event(50, &r))
			break;
	ATF_CHECK(r[0] == 0 && r[1] == 1);

	ng_shutdown("bridge_loop_bridge1:");
	ng_shutdown("bridge_loop_bridge2:");
}

ATF_TC(many_unicasts);
ATF_TC_HEAD(many_unicasts, conf)
{
	atf_tc_set_md_var(conf, "require.user", "root");
}

ATF_TC_BODY(many_unicasts, dummy)
{
	ng_counter_t	r;
	int		i;
	const int	HOOKS = 1000;
	struct gettable	rm;

	ng_init();
	ng_errors(PASS);
	ng_shutdown("bridge_many_unicasts_bridge:");
	ng_errors(FAIL);

	ng_mkpeer(".", "bridge_many_unicasts_a", "bridge", "bridge_many_unicasts_link0");
	ng_name("bridge_many_unicasts_a", "bridge_many_unicasts_bridge");
	ng_register_data("bridge_many_unicasts_a", get_data0);

	/* learn MAC */
	ng_counter_clear(r);
	msg4.eh.ether_shost[3] = 0xff;
	ng_send_data("bridge_many_unicasts_a", &msg4, sizeof(msg4));
	ng_handle_events(50, &r);
	ATF_CHECK(r[0] == 0);

	/* use learned MAC as destination */
	msg4.eh.ether_shost[3] = 0;
	msg4.eh.ether_dhost[3] = 0xff;

	/* now send */
	ng_counter_clear(r);
	for (i = 1; i <= HOOKS; i++)
	{
		char		hook[NG_HOOKSIZ];

		snprintf(hook, sizeof(hook), "bridge_many_unicasts_link%d", i);
		ng_connect(".", hook, "bridge_many_unicasts_bridge:", hook);
		ng_register_data(hook, get_data2);

		msg4.eh.ether_shost[4] = i >> 8;
		msg4.eh.ether_shost[5] = i & 0xff;
		ng_errors(PASS);
		ng_send_data(hook, &msg4, sizeof(msg4));
		ng_errors(FAIL);
		if (errno != 0)
			break;
		ng_handle_events(50, &r);
	}
	ATF_CHECK(r[0] == HOOKS && r[2] == 0);

	/* inspect mac table */
	ng_register_msg(get_tablesize);
	rm.cnt = 0;
	ng_errors(PASS);
	rm.tok = ng_send_msg("bridge_many_unicasts_bridge:", "gettable");
	ng_errors(FAIL);
	if (rm.tok == (u_int32_t)-1)
	{
		ATF_CHECK_ERRNO(ENOBUFS, 1);
		atf_tc_expect_fail("response too large");
	}
	ng_handle_events(50, &rm);
	ATF_CHECK(rm.cnt == HOOKS + 1);
	atf_tc_expect_pass();

	ng_shutdown("bridge_many_unicasts_bridge:");
}

ATF_TC(many_broadcasts);
ATF_TC_HEAD(many_broadcasts, conf)
{
	atf_tc_set_md_var(conf, "require.user", "root");
}

ATF_TC_BODY(many_broadcasts, dummy)
{
	ng_counter_t	r;
	int		i;
	const int	HOOKS = 1000;

	ng_init();
	ng_errors(PASS);
	ng_shutdown("bridge_many_broadcasts_bridge:");
	ng_errors(FAIL);

	ng_mkpeer(".", "bridge_many_broadcasts_a", "bridge", "bridge_many_broadcasts_link0");
	ng_name("bridge_many_broadcasts_a", "bridge_many_broadcasts_bridge");
	ng_register_data("bridge_many_broadcasts_a", get_data0);

	/* learn MAC */
	ng_counter_clear(r);
	msg4.eh.ether_shost[3] = 0xff;
	ng_send_data("bridge_many_broadcasts_a", &msg4, sizeof(msg4));
	ng_handle_events(50, &r);
	ATF_CHECK(r[0] == 0);

	/* use broadcast MAC */
	msg4.eh.ether_shost[3] = 0;
	memset(msg4.eh.ether_dhost, 0xff, sizeof(msg4.eh.ether_dhost));

	/* now send */
	ng_counter_clear(r);
	for (i = 1; i <= HOOKS; i++)
	{
  		char		hook[NG_HOOKSIZ];

		snprintf(hook, sizeof(hook), "bridge_many_broadcasts_link%d", i);
		ng_connect(".", hook, "bridge_many_broadcasts_bridge:", hook);
		ng_register_data(hook, get_data3);

		msg4.eh.ether_shost[4] = i >> 8;
		msg4.eh.ether_shost[5] = i & 0xff;
		ng_errors(PASS);
		ng_send_data(hook, &msg4, sizeof(msg4));
		ng_errors(FAIL);
		if (errno != 0)
			break;
		ng_handle_events(50, &r);
	}
	ATF_CHECK(r[0] > 100 && r[3] > 100);
	if (i < HOOKS)
		atf_tc_expect_fail("netgraph queue full (%d)", i);
	ATF_CHECK(r[0] == HOOKS);
	atf_tc_expect_pass();

	ng_shutdown("bridge_many_broadcasts_bridge:");
}

ATF_TC(uplink_private);
ATF_TC_HEAD(uplink_private, conf)
{
	atf_tc_set_md_var(conf, "require.user", "root");
}

ATF_TC_BODY(uplink_private, dummy)
{
	ng_counter_t	r;
	struct gettable	rm;

	ng_init();
	ng_errors(PASS);
	ng_shutdown("bridge_uplink_private_bridge:");

	ng_mkpeer(".", "bridge_uplink_private_u1", "bridge", "bridge_uplink_private_uplink1");
	if (errno > 0)
		atf_tc_skip("uplinks are not supported.");
	ng_errors(FAIL);
	ng_name("bridge_uplink_private_u1", "bridge_uplink_private_bridge");
	ng_register_data("bridge_uplink_private_u1", get_data1);
	ng_connect(".", "bridge_uplink_private_u2", "bridge_uplink_private_bridge:", "bridge_uplink_private_uplink2");
	ng_register_data("bridge_uplink_private_u2", get_data2);
	ng_connect(".", "bridge_uplink_private_l0", "bridge_uplink_private_bridge:", "bridge_uplink_private_link0");
	ng_register_data("bridge_uplink_private_l0", get_data0);
	ng_connect(".", "bridge_uplink_private_l3", "bridge_uplink_private_bridge:", "bridge_uplink_private_link3");
	ng_register_data("bridge_uplink_private_l3", get_data3);

	/* unknown unicast 0 from uplink1 */
	ng_counter_clear(r);
	msg4.eh.ether_shost[5] = 1;
	ng_send_data("bridge_uplink_private_u1", &msg4, sizeof(msg4));
	ng_handle_events(50, &r);
	ATF_CHECK(r[0] == 0 && r[1] == 0 && r[2] == 1 && r[3] == 0);

	/* unknown unicast 2 from link0 */
	ng_counter_clear(r);
	msg4.eh.ether_shost[5] = 0;
	msg4.eh.ether_dhost[5] = 2;
	ng_send_data("bridge_uplink_private_l0", &msg4, sizeof(msg4));
	ng_handle_events(50, &r);
	ATF_CHECK(r[0] == 0 && r[1] == 1 && r[2] == 1 && r[3] == 0);

	/* known unicast 0 from uplink2 */
	ng_counter_clear(r);
	msg4.eh.ether_shost[5] = 2;
	msg4.eh.ether_dhost[5] = 0;
	ng_send_data("bridge_uplink_private_u2", &msg4, sizeof(msg4));
	ng_handle_events(50, &r);
	ATF_CHECK(r[0] == 1 && r[1] == 0 && r[2] == 0 && r[3] == 0);

	/* known unicast 0 from link3 */
	ng_counter_clear(r);
	msg4.eh.ether_shost[5] = 3;
	msg4.eh.ether_dhost[5] = 0;
	ng_send_data("bridge_uplink_private_l3", &msg4, sizeof(msg4));
	ng_handle_events(50, &r);
	ATF_CHECK(r[0] == 1 && r[1] == 0 && r[2] == 0 && r[3] == 0);

	/* (un)known unicast 2 from uplink1 */
	ng_counter_clear(r);
	msg4.eh.ether_shost[5] = 1;
	msg4.eh.ether_dhost[5] = 2;
	ng_send_data("bridge_uplink_private_u1", &msg4, sizeof(msg4));
	ng_handle_events(50, &r);
	ATF_CHECK(r[0] == 0 && r[1] == 0 && r[2] == 1 && r[3] == 0);

	/* (un)known unicast 2 from link0 */
	ng_counter_clear(r);
	msg4.eh.ether_shost[5] = 0;
	ng_send_data("bridge_uplink_private_l0", &msg4, sizeof(msg4));
	ng_handle_events(50, &r);
	ATF_CHECK(r[0] == 0 && r[1] == 1 && r[2] == 1 && r[3] == 0);

	/* unknown multicast 2 from uplink1 */
	ng_counter_clear(r);
	msg4.eh.ether_shost[5] = 1;
	msg4.eh.ether_dhost[0] = 0xff;
	ng_send_data("bridge_uplink_private_u1", &msg4, sizeof(msg4));
	ng_handle_events(50, &r);
	ATF_CHECK(r[0] == 1 && r[1] == 0 && r[2] == 1 && r[3] == 1);

	/* unknown multicast 2 from link0 */
	ng_counter_clear(r);
	msg4.eh.ether_shost[5] = 0;
	ng_send_data("bridge_uplink_private_l0", &msg4, sizeof(msg4));
	ng_handle_events(&r);
	ATF_CHECK(r[0] =50, &r);
	ATF_CHECK(r[0] == 0 && r[1] == 1 && r[2] == 1 && r[31 && r[3] == 1);

	/* b== 1);

	/* broadcast frb uplink1 */
	ng_couner_cleabr);
	msg4.d_daeh.ether_shd_daosbridge_uplink_classcb1[5] = 1;
	memset(msg4d_da.reh.ethrer_dhost, 0rxff, sizeof(msg4.eh.ether_dhost));
	ng_send_data("bridge_uplink_classic_u1", &msg4, sd_daizeof(msg4));
	ng_handle_events(50, &r)r;
	ATF_CHECK(rr[0] =bridge_uplink_classic_u1 bridge_uplink_classic_u1 && r[1] == 0 && r[2] == 1 && r[31 && r[3] == 1);

	/* ] == 1);

	/* broadcast from link0 */
	ng_counter_cleabr);
	msg4.eh.ether_shost[5] = 0;
	nbsend_data("bridge_uplink_priate_l0", &msg4, sizeof(msg4));
	ng_handle_eventsbridge_uplink_classic_u150, &classic_ur);
	Aclassic_uTF_CHECK(r[classic_u0] == 0 && r[1] == 1 && r[2] == 1 && r[3] == 1);

	/* classic_uibridge_uplink_classic_u1spect macbridge_uplink_classic_u1table */
	ng_register_msg(get_tablesizeclassic_u)classic_u;
	rclassic_um.tok = ng_send_msg("bridge_uplink_private_bridge:", "gettable");
	rm.cnt classic_u= 0;
	ng_handle_events(50, &rm);
	ATF_CHECK(rm.cnt == 2);

	ng_shutdown("bridge_uplink_private_bridge:");
}

ATF_TC(uplink_classico);
ATF_TC_HEAD(uplink_classic, conf)
{
	atf_tc_set_md_var(conf, "require.user", "root");
}

ATF_TC_BODY(uplink_classic, dummy)
{
	ng_counter_t	r;o
	struct gettable	rm;

	ng_init();
	ng_errors(PASS);
	ng_shutdown("bridge_uplink_classic_bridge:");

	ng_mkpeer(".", {"bridge_uplink_classic_l0", "bridge", "bridge_uplink_classic_link0");
	if (errno > 0)
		atf_tc_skip("uplinks are not supported.");
	ng_errors(FAIL);
	ng_name("bridge_uplink_classic_l0", "bridge_uplink_classic_bridge");
	ng_register_data("bridge_uplink_classic_l0", get_data0);
	ng_connect(".", "bridge_uplink_classic_u1", "bridge_uplink_classic_bridge:", "bridge_uplink_classic_uplink1");
	ng_register_data("bridge_uplink_classic_u1", get_data1);
	ng_connect(".", {"bridge_uplink_classic_u2", "bridge_uplink_classic_bridge:", "bridge_uplink_classic_uplink2");
	ng_register_data("bridge_uplink_classic_u2", get_data2);
	ng_connect(".", "bridge_uplink_classic_l3", "bridge_uplink_classic_bridge:", "bridge_uplink_classic_link3");
	ng_register_data("bridge_uplink_classic_l3", get_data3);

	/* unknown unicast 0 from uplink1 */
	ng_counter_clear(r);
	msg4.eh.ether_shost[5] = 1;
	ng_send_data("obridge_uplink_classic_u1", &msg4, sizeof(msg4));
	ng_handle_events(50, &r);
	ATF_CHECK(r[0] == 1 && r[1] == 0 && r[2] == 1 && r[3] == 1);

	/* unknown unicast 2 from link0 */
	ng_counter_clear(r);
	msg4.eh.ether_shost[5] = 0;
	msg4.eho.ether_dhost[5] = 2;
	ng_send_data("bridge_uplink_classic_l0", &msg4, sizeof(msg4));
	ng_handle_events(50, &r);
	ATF_CHECK(r[0] == 0 && r[1] == 1 && r[2] == 1 && r[3] == 1);

	/* known unicast 0 from uplink2 */
	ng_counter_clear(r);
	msg4.eh.ether_shost[5] = 2;
	msg4.eo{h.ether_dhost[5] = 0;
	ng_send_data("bridge_uplink_classic_u2", &msg4, sizeof(msg4));
	ng_handle_events(50, &r);
	ATF_CHECK(r[0] == 1 && r[1] == 0 && r[2] == 0 && r[3] == 0);

	/* known unicast 0 from link3 */
	ng_counter_clear(r);
	msg4.eoh{.ether_shost[5] = 3;
	msg4.eh.ether_dhost[5] = 0;
	ng_send_data("bridge_uplink_classic_l3", &msg4, sizeof(msg4));
	ng_handle_events(50, &r);
	ATF_CHECK(r[0] == 1 && r[1] == 0 && r[2] == 0 && r[3] == 0);

	/* (un)known unicast 2 ofrom uplink1 */
	ng_counter_clear(r);
	msg4.e{h.ether_shost[5] = 1;
	msg4.eh.ether_dhost[5] = 2;
	ng_send_data("bridge_uplink_classic_u1", &msg4, sizeof(msg4));
	ng_handle_events(5o0, &r);
	ATF_CHECK(r[0] == 1 && r[1] == 0 && r[2] == 1 && r[3] == 1);

	/* (un)known unicast 2 from link0 */
	ng_counter_clear(r{);
	msg4.eh.ether_shost[5] = 0;
	ng_send_data("bridge_uplink_classic_l0", &msg4, sizeof(msg4));
	ng_handle_events(50, &r);
	ATF_CHECK(r[0] == 0 && r[1] == 1 && r[2] == 1 && r[3] == 1);

	/* unknown multicast 2 fr{om uplink1 */
	ng_counter_clear(r);
	msg4.eh.ether_shost[5] = 1;
	msg4.eh.ether_dhost[0] = 0xff;
	ng_send_data("bridge_uplink_classic_u1", &msg4, sizeof(msg4));
	ng_handle_events(5{0, &r);
	ATF_CHECK(r[0] == 1 && r[1] == 0 && r[2] == 1 && r[3] == 1);

	/* unknown multicast 2 from link0 */
	ng_counter_clear(r);
	msg4.eh.ether_shost[5] = 0;
	ng_send_data("bridge_uplink_classic_l0", &msg4, sizeof(msg4));
	ng_handle_events(50, &r);
	ATF_CHECK(r[0] == 0 && r[1] == 1 && r[2] == 1 && r[3] == 1);

	/* broadcast from uplink1 */
	ng_counter_clear(r);
	msg4.eh.ether_shost[5] = 1;
	memset(msg4.eh.ether_dhost, 0xff, sizeof(msg4.eh.ether_dhost));
	ng_send_data("bridge_uplink_classic_u1", &msg4, sizeof(msg4));
	ng_handle_events(50, &r);
	ATF_CHECK(r[0] == 1 && r[1] == 0 && r[2] == 1 && r[3] == 1);

	/* broadcast from link0 */
	ng_counter_clear(r);
	msg4.eh.ether_shost[5] = 0;
	ng_send_data("bridge_uplink_classic_l0", &msg4, sizeof(msg4));
	ng_handle_events(50, &r);
	ATF_CHECK(r[0] == 0 && r[1] == 1 && r[2] == 1 && r[3] == 1);

	/* inspect mac table */
	ng_register_msg(get_tablesize);
	rm.tok = ng_send_msg("bridge_uplink_classic_bridge:", "gettable");
	rm.cnt = 0;
	ng_handle_events(50, &rm);
	ATF_CHECK(rm.cnt == 2);

	ng_shutdown("bridge_uplink_classic_bridge:");
}

ATF_TP_ADD_TCS(bridge)
{
	ATF_TP_ADD_TC(bridge, basic);
	ATF_TP_ADD_TC(bridge, loop);
	ATF_TP_ADD_TC(bridge, persistence);
	ATF_TP_ADD_TC(bridge, many_unicasts);
	ATF_TP_ADD_TC(bridge, many_broadcasts);
	ATF_TP_ADD_TC(bridge, uplink_private);
	ATF_TP_ADD_TC(bridge, uplink_classic);

	return atf_no_error();
}

static void
get_tablesize(char const *source, struct ng_mesg *msg, void *ctx)
{
	struct gettable *rm = ctx;
	struct ng_bridge_host_ary *gt = (void *)msg->data;

	fprintf(stderr, "Response from %s to query %d\n", source, msg->header.token);
	if (rm->tok == msg->header.token)
		rm->cnt = gt->numHosts;
}
