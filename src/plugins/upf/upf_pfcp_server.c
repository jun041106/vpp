/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/** @file
    udp upf_pfcp server
*/

#define _LGPL_SOURCE            /* LGPL v3.0 is compatible with Apache 2.0 */
#include <urcu-qsbr.h>          /* QSBR RCU flavor */

#include <math.h>

#include <vnet/ip/ip.h>
#include <vnet/udp/udp.h>
#include <vnet/session/session.h>
#include <vnet/session/application_interface.h>

#include <vppinfra/bihash_vec8_8.h>
#include <vppinfra/bihash_template.h>

#include <vppinfra/bihash_template.c>

#include "upf_pfcp.h"
#include "upf_pfcp_api.h"
#include "upf_pfcp_server.h"

#if CLIB_DEBUG > 0
#define gtp_debug clib_warning
#else
#define gtp_debug(...)				\
  do { } while (0)
#endif

typedef enum
{
  EVENT_RX = 1,
  EVENT_NOTIFY,
  EVENT_URR,
} sx_process_event_t;

static vlib_node_registration_t sx_api_process_node;

sx_server_main_t sx_server_main;

#define MAX_HDRS_LEN    100	/* Max number of bytes for headers */

void upf_pfcp_send_data (sx_msg_t * msg)
{
  vlib_main_t *vm = vlib_get_main ();
  vlib_buffer_free_list_t *fl;
  vlib_buffer_t *b0 = 0;
  u32 to_node_index;
  vlib_frame_t *f;
  u32 bi0 = ~0;
  u32 *to_next;
  u8 * data0;

  if (vlib_buffer_alloc (vm, &bi0, 1) != 1)
    {
      clib_warning ("can't allocate buffer for Sx send event");
      return;
    }

  b0 = vlib_get_buffer (vm, bi0);
  fl =
    vlib_buffer_get_free_list (vm, VLIB_BUFFER_DEFAULT_FREE_LIST_INDEX);
  vlib_buffer_init_for_free_list (b0, fl);
  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b0);

  b0->error = 0;
  b0->flags = VNET_BUFFER_F_LOCALLY_ORIGINATED;
  b0->current_data = 0;
  b0->total_length_not_including_first_buffer = 0;

  data0 = vlib_buffer_make_headroom (b0, MAX_HDRS_LEN);
  clib_memcpy(data0, msg->data, _vec_len(msg->data));
  b0->current_length = _vec_len(msg->data);

  vlib_buffer_push_udp (b0, msg->lcl.port, msg->rmt.port, 1);
  if (ip46_address_is_ip4(&msg->rmt.address))
    {
      vlib_buffer_push_ip4 (vm, b0, &msg->lcl.address.ip4, &msg->rmt.address.ip4,
			    IP_PROTOCOL_UDP, 1);
      to_node_index = ip4_lookup_node.index;
    }
  else
    {
      ip6_header_t *ih;
      ih = vlib_buffer_push_ip6 (vm, b0, &msg->lcl.address.ip6, &msg->rmt.address.ip6,
				 IP_PROTOCOL_UDP);
      vnet_buffer (b0)->l3_hdr_offset = (u8 *) ih - b0->data;
      to_node_index = ip6_lookup_node.index;
    }

  vnet_buffer (b0)->sw_if_index[VLIB_RX] = 0;
  vnet_buffer (b0)->sw_if_index[VLIB_TX] = msg->fib_index;

  f = vlib_get_frame_to_node (vm, to_node_index);
  to_next = vlib_frame_vector_args (f);
  to_next[0] = bi0;
  f->n_vectors = 1;

  vlib_put_frame_to_node (vm, to_node_index, f);
}

always_inline void sx_msg_free (sx_server_main_t *sxsm, sx_msg_t * m)
{
  if (!m)
    return;

  vec_free(m->data);
  pool_put (sxsm->msg_pool, m);
}

static int encode_sx_msg(upf_session_t * sx, u8 type, struct pfcp_group * grp, sx_msg_t * msg)
{
  sx_server_main_t *sxs = &sx_server_main;
  int r = 0;

  memset (msg, 0, sizeof (*msg));

  msg->seq_no = clib_smp_atomic_add(&sxs->seq_no, 1) % 0x1000000;
  msg->data = vec_new(u8, 2048);

  msg->hdr->version = 1;
  msg->hdr->s_flag = 1;
  msg->hdr->type = type;

  msg->hdr->session_hdr.seid = clib_host_to_net_u64(sx->cp_seid);
  msg->hdr->session_hdr.sequence[0] = (msg->seq_no >> 16) & 0xff;
  msg->hdr->session_hdr.sequence[1] = (msg->seq_no >>  8) & 0xff;
  msg->hdr->session_hdr.sequence[2] = msg->seq_no & 0xff;

  _vec_len(msg->data) = offsetof(pfcp_header_t, session_hdr.ies);

  r = pfcp_encode_msg(type, grp, &msg->data);
  if (r != 0)
    {
      vec_free(msg->data);
      return r;
    }

  msg->hdr->length = clib_host_to_net_u16(_vec_len(msg->data) - 4);

  msg->fib_index = sx->fib_index,
  msg->lcl.address = sx->up_address;
  msg->rmt.address = sx->cp_address;
  msg->lcl.port = clib_host_to_net_u16 (UDP_DST_PORT_SX);
  msg->rmt.port = clib_host_to_net_u16 (UDP_DST_PORT_SX);

  clib_warning("PFCP Msg no VRF %d from %U:%d to %U:%d\n",
	       msg->fib_index,
	       format_ip46_address, &msg->lcl.address, IP46_TYPE_ANY,
	       clib_net_to_host_u16 (msg->lcl.port),
	       format_ip46_address, &msg->rmt.address, IP46_TYPE_ANY,
	       clib_net_to_host_u16 (msg->rmt.port));

  clib_warning("PFCP Msg no VRF %d from %U:%d to %U:%d\n",
	       msg->fib_index,
	       format_ip46_address, &sx->up_address, IP46_TYPE_ANY,
	       clib_net_to_host_u16 (msg->lcl.port),
	       format_ip46_address, &sx->cp_address, IP46_TYPE_ANY,
	       clib_net_to_host_u16 (msg->rmt.port));

  return 0;
}

static int upf_pfcp_server_rx_msg(sx_msg_t * msg)
{
  int len = vec_len(msg->data);
  u8 * seq_no;

  if (len < 4)
    return -1;

  gtp_debug ("%U", format_pfcp_msg_hdr, msg->hdr);

  if (msg->hdr->version != 1)
    {
      sx_msg_t * resp = NULL;

      gtp_debug ("PFCP: msg version invalid: %d.", msg->hdr->version);

      resp = upf_pfcp_make_response(msg, sizeof(pfcp_header_t));

      resp->hdr->version = 1;
      resp->hdr->type = PFCP_VERSION_NOT_SUPPORTED_RESPONSE;
      resp->hdr->length = clib_host_to_net_u16(offsetof(pfcp_header_t, msg_hdr.ies) - 4);
      _vec_len(resp->data) = offsetof(pfcp_header_t, msg_hdr.ies);

      upf_pfcp_send_data(resp);
      return 0;
  }

  if (len != (clib_net_to_host_u16(msg->hdr->length) + 4) ||
      (!msg->hdr->s_flag && len < offsetof(pfcp_header_t, msg_hdr.ies)) ||
      (msg->hdr->s_flag && len < offsetof(pfcp_header_t, session_hdr.ies)))
    {
      gtp_debug ("PFCP: msg length invalid, data %d, msg %d.",
		    len, clib_net_to_host_u16(msg->hdr->length));
      return -1;
    }

  seq_no = (msg->hdr->s_flag) ?
    &msg->hdr->session_hdr.sequence[0] : &msg->hdr->msg_hdr.sequence[0];
  msg->seq_no = (seq_no[0] << 16) |  (seq_no[1] << 8) |  seq_no[2];

  /* TODO: duplicate message detection, resent last reply */

  upf_pfcp_handle_msg(msg);

  return 0;
}

static sx_msg_t * build_sx_msg(upf_session_t * sx, u8 type, struct pfcp_group * grp)
{
  sx_server_main_t *sxsm = &sx_server_main;
  sx_msg_t * msg;
  int r = 0;

  pool_get_aligned (sxsm->msg_pool, msg, CLIB_CACHE_LINE_BYTES);
  memset (msg, 0, sizeof (*msg));

  if ((r = encode_sx_msg(sx, type, grp, msg)) != 0)
    {
      pool_put (sxsm->msg_pool, msg);
      return NULL;
    }

  return msg;
}

int upf_pfcp_send_request(upf_session_t * sx, u8 type, struct pfcp_group *grp)
{
  sx_server_main_t *sxsm = &sx_server_main;
  vlib_main_t *vm = sxsm->vlib_main;
  sx_msg_t * msg;
  int r = -1;

  msg = clib_mem_alloc_no_fail(sizeof(*msg));
  if (msg)
    {
      if ((r = encode_sx_msg(sx, type, grp, msg)) != 0)
	{
	  clib_mem_free(msg);
	  goto out_free;
	}

      gtp_debug ("sending NOTIFY event %p", msg);
      vlib_process_signal_event_mt(vm, sx_api_process_node.index, EVENT_NOTIFY, (uword)msg);
    }

 out_free:
  pfcp_free_msg(type, grp);
  return r;
}

void upf_pfcp_server_send_request(upf_session_t * sx, u8 type, struct pfcp_group *grp)
{
  sx_server_main_t *sxsm = &sx_server_main;
  sx_msg_t * msg;

  if ((msg = build_sx_msg(sx, type, grp)))
    {
      clib_warning("Msg: %p\n", msg);
      upf_pfcp_send_data(msg);
      sx_msg_free(sxsm, msg);
    }
}

sx_msg_t * upf_pfcp_make_response(sx_msg_t * req, size_t len)
{
  sx_msg_t * resp;

  resp = clib_mem_alloc_no_fail(sizeof(sx_msg_t));
  memset(resp, 0, sizeof(sx_msg_t));

  resp->fib_index = req->fib_index;
  resp->lcl = req->lcl;
  resp->rmt = req->rmt;
  vec_alloc(resp->data, len);

  return resp;
}

int upf_pfcp_send_response(sx_msg_t * req, u64 cp_seid, u8 type, struct pfcp_group *grp)
{
  sx_msg_t * resp;
  int r = 0;

  resp = upf_pfcp_make_response(req, 2048);

  resp->hdr->version = req->hdr->version;
  resp->hdr->s_flag = req->hdr->s_flag;
  resp->hdr->type = type;

  if (req->hdr->s_flag)
    {
      resp->hdr->s_flag = 1;
      resp->hdr->session_hdr.seid = clib_host_to_net_u64(cp_seid);

      memcpy(resp->hdr->session_hdr.sequence, req->hdr->session_hdr.sequence,
	     sizeof(resp->hdr->session_hdr.sequence));
      _vec_len(resp->data) = offsetof(pfcp_header_t, session_hdr.ies);
    }
  else
    {
      memcpy(resp->hdr->msg_hdr.sequence, req->hdr->msg_hdr.sequence,
	     sizeof(resp->hdr->session_hdr.sequence));
      _vec_len(resp->data) = offsetof(pfcp_header_t, msg_hdr.ies);
    }

  r = pfcp_encode_msg(type, grp, &resp->data);
  if (r != 0)
    goto out_free;

  /* vector resp might have changed */
  resp->hdr->length = clib_host_to_net_u16(_vec_len(resp->data) - 4);

  upf_pfcp_send_data(resp);

 out_free:
  pfcp_free_msg(type, grp);
  return 0;
}

static int urr_check_counter(u64 bytes, u64 consumed, u64 threshold, u64 quota)
{
  u32 r = 0;

  if (quota != 0 && consumed >= quota)
    r |= USAGE_REPORT_TRIGGER_VOLUME_QUOTA;

  if (threshold != 0 && bytes > threshold)
    r |= USAGE_REPORT_TRIGGER_VOLUME_THRESHOLD;

  return r;
}

static void
upf_pfcp_session_usage_report(upf_session_t *sx, f64 now)
{
  pfcp_session_report_request_t req;
  struct rules *active;
  upf_urr_t *urr;

  active = sx_get_rules(sx, SX_ACTIVE);

  if (vec_len(active->urr) == 0)
    /* how could that happen? */
    return;

  memset(&req, 0, sizeof(req));
  SET_BIT(req.grp.fields, SESSION_REPORT_REQUEST_REPORT_TYPE);
  req.report_type = REPORT_TYPE_USAR;

  SET_BIT(req.grp.fields, SESSION_REPORT_REQUEST_USAGE_REPORT);

  vec_foreach(urr, active->urr)
    {
      u32 trigger = 0;

#define urr_check(V, D)					\
      urr_check_counter(				\
			V.measure.bytes.D,		\
			V.measure.consumed.D,		\
			V.threshold.D,			\
			V.quota.D)

      trigger = urr_check(urr->volume, ul);
      trigger |= urr_check(urr->volume, dl);
      trigger |= urr_check(urr->volume, total);

#undef urr_check

      if (trigger != 0)
	{
	  build_usage_report(sx, urr, trigger, now, &req.usage_report);
	}
    }

  upf_pfcp_server_send_request(sx, PFCP_SESSION_REPORT_REQUEST, &req.grp);

  pfcp_free_msg(PFCP_SESSION_REPORT_REQUEST, &req.grp);
}

void upf_pfcp_session_stop_urr_time(urr_time_t *t)
{
  sx_server_main_t *sx = &sx_server_main;

  if (t->handle != ~0)
    {
      // stop timer ....
      TW (tw_timer_stop) (&sx->timer, t->handle);
      t->handle = ~0;
    }
}

void
upf_pfcp_session_start_stop_urr_time(u32 si, f64 now, urr_time_t *t, u8 start_it)
{
  sx_server_main_t *sx = &sx_server_main;

  if (t->handle != ~0)
     upf_pfcp_session_stop_urr_time(t);

  if (t->period != 0 && start_it)
    {
      i64 interval;

      // start timer.....

      interval = t->period * 100 - ceil((now - t->base) * 100.0) + 1;
      interval = clib_max(interval, 1);		 /* make sure interval is at least 1 */
      t->handle = TW (tw_timer_start) (&sx->timer, si, 0, interval);

      gtp_debug ("starting URR timer %u, now is %.3f, base is %.3f, expire in %lu ticks,"
		 " alternate %.4f, %.4f, clib_now %.4f, current tick: %u",
		 si, now, t->base, interval,
		 ((t->base + (f64)interval) - now) * 100,
		 ((t->base + interval) - now) * 100,
		 vlib_time_now (sx->vlib_main),
		 sx->timer.current_tick);
    }
}

void
upf_pfcp_session_start_stop_urr_time_abs(u32 si, f64 now, urr_time_t *t)
{
  sx_server_main_t *sx = &sx_server_main;

  if (t->handle != ~0)
     upf_pfcp_session_stop_urr_time(t);

  if (t->base != 0 && t->base > now)
    {
      u64 ticks;

      // start timer.....
      ticks = ceil((t->base - now) * 100.0);
      t->handle = TW (tw_timer_start) (&sx->timer, si, 0, ticks);

      gtp_debug ("starting URR absolute timer %u, now is %.3f, base is %.3f, expire in %lu ticks\n",
		 si, now, t->base, ticks);
    }
}

static void
upf_pfcp_session_urr_timer(upf_session_t *sx, f64 now, f64 cnow)
{
  gtp_debug ("upf_pfcp_session_urr_timer (%p, %u, %.3f, %.4f",
	     sx, now, cnow);

  pfcp_session_report_request_t req;
  upf_main_t *gtm = &upf_main;
  struct rules *active;
  u8 send_report = 0;
  upf_urr_t *urr;

  active = sx_get_rules(sx, SX_ACTIVE);

  memset(&req, 0, sizeof(req));
  SET_BIT(req.grp.fields, SESSION_REPORT_REQUEST_REPORT_TYPE);
  req.report_type = REPORT_TYPE_USAR;

  SET_BIT(req.grp.fields, SESSION_REPORT_REQUEST_USAGE_REPORT);

  vec_foreach(urr, active->urr)
    {
      u32 trigger = 0;

#define urr_check(V, NOW)					\
      (((V).base != 0) && ((V).period != 0) &&			\
       (trunc(((NOW) - (V).base - (f64)(V).period) * 100) >= 0))

      if (urr_check(urr->measurement_period, now))
	{
	  u32 si = sx - gtm->sessions;

	  if (urr->triggers & REPORTING_TRIGGER_PERIODIC_REPORTING)
	    trigger |= USAGE_REPORT_TRIGGER_PERIODIC_REPORTING;

	  urr->measurement_period.base += urr->measurement_period.period;

	  /* rearm Measurement Period */
	  upf_pfcp_session_start_stop_urr_time
	    (si, now, &urr->measurement_period, 1);

	}
      if (urr_check(urr->time_threshold, now))
	{
	  if (urr->triggers & REPORTING_TRIGGER_TIME_THRESHOLD)
	    trigger |= USAGE_REPORT_TRIGGER_TIME_THRESHOLD;

	  upf_pfcp_session_stop_urr_time(&urr->time_threshold);
	}
      if (urr_check(urr->time_quota, now))
	{
	  if (urr->triggers & REPORTING_TRIGGER_TIME_QUOTA)
	    trigger |= USAGE_REPORT_TRIGGER_TIME_QUOTA;

	  upf_pfcp_session_stop_urr_time(&urr->time_quota);
	  urr->time_quota.period = 0;
	  urr->status |= URR_OVER_QUOTA;
	}

#undef urr_check

      if (trigger != 0)
	{
	  build_usage_report(sx, urr, trigger, now, &req.usage_report);
	  send_report = 1;

	  // clear reporting on the time based triggers, until rearmed by update
	  urr->triggers &= ~(REPORTING_TRIGGER_TIME_THRESHOLD |
			     REPORTING_TRIGGER_TIME_QUOTA);
	}
      else if (!(urr->status & URR_AFTER_MONITORING_TIME) &&
	       (urr->monitoring_time.base != 0) &&
	       (urr->monitoring_time.base <= now))
	{
	  clib_spinlock_lock (&sx->lock);

	  urr->usage_before_monitoring_time.volume = urr->volume.measure;
	  memset(&urr->volume.measure.packets, 0, sizeof(urr->volume.measure.packets));
	  memset(&urr->volume.measure.bytes, 0, sizeof(urr->volume.measure.bytes));

	  clib_spinlock_unlock (&sx->lock);

	  upf_pfcp_session_stop_urr_time(&urr->monitoring_time);

	  urr->usage_before_monitoring_time.start_time = urr->start_time;
	  urr->start_time = now;
	  urr->status |= URR_AFTER_MONITORING_TIME;
	}
    }

  if (send_report)
    upf_pfcp_server_send_request(sx, PFCP_SESSION_REPORT_REQUEST, &req.grp);

  pfcp_free_msg(PFCP_SESSION_REPORT_REQUEST, &req.grp);
}

static uword
sx_process (vlib_main_t * vm,
	    vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  sx_server_main_t *sxsm = &sx_server_main;
  upf_main_t *gtm = &upf_main;
  u32 * expired = NULL;

  sxsm->timer.last_run_time = vlib_time_now (sxsm->vlib_main);
  sxsm->now = unix_time_now ();

  while (1)
    {
      uword event_type, *event_data = 0;
      u32 ticks_until_expiration;
      f64 timeout;
      f64 now;

      ticks_until_expiration = TW (tw_timer_first_expires_in_ticks)(&sxsm->timer);

      /* Nothing on the fast wheel, sleep 10ms */
      if (ticks_until_expiration == TW_SLOTS_PER_RING)
	{
	  timeout = 10e-3;
	}
      else
	{
	  timeout = (f64) ticks_until_expiration * 1e-5;
	}

      (void) vlib_process_wait_for_event_or_clock (vm, timeout);
      event_type = vlib_process_get_events (vm, &event_data);

      now = vlib_time_now (sxsm->vlib_main);
      sxsm->now = unix_time_now ();

      switch (event_type)
	{
	case ~0:                /* timeout */
	  break;

	case EVENT_RX:
	  {
	    for (int i = 0; i < vec_len (event_data); i++)
	      {
		sx_msg_t * msg = (sx_msg_t *)event_data[i];

		upf_pfcp_server_rx_msg(msg);

		vec_free(msg->data);
		clib_mem_free(msg);
	      }
	    break;
	  }

	case EVENT_NOTIFY:
	  {
	    for (int i = 0; i < vec_len (event_data); i++)
	      {
		sx_msg_t * msg;

		pool_get_aligned (sxsm->msg_pool, msg, CLIB_CACHE_LINE_BYTES);
		memcpy(msg, (sx_msg_t *)event_data[i], sizeof(*msg));
		clib_mem_free((sx_msg_t *)event_data[i]);

		upf_pfcp_send_data(msg);
		sx_msg_free(sxsm, msg);
	      }
	    break;
	  }

	case EVENT_URR:
	  {
	    for (int i = 0; i < vec_len (event_data); i++)
	      {
		uword si = (uword)event_data[i];
		upf_session_t *sx;

		sx = pool_elt_at_index (gtm->sessions, si);
		upf_pfcp_session_usage_report(sx, sxsm->now);
	      }
	    break;
	  }

	default:
	  gtp_debug ("event %ld, %p. ", event_type, event_data[0]);
	  break;
	}

      /*
	gtp_debug ("advancing wheel, now is %lu", now);
	gtp_debug ("tw_timer_expire_timers_vec (%p, %lu, %p);", &sx->timer, now, expired);
      */

      expired = TW (tw_timer_expire_timers_vec) (&sxsm->timer, now, expired);
      //gtp_debug ("Expired %d elements", vec_len (expired));

      for (int i = 0; i < vec_len (expired); i++)
	{
	  u8 tid = expired[i] >> 24;

	  if ((tid & 0x80) == 0)
	    {
	      const u32 si = expired[i] & 0x7FFFFFFF;
	      upf_session_t *sx;

	      if (pool_is_free_index (gtm->sessions, si))
		continue;

	      gtp_debug("wheel current tick: %u", sxsm->timer.current_tick);
	      sx = pool_elt_at_index (gtm->sessions, si);
	      upf_pfcp_session_urr_timer(sx, sxsm->now, now);
	    }
	}

      if (expired)
	{
	  _vec_len (expired) = 0;
	}
      if (event_data)
	{
	  _vec_len (event_data) = 0;
	}
    }

  return (0);
}

void upf_pfcp_handle_input (vlib_main_t * vm, vlib_buffer_t *b, int is_ip4)
{
  udp_header_t *udp;
  ip4_header_t *ip4;
  ip6_header_t *ip6;
  sx_msg_t * msg;
  u8 * data;

  /* signal Sx process to handle data */
  msg = clib_mem_alloc_no_fail(sizeof(*msg));
  memset(msg, 0, sizeof(*msg));
  msg->fib_index = vnet_buffer (b)->ip.fib_index;

  /* udp_local hands us a pointer to the udp data */
  data = vlib_buffer_get_current (b);
  udp = (udp_header_t *) (data - sizeof (*udp));

  if (is_ip4)
    {
      /* $$$$ fixme: udp_local doesn't do ip options correctly anyhow */
      ip4 = (ip4_header_t *) (((u8 *) udp) - sizeof (*ip4));
      ip_set(&msg->lcl.address, &ip4->dst_address, is_ip4);
      ip_set(&msg->rmt.address, &ip4->src_address, is_ip4);
    }
  else
    {
      ip6 = (ip6_header_t *) (((u8 *) udp) - sizeof (*ip6));
      ip_set(&msg->lcl.address, &ip6->dst_address, is_ip4);
      ip_set(&msg->rmt.address, &ip6->src_address, is_ip4);
    }

  msg->lcl.port = udp->dst_port;
  msg->rmt.port = udp->src_port;

  msg->data = vec_new(u8, vlib_buffer_length_in_chain (vm, b));
  vlib_buffer_contents (vm, vlib_get_buffer_index (vm, b), msg->data);

  gtp_debug ("sending event %p %U:%d - %U:%d, data %p", msg,
		format_ip46_address, &msg->rmt.address, IP46_TYPE_ANY,
		clib_net_to_host_u16(msg->rmt.port),
		format_ip46_address, &msg->lcl.address, IP46_TYPE_ANY,
		clib_net_to_host_u16(msg->lcl.port),
		msg->data);

  vlib_process_signal_event_mt(vm, sx_api_process_node.index, EVENT_RX, (uword)msg);
}

void
upf_pfcp_server_session_usage_report(upf_session_t *sess)
{
  sx_server_main_t *sx = &sx_server_main;
  vlib_main_t *vm = sx->vlib_main;
  upf_main_t *gtm = &upf_main;

  vlib_process_signal_event_mt(vm, sx_api_process_node.index, EVENT_URR, (uword)(sess - gtm->sessions));
}

/*********************************************************/

clib_error_t *
sx_server_main_init (vlib_main_t * vm)
{
  sx_server_main_t *sx = &sx_server_main;
  clib_error_t *error;

  if ((error = vlib_call_init_function (vm, vnet_interface_cli_init)))
    return error;

  sx->vlib_main = vm;
  sx->start_time = time(NULL);

  TW (tw_timer_wheel_init) (&sx->timer, NULL, 10e-3 /* 10ms timer interval */ , ~0);

  udp_register_dst_port (vm, UDP_DST_PORT_SX,
			 sx4_input_node.index, /* is_ip4 */ 1);
  udp_register_dst_port (vm, UDP_DST_PORT_SX,
			 sx6_input_node.index, /* is_ip4 */ 0);

  gtp_debug ("PFCP: start_time: %p, %d, %x.", sx, sx->start_time, sx->start_time);
  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (sx_api_process_node, static) = {
    .function = sx_process,
    .type = VLIB_NODE_TYPE_PROCESS,
    .process_log2_n_stack_bytes = 16,
    .runtime_data_bytes = sizeof (void *),
    .name = "sx-api",
};

/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
