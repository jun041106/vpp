/*---------------------------------------------------------------------------
 * Copyright (c) 2016 Qosmos and/or its affiliates.
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
 *---------------------------------------------------------------------------
 */

#include <vppinfra/dlist.h>
#include <vppinfra/types.h>
#include <vppinfra/vec.h>
#include <vnet/ip/ip4_packet.h>

#include "flowtable.h"
#include "flowtable_tcp.h"
#include "flowtable_impl.h"

u64 flow_id = 0;
flowtable_main_t flowtable_main;

clib_error_t *
flowtable_init_session(flowtable_main_t *fm, flowtable_per_session_t * fmt)
{
    int i;
    flow_entry_t * f;
    clib_error_t * error = 0;

    /* init hashtable */
    pool_alloc(fmt->ht_lines, 2 * fm->flows_max);
    BV(clib_bihash_init) (&fmt->flows_ht, "flow hash table",
        FM_NUM_BUCKETS, FM_MEMORY_SIZE);

    /* init timer wheel */
    fmt->time_index = ~0;
    for (i = 0; i < fm->timer_max_lifetime; i++)
    {
        dlist_elt_t * timer_slot;
        pool_get(fmt->timers, timer_slot);

        u32 timer_slot_head_index = timer_slot - fmt->timers;
        clib_dlist_init(fmt->timers, timer_slot_head_index);
        vec_add1(fmt->timer_wheel, timer_slot_head_index);
    }

    /* fill flow entry cache */
    if (pthread_spin_lock(&fm->flows_lock) == 0)
    {
        for (i = 0; i < FLOW_CACHE_SZ; i++)
        {
            pool_get_aligned(fm->flows, f, CLIB_CACHE_LINE_BYTES);
            vec_add1(fmt->flow_cache, f - fm->flows);
        }
        fm->flows_cpt += FLOW_CACHE_SZ;

        pthread_spin_unlock(&fm->flows_lock);
    }

    return error;
}

clib_error_t *
flowtable_init(vlib_main_t * vm)
{
  clib_error_t * error = 0;
  flowtable_main_t * fm = &flowtable_main;

  fm->vlib_main = vm;
  fm->vnet_main = vnet_get_main ();

  /* By default, forward packets to ethernet-input */
  fm->next_node_index = FT_NEXT_ETHERNET_INPUT;

  /* ensures flow_info structure fits into vlib_buffer_t's opaque 1 field */
  ASSERT(sizeof(flow_data_t) <= 6 * sizeof(u32));

  /* init flow pool */
  fm->flows_max = FM_POOL_COUNT;
  pool_alloc_aligned(fm->flows, fm->flows_max, CLIB_CACHE_LINE_BYTES);
  pthread_spin_init(&fm->flows_lock, PTHREAD_PROCESS_PRIVATE);
  fm->flows_cpt = 0;

  /* init timeout msg pool */
  pool_alloc(fm->msg_pool, TIMEOUT_MSG_QUEUE_SZ);
  pthread_spin_init(&fm->msg_lock, PTHREAD_PROCESS_PRIVATE);

  /* XXX what's the best way to do this ? */
  fm->msg_pool = calloc(TIMEOUT_MSG_QUEUE_SZ, sizeof(timeout_msg_t));
  fm->first_msg_index = ~0;
  fm->last_msg_index = 0;

  /* init timers */
  fm->timer_default_lifetime = TIMER_DEFAULT_LIFETIME;
  fm->timer_ip4_lifetime = 0;
  fm->timer_ip6_lifetime = 0;
  fm->timer_icmp_lifetime = 0;
  fm->timer_udp_lifetime = 0;
  fm->timer_tcp_lifetime = 0;
  fm->timer_max_lifetime = TIMER_MAX_LIFETIME;

  return error;
}

clib_error_t *
flowtable_timelife_update(flowtable_timeout_type_t type, u16 value)
{
  clib_error_t * error = 0;
  flowtable_main_t * fm = &flowtable_main;

  if (value > fm->timer_max_lifetime)
    return clib_error_return (0, "value is too big");

  switch (type)
    {
      case FT_TIMEOUT_TYPE_DEFAULT:
        fm->timer_default_lifetime = value;
        break;
      case FT_TIMEOUT_TYPE_IPV4:
        fm->timer_ip4_lifetime = value;
        break;
      case FT_TIMEOUT_TYPE_IPV6:
        fm->timer_ip6_lifetime = value;
        break;
      case FT_TIMEOUT_TYPE_ICMP:
        fm->timer_icmp_lifetime = value;
        break;
      case FT_TIMEOUT_TYPE_UDP:
        fm->timer_udp_lifetime = value;
        break;
      case FT_TIMEOUT_TYPE_TCP:
        fm->timer_tcp_lifetime = value;
        break;
      default:
        return clib_error_return (0, "unknown timer type");
    }

  return error;
}

u16
flowtable_timelife_get(flowtable_timeout_type_t type)
{
  flowtable_main_t * fm = &flowtable_main;

  switch (type)
    {
      case FT_TIMEOUT_TYPE_DEFAULT:
        return fm->timer_default_lifetime;
      case FT_TIMEOUT_TYPE_IPV4:
        return fm->timer_ip4_lifetime;
      case FT_TIMEOUT_TYPE_IPV6:
        return fm->timer_ip6_lifetime;
      case FT_TIMEOUT_TYPE_ICMP:
        return fm->timer_icmp_lifetime;
      case FT_TIMEOUT_TYPE_UDP:
        return fm->timer_udp_lifetime;
      case FT_TIMEOUT_TYPE_TCP:
        return fm->timer_tcp_lifetime;
      default:
        return ~0;
    }

  return ~0;
}

clib_error_t *
flowtable_max_timelife_update(u16 value)
{
  clib_error_t * error = 0;
  flowtable_main_t * fm = &flowtable_main;

  fm->timer_max_lifetime = value;

  return error;
}
