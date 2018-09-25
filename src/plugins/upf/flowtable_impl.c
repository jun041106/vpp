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
    for (i = 0; i < TIMER_MAX_LIFETIME; i++)
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

  return error;
}

#if 0
int
flowtable_update(u8 is_ip4, u8 ip_src[16], u8 ip_dst[16], u8 ip_upper_proto,
    u16 port_src, u16 port_dst, u16 lifetime, u8 offloaded, u8 infos[16])
{
    flow_signature_t sig;
    flow_entry_t * flow;
    BVT(clib_bihash_kv) kv;
    flowtable_main_t * fm = &flowtable_main;
    uword session_index;

    if (is_ip4)
    {
        sig.len = sizeof(struct ip4_sig);
        clib_memcpy(&sig.s.ip4.src, ip_src, 4);
        clib_memcpy(&sig.s.ip4.dst, ip_dst, 4);
        sig.s.ip4.proto = ip_upper_proto;
        sig.s.ip4.port_src = port_src;
        sig.s.ip4.port_dst = port_dst;
    } else {
        sig.len = sizeof(struct ip6_sig);
        clib_memcpy(&sig.s.ip6.src, ip_src, 16);
        clib_memcpy(&sig.s.ip6.dst, ip_dst, 16);
        sig.s.ip6.proto = ip_upper_proto;
        sig.s.ip6.port_src = port_src;
        sig.s.ip6.port_dst = port_dst;
    }

    flow = NULL;
    kv.key = hash_signature(&sig);

    /* TODO: recover handoff dispatch fun to get the correct node index */
    for (session_index = 0; session_index < ARRAY_LEN(fm->per_session); session_index++)
    {
        flowtable_per_session_t * fmt = &fm->per_session[session_index];
        if (fmt == NULL)
            continue;

        if (PREDICT_FALSE(BV(clib_bihash_search) (&fmt->flows_ht, &kv, &kv)))
        {
            continue;
        } else {
            dlist_elt_t * ht_line;
            u32 index;
            u32 ht_line_head_index;

            flow = NULL;
            ht_line_head_index = (u32) kv.value;
            if (dlist_is_empty(fmt->ht_lines, ht_line_head_index))
                continue;

            ht_line = pool_elt_at_index(fmt->ht_lines, ht_line_head_index);
            index = ht_line->next;
            while (index != ht_line_head_index)
            {
                dlist_elt_t * e = pool_elt_at_index(fmt->ht_lines, index);
                flow = pool_elt_at_index(fm->flows, e->value);
                if (PREDICT_TRUE(memcmp(&flow->sig, &sig, sig.len) == 0))
                    break;

                index = e->next;
            }
        }
    }

    if (PREDICT_FALSE(flow == NULL))
        return -1;  /* flow not found */

    if (lifetime != (u16) ~0)
    {
        ASSERT(lifetime < TIMER_MAX_LIFETIME);
        flow->lifetime = lifetime;
    }
    flow->infos.data.offloaded = offloaded;
    clib_memcpy(flow->infos.data.opaque, infos, sizeof(flow->infos.data.opaque));

    return 0;
}
#endif
