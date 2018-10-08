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

#include <vnet/ip/ip.h>
#include <vnet/session/session.h>
#include <vnet/session/application_interface.h>

#include "upf.h"
#include "flowtable.h"
#include "flowtable_impl.h"

#if CLIB_DEBUG > 0
#define timer_debug clib_warning
#else
#define timer_debug(...)				\
  do { } while (0)
#endif

clib_error_t *
upf_timers_init (vlib_main_t * vm)
{
  return 0;
}

static uword
update_timers_service (vlib_main_t * vm,
                       vlib_node_runtime_t * rt,
                       vlib_frame_t * f)
{
  f64 period = 1.0;
  upf_main_t *gtm = &upf_main;
  upf_session_t *sess = NULL;
  u32 current_time = 0;

  while (1)
    {
      vlib_process_wait_for_event_or_clock (vm, period);

      current_time = (u32) ((u64) vm->cpu_time_last_node_dispatch /
                            vm->clib_time.clocks_per_second);

      timer_debug("current time: %u", current_time);

      /* *INDENT-OFF* */
      pool_foreach (sess, gtm->sessions,
      ({
         if (sess->fmt.ht_lines)
           {
             timer_wheel_index_update(&sess->fmt, current_time);
             flowtable_timer_update(&sess->fmt, current_time);
           }
      }));
      /* *INDENT-ON* */
    }

  /* unreachable */
  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (upf_timers_service_node, static) = {
    .function = update_timers_service,
    .type = VLIB_NODE_TYPE_PROCESS,
    .name = "upf-timers-service",
    .process_log2_n_stack_bytes = 16,
};
/* *INDENT-ON* */

VLIB_INIT_FUNCTION (upf_timers_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
