/*
 * upf_adf.h - 3GPP TS 29.244 UPF adf header file
 *
 * Copyright (c) 2017 Travelping GmbH
 *
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

#ifndef __included_upf_adf_h__
#define __included_upf_adf_h__

#include <stddef.h>
#include <upf/upf.h>

#if CLIB_DEBUG > 0
#define adf_debug clib_warning
#else
#define adf_debug(...)				\
  do { } while (0)
#endif

int upf_adf_lookup(u32 db_index, u8 * str, uint16_t length);
int upf_adf_remove(u32 db_index);
int upf_app_add_del (upf_main_t * sm, u8 * name, int add);
int upf_rule_add_del (upf_main_t * sm, u8 * name, u32 id,
		      int add, upf_rule_args_t * args);
void foreach_upf_flows (BVT (clib_bihash_kv) * kvp, void * arg);

u32 upf_adf_get_adr_db(u32 application_id);
void upf_adf_put_adr_db(u32 db_index);

int upf_flow_timeout_update (flowtable_timeout_type_t type, u16 timeout);

#define MIN(x,y) (((x)<(y))?(x):(y))

always_inline int
upf_adf_parse_tcp_payload(tcp_header_t * tcp, u32 db_id)
{
  u8 *http = NULL;
  u8 *version = NULL;
  u8 *host = NULL;
  u8 *host_end = NULL;
  u16 uri_length = 0;
  u16 host_length = 0;
  u8 *url = NULL;
  int res = 0;

  http = (u8*)tcp + tcp_header_bytes(tcp);

  if ((http[0] != 'G') ||
      (http[1] != 'E') ||
      (http[2] != 'T'))
    {
      return -1;
    }

  http += sizeof("GET");

  version = (u8*)strchr((const char*)http, ' ');
  if (version == NULL)
    return -1;

  uri_length = version - http;

  host = (u8*)strstr((const char*)http, "Host:");
  if (host == NULL)
    return -1;

  host += sizeof("Host:");

  host_end = (u8*)strchr((const char*)host, '\r');
  if (host_end == NULL)
    return -1;

  host_length = host_end - host;

  vec_add(url, "http://", sizeof("http://"));
  vec_add(url, host, host_length);
  vec_add(url, http, uri_length);

  adf_debug("URL: %v", url);

  res = upf_adf_lookup(db_id, url, vec_len(url));

  vec_free(url);

  return res;
}

always_inline int
upf_adf_parse_ip4_packet(ip4_header_t * ip4, u32 db_id)
{
  int tcp_payload_len = 0;
  tcp_header_t *tcp = NULL;

  if (db_id == ~0)
    return -1;

  if (ip4->protocol != IP_PROTOCOL_TCP)
    return -1;

  tcp = (tcp_header_t *) ip4_next_header(ip4);

  tcp_payload_len = clib_net_to_host_u16(ip4->length) -
		    sizeof(ip4_header_t) - tcp_header_bytes(tcp);

  if (tcp_payload_len < 8)
    return -1;

  return upf_adf_parse_tcp_payload(tcp, db_id);
}

always_inline int
upf_adf_parse_ip6_packet(ip6_header_t * ip6, u32 db_id)
{
  int tcp_payload_len = 0;
  tcp_header_t *tcp = NULL;

  if (db_id == ~0)
    return -1;

  if (ip6->protocol != IP_PROTOCOL_TCP)
    return -1;

  tcp = (tcp_header_t *) ip6_next_header(ip6);

  tcp_payload_len = clib_net_to_host_u16(ip6->payload_length) -
		    tcp_header_bytes(tcp);

  if (tcp_payload_len < 8)
    return -1;

  return upf_adf_parse_tcp_payload(tcp, db_id);
}

always_inline upf_pdr_t *
upf_get_highest_adf_pdr (struct rules * active, int direction)
{
  upf_pdr_t *pdr = NULL;
  upf_pdr_t *pdr_iter = NULL;
  int iter_direction = 0;

  if (vec_len(active->pdr) == 0)
    return NULL;

  vec_foreach (pdr_iter, active->pdr)
    {
      if (!(pdr->pdi.fields & F_PDI_APPLICATION_ID))
	continue;

      iter_direction = (pdr_iter->pdi.src_intf == SRC_INTF_ACCESS) ? UL_SDF : DL_SDF;
      if (iter_direction != direction)
	continue;

      if (pdr == NULL)
	{
	  pdr = pdr_iter;
	  continue;
	}

      if (pdr_iter->precedence < pdr->precedence)
	pdr = pdr_iter;
    }

  return pdr;
}

always_inline int
upf_check_http_req (u8 * pl, int is_ip4)
{
  int tcp_payload_len = 0;
  tcp_header_t *tcp = NULL;
  u8 *http = NULL;

  if (is_ip4)
    {
      ip4_header_t *ip4 = (ip4_header_t *)pl;
      if (ip4->protocol != IP_PROTOCOL_TCP)
	return 0;

      tcp = (tcp_header_t *) ip4_next_header(ip4);
      tcp_payload_len = clib_net_to_host_u16(ip4->length) -
			sizeof(ip4_header_t) - tcp_header_bytes(tcp);
    }
  else
    {
      ip6_header_t *ip6 = (ip6_header_t *)pl;
      if (ip6->protocol != IP_PROTOCOL_TCP)
	return 0;

      tcp = (tcp_header_t *) ip6_next_header(ip6);
      tcp_payload_len = clib_net_to_host_u16(ip6->payload_length) -
			tcp_header_bytes(tcp);
    }

  if (tcp_payload_len < 8)
    return 0;

  http = (u8*)tcp + tcp_header_bytes(tcp);

  if ((http[0] != 'G') ||
      (http[1] != 'E') ||
      (http[2] != 'T'))
    {
      return 0;
    }

  return 1;
}

always_inline void
upf_update_flow_application_id (flow_entry_t * flow, upf_pdr_t * pdr,
			   u8 * pl, int is_ip4)
{
  int r;

  if (!flow)
    return;

  if (flow->application_id != ~0)
    return;

  if (!(pdr->pdi.fields & F_PDI_APPLICATION_ID))
    return;

  r = (is_ip4) ?
    upf_adf_parse_ip4_packet((ip4_header_t *)pl, pdr->pdi.adr.db_id) :
    upf_adf_parse_ip6_packet((ip6_header_t *)pl, pdr->pdi.adr.db_id);

  if (r == 0)
    flow->application_id = pdr->pdi.adr.application_id;
}

always_inline upf_pdr_t *
upf_get_adf_pdr_by_name (struct rules * active, u8 src_intf, u32 application_id)
{
  upf_pdr_t *pdr;

  vec_foreach (pdr, active->pdr)
    {
      if (!(pdr->pdi.fields & F_PDI_APPLICATION_ID))
	continue;

      if (pdr->pdi.src_intf != src_intf)
	continue;

      if (pdr->pdi.adr.application_id == application_id)
	return pdr;
    }

  /* not found */
  return NULL;
}

#endif /* __included_upf_adf_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */