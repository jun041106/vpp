/*
 * upf_adf.c - 3GPP TS 29.244 UPF adf
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

#define _LGPL_SOURCE            /* LGPL v3.0 is compatible with Apache 2.0 */

#include <arpa/inet.h>
#include <urcu-qsbr.h>          /* QSBR RCU flavor */
#include <vlib/vlib.h>
#include <vppinfra/types.h>
#include <vppinfra/vec.h>
#include <vppinfra/pool.h>

#include <hs/hs.h>
#include "upf/upf_adf.h"
#include <upf/upf_pfcp.h>

typedef struct {
  regex_t *expressions;
  u32 *flags;
  hs_database_t *database;
  hs_scratch_t *scratch;
  u32 ref_cnt;
} upf_adf_entry_t;

typedef struct {
  int res;
} upf_adf_cb_args_t;

static upf_adf_entry_t *upf_adf_db = NULL;

static void
upf_adf_cleanup_db_entry(upf_adf_entry_t *entry)
{
  regex_t *regex = NULL;

  vec_foreach (regex, entry->expressions)
    {
      vec_free(*regex);
    }

  hs_free_database(entry->database);
  hs_free_scratch(entry->scratch);
  vec_free(entry->expressions);
  vec_free(entry->flags);

  memset(entry, 0, sizeof(upf_adf_entry_t));
}

static int upf_adf_create_update_db(upf_adf_app_t * app)
{
  upf_adf_entry_t *entry = NULL;
  hs_compile_error_t *compile_err = NULL;
  int error = 0;
  u32 index = 0;
  u32 rule_index = 0;
  upf_adr_t *rule = NULL;

  if (app->db_index != ~0)
    {
      entry = pool_elt_at_index (upf_adf_db, app->db_index);
      upf_adf_cleanup_db_entry (entry);
    }
  else
    {
      pool_get (upf_adf_db, entry);
      if (!entry)
	return -1;

      memset(entry, 0, sizeof(*entry));
      app->db_index = entry - upf_adf_db;
    }

  /* *INDENT-OFF* */
  hash_foreach(rule_index, index, app->rules_by_id,
  ({
     regex_t regex = NULL;
     rule = pool_elt_at_index(app->rules, index);

     vec_add(regex, ".*\\Q", 4);
     vec_add(regex, rule->host, vec_len(rule->host));
     vec_add(regex, "\\E.*\\Q", 6);
     vec_add(regex, rule->path, vec_len(rule->path));
     vec_add(regex, "\\E.*", 4);
     vec_add1(regex, 0);

     adf_debug("app id: %u, regex: %s", app - gtm->upf_apps, regex);

     vec_add1(entry->expressions, regex);
     vec_add1(entry->flags, HS_FLAG_SINGLEMATCH);
  }));
  /* *INDENT-ON* */

  if (hs_compile_multi((const char **)entry->expressions, entry->flags, NULL,
		       vec_len(entry->expressions),
		       HS_MODE_BLOCK, NULL, &entry->database,
		       &compile_err) != HS_SUCCESS)
    {
      adf_debug("Error: %s", compile_err->message);
      error = -1;
      goto done;
    }

  if (hs_alloc_scratch(entry->database, &entry->scratch) != HS_SUCCESS)
    {
      hs_free_database(entry->database);
      entry->database = NULL;
      error = -1;
      goto done;
    }

done:
  return error;
}

static int
upf_adf_event_handler(unsigned int id, unsigned long long from,
		      unsigned long long to, unsigned int flags,
		      void *ctx)
{
  (void) from;
  (void) to;
  (void) flags;

  upf_adf_cb_args_t *args = (upf_adf_cb_args_t*)ctx;

  args->res = 1;

  return 0;
}

int
upf_adf_lookup(u32 db_index, u8 * str, uint16_t length)
{
  upf_adf_entry_t *entry = NULL;
  int ret = 0;
  upf_adf_cb_args_t args = {};

  if (db_index == ~0)
    return -1;

  entry = pool_elt_at_index (upf_adf_db, db_index);
  ret = hs_scan(entry->database, (const char*)str, length, 0, entry->scratch,
		upf_adf_event_handler, (void*)&args);
  if (ret != HS_SUCCESS)
    return -1;

  if (args.res == 0)
    return -1;

  return 0;
}

int
upf_adf_remove(u32 db_index)
{
  upf_adf_entry_t *entry = NULL;

  entry = pool_elt_at_index (upf_adf_db, db_index);
  upf_adf_cleanup_db_entry(entry);
  pool_put (upf_adf_db, entry);

  return 0;
}

u32 upf_adf_get_adr_db(u32 application_id)
{
  upf_main_t * sm = &upf_main;
  upf_adf_app_t *app;

  app = pool_elt_at_index(sm->upf_apps, application_id);
  if (app->db_index != ~0 &&
      !pool_is_free_index (upf_adf_db, app->db_index))
    {
      upf_adf_entry_t *entry = pool_elt_at_index (upf_adf_db, app->db_index);
      clib_smp_atomic_add(&entry->ref_cnt, 1);
    }

  return app->db_index;
}

void upf_adf_put_adr_db(u32 db_index)
{
  if (db_index != ~0)
    {
      upf_adf_entry_t *entry = pool_elt_at_index (upf_adf_db, db_index);
      clib_smp_atomic_add(&entry->ref_cnt, -1);
    }
}

static u32 upf_adf_adr_ref_count(u32 db_index)
{
  if (db_index != ~0)
    {
      upf_adf_entry_t *entry = pool_elt_at_index (upf_adf_db, db_index);
      return entry->ref_cnt;
    }

  return 0;
}


static clib_error_t *
upf_adf_app_add_command_fn (vlib_main_t * vm,
			    unformat_input_t * input,
			    vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 *name = NULL;
  clib_error_t *error = NULL;
  u64 up_seid = 0;
  upf_session_t *sess = NULL;
  upf_pdr_t *pdr = NULL;
  u16 pdr_id = 0;
  u8 add_flag = ~0;
  upf_main_t *gtm = &upf_main;
  uword *p = NULL;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return error;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "add session 0x%lx pdr %u name %_%v%_",
		    &up_seid, &pdr_id, &name))
	{
	  add_flag = 1;
	  break;
	}
      if (unformat (line_input, "update session 0x%lx pdr %u name %_%v%_",
		    &up_seid, &pdr_id, &name))
	{
	  add_flag = 0;
	  break;
	}
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
	  format_unformat_error, input);
	  goto done;
	}
    }

  sess = sx_lookup(up_seid);
  if (sess == NULL)
    {
      error = clib_error_return (0, "could not find a session");
      goto done;
    }

  pdr = sx_get_pdr(sess, SX_ACTIVE, pdr_id);
  if (pdr == NULL)
    {
      error = clib_error_return (0, "could not find a pdr");
      goto done;
    }

  p = hash_get_mem (gtm->upf_app_by_name, name);
  if (!p)
    {
      goto done;
    }

  ASSERT(!pool_is_free_index (gtm->upf_apps, p[0]));

  if (add_flag == 0)
    {
      upf_adf_put_adr_db(pdr->pdi.adr.db_id);

      pdr->pdi.fields &= ~F_PDI_APPLICATION_ID;
      pdr->pdi.adr.application_id = ~0;
      pdr->pdi.adr.db_id = ~0;
    }
  else if (add_flag == 1)
    {
      pdr->pdi.fields |= F_PDI_APPLICATION_ID;
      pdr->pdi.adr.application_id = p[0];
      pdr->pdi.adr.db_id = upf_adf_get_adr_db(p[0]);
    }

  vlib_cli_output (vm, "ADR DB id: %u", pdr->pdi.adr.db_id);

done:
  vec_free (name);
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_adf_app_add_command, static) =
{
  .path = "upf adf app",
  .short_help = "upf adf app <add|update> session <id> pdr <id> name <app name>",
  .function = upf_adf_app_add_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
upf_adf_url_test_command_fn (vlib_main_t * vm,
			     unformat_input_t * input,
			     vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 *url = NULL;
  clib_error_t *error = NULL;
  u32 id = 0;
  int r;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return error;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%u url %_%v%_", &id, &url))
	{
	  break;
	}
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
	  format_unformat_error, input);
	  goto done;
	}
    }

  r = upf_adf_lookup(id, url, vec_len(url));
  vlib_cli_output (vm, "Matched Result: %u", r);

done:
  vec_free (url);
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_adf_url_test_command, static) =
{
  .path = "upf adf test db",
  .short_help = "upf adf test db <id> url <url>",
  .function = upf_adf_url_test_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
upf_adf_show_db_command_fn (vlib_main_t * vm,
			    unformat_input_t * input,
			    vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;
  u8 *name = NULL;
  regex_t *expressions = NULL;
  upf_main_t * sm = &upf_main;
  uword *p = NULL;
  upf_adf_entry_t *e;
  upf_adf_app_t *app;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return error;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
    if (unformat (line_input, "%_%v%_", &name))
	{
	  break;
	}
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
	  format_unformat_error, input);
	  goto done;
	}
    }

  p = hash_get_mem (sm->upf_app_by_name, name);
  if (!p)
      goto done;

  app = pool_elt_at_index(sm->upf_apps, p[0]);
  if (app->db_index == ~0)
    {
      error = clib_error_return (0, "DB does not exist...");
      goto done;
    }

  e = pool_elt_at_index (upf_adf_db, app->db_index);
  for (int i = 0; i < vec_len(e->expressions); i++)
    {
      vlib_cli_output (vm, "regex: %v", expressions[i]);
    }

done:
  vec_free (name);
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_adf_show_db_command, static) =
{
  .path = "show upf adf app",
  .short_help = "show upf adf app <name>",
  .function = upf_adf_show_db_command_fn,
};
/* *INDENT-ON* */

/* Action function shared between message handler and debug CLI */

static int
vnet_upf_rule_add_del(u8 * app_name, u32 rule_index, u8 add,
		      upf_rule_args_t * args);

static int
vnet_upf_app_add_del(u8 * name, u8 add);

int upf_app_add_del (upf_main_t * sm, u8 * name, int add)
{
  int rv = 0;

  rv = vnet_upf_app_add_del(name, add);

  return rv;
}

int upf_rule_add_del (upf_main_t * sm, u8 * name, u32 id,
		      int add, upf_rule_args_t * args)
{
  int rv = 0;

  rv = vnet_upf_rule_add_del(name, id, add, args);

  return rv;
}

static int
vnet_upf_app_add_del(u8 * name, u8 add)
{
  upf_main_t *sm = &upf_main;
  upf_adf_app_t *app = NULL;
  u32 index = 0;
  u32 rule_index = 0;
  uword *p = NULL;

  p = hash_get_mem (sm->upf_app_by_name, name);

  if (add)
    {
      if (p)
	return VNET_API_ERROR_VALUE_EXIST;

      pool_get (sm->upf_apps, app);
      memset(app, 0, sizeof(*app));

      app->name = vec_dup(name);
      app->rules_by_id = hash_create_mem (0, sizeof (u32), sizeof (uword));
      app->db_index = ~0;

      hash_set_mem (sm->upf_app_by_name, app->name, app - sm->upf_apps);
    }
  else
    {
      if (!p)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      hash_unset_mem (sm->upf_app_by_name, name);
      app = pool_elt_at_index (sm->upf_apps, p[0]);

      if (upf_adf_adr_ref_count(app->db_index) != 0)
	return VNET_API_ERROR_INSTANCE_IN_USE;

      /* *INDENT-OFF* */
      hash_foreach(rule_index, index, app->rules_by_id,
      ({
	 upf_adr_t *rule = NULL;
	 rule = pool_elt_at_index(app->rules, index);
	 vnet_upf_rule_add_del(app->name, rule->id, 0, NULL);
      }));
      /* *INDENT-ON* */

      upf_adf_remove(app->db_index);
      vec_free (app->name);
      hash_free(app->rules_by_id);
      pool_free(app->rules);
      pool_put (sm->upf_apps, app);
    }

  return 0;
}

static clib_error_t *
upf_create_app_command_fn (vlib_main_t * vm,
			   unformat_input_t * input,
			   vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 *name = NULL;
  clib_error_t *error = NULL;
  int rv = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return error;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%_%v%_", &name))
	break;
      else
	{
	  error = unformat_parse_error (line_input);
	  goto done;
	}
    }

  rv = vnet_upf_app_add_del(name, 1);

  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_VALUE_EXIST:
      error = clib_error_return (0, "application already exists...");
      break;

    case VNET_API_ERROR_NO_SUCH_ENTRY:
      error = clib_error_return (0, "application does not exist...");
      break;

    default:
      error = clib_error_return (0, "%s returned %d", __FUNCTION__, rv);
      break;
    }

done:
  vec_free (name);
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_create_app_command, static) =
{
  .path = "create upf application",
  .short_help = "create upf application <name>",
  .function = upf_create_app_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
upf_delete_app_command_fn (vlib_main_t * vm,
			   unformat_input_t * input,
			   vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 *name = NULL;
  clib_error_t *error = NULL;
  int rv = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return error;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%_%v%_", &name))
	break;
      else
	{
	  error = unformat_parse_error (line_input);
	  goto done;
	}
    }

  rv = vnet_upf_app_add_del(name, 0);

  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_VALUE_EXIST:
      error = clib_error_return (0, "application already exists...");
      break;

    case VNET_API_ERROR_NO_SUCH_ENTRY:
      error = clib_error_return (0, "application does not exist...");
      break;

    case VNET_API_ERROR_INSTANCE_IN_USE:
      error = clib_error_return (0, "application is in use...");
      break;

    default:
      error = clib_error_return (0, "%s returned %d", __FUNCTION__, rv);
      break;
    }

done:
  vec_free (name);
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_delete_app_command, static) =
{
  .path = "delete upf application",
  .short_help = "delete upf application <name>",
  .function = upf_delete_app_command_fn,
};
/* *INDENT-ON* */

static int
vnet_upf_rule_add_del(u8 * app_name, u32 rule_index, u8 add,
		      upf_rule_args_t * args)
{
  upf_main_t *sm = &upf_main;
  uword *p = NULL;
  upf_adf_app_t *app = NULL;
  upf_adr_t *rule = NULL;
  int res = 0;

  p = hash_get_mem (sm->upf_app_by_name, app_name);
  if (!p)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  app = pool_elt_at_index (sm->upf_apps, p[0]);

  if (upf_adf_adr_ref_count(app->db_index) != 0)
    return VNET_API_ERROR_INSTANCE_IN_USE;

  p = hash_get_mem (app->rules_by_id, &rule_index);

  if (add)
    {
      if (p)
	return VNET_API_ERROR_VALUE_EXIST;

      pool_get (app->rules, rule);
      memset(rule, 0, sizeof(*rule));
      rule->id = rule_index;
      rule->host = vec_dup(args->host);
      rule->path = vec_dup(args->path);

      hash_set_mem (app->rules_by_id, &rule_index, rule - app->rules);
    }
  else
    {
      if (!p)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      rule = pool_elt_at_index (app->rules, p[0]);
      vec_free(rule->host);
      vec_free(rule->path);
      hash_unset_mem (app->rules_by_id, &rule_index);
      pool_put (app->rules, rule);
    }

  res = upf_adf_create_update_db(app);
  if (res < 0)
    return res;

  return 0;
}

static clib_error_t *
upf_application_rule_add_del_command_fn (vlib_main_t * vm,
					 unformat_input_t * input,
					 vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 *app_name = NULL;
  ip46_address_t src_ip;
  ip46_address_t dst_ip;
  u8 *host = NULL;
  u8 *path = NULL;
  u32 rule_index = 0;
  clib_error_t *error = NULL;
  int rv = 0;
  int add = 1;
  upf_rule_args_t rule_args = {};

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return error;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%_%v%_ rule %u",
		    &app_name, &rule_index))
	{
	  if (unformat (line_input, "del"))
	    {
	      add = 0;
	      break;
	    }
	  else if (unformat (line_input, "add"))
	    {
	      add = 1;

	      if (unformat (line_input, "ip dst %U", unformat_ip46_address, &dst_ip, IP46_TYPE_ANY))
		break;
	      else if (unformat (line_input, "ip src %U", unformat_ip46_address, &src_ip, IP46_TYPE_ANY))
		break;
	      else if (unformat (line_input, "l7 http host %_%v%_", &host))
		{
		  if (unformat (line_input, "path %_%v%_", &path))
		    break;
		}
	      else
		{
		  error = clib_error_return (0, "unknown input `%U'",
					     format_unformat_error, input);
		  goto done;
		}
	    }
	  else
	    {
	      error = clib_error_return (0, "unknown input `%U'",
					 format_unformat_error, input);
	      goto done;
	    }
	}
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, input);
	  goto done;
	}
    }

  rule_args.host = host;
  rule_args.path = path;
  rule_args.src_ip = src_ip;
  rule_args.dst_ip = dst_ip;

  rv = vnet_upf_rule_add_del(app_name, rule_index, add, &rule_args);
  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_VALUE_EXIST:
      error = clib_error_return (0, "rule already exists...");
      break;

    case VNET_API_ERROR_NO_SUCH_ENTRY:
      error = clib_error_return (0, "application or rule does not exist...");
      break;

    case VNET_API_ERROR_INSTANCE_IN_USE:
      error = clib_error_return (0, "application is in use...");
      break;

    default:
      error = clib_error_return (0, "%s returned %d", __FUNCTION__, rv);
      break;
    }

done:
  vec_free (host);
  vec_free (path);
  vec_free (app_name);
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_application_rule_add_del_command, static) =
{
  .path = "upf application",
  .short_help = "upf application <name> rule <id> (add | del) [ip src <ip> | dst <ip>] [l7 http host <regex> path <path>] ",
  .function = upf_application_rule_add_del_command_fn,
};
/* *INDENT-ON* */

static void
upf_show_rules(vlib_main_t * vm, upf_adf_app_t * app)
{
  u32 index = 0;
  u32 rule_index = 0;
  upf_adr_t *rule = NULL;

  /* *INDENT-OFF* */
  hash_foreach(rule_index, index, app->rules_by_id,
  ({
     rule = pool_elt_at_index(app->rules, index);
     vlib_cli_output (vm, "rule: %u", rule->id);

     if (rule->host)
       vlib_cli_output (vm, "host: %v", rule->host);

     if (rule->path)
       vlib_cli_output (vm, "path: %v", rule->path);
  }));
  /* *INDENT-ON* */
}

static clib_error_t *
upf_show_app_command_fn (vlib_main_t * vm,
			 unformat_input_t * input,
			 vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 *name = NULL;
  uword *p = NULL;
  clib_error_t *error = NULL;
  upf_adf_app_t *app = NULL;
  upf_main_t * sm = &upf_main;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return error;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%_%v%_", &name))
	{
	  break;
	}
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
	  format_unformat_error, input);
	  goto done;
	}
    }

  p = hash_get_mem (sm->upf_app_by_name, name);
  if (!p)
    {
      error = clib_error_return (0, "unknown application name");
      goto done;
    }

  app = pool_elt_at_index (sm->upf_apps, p[0]);
  upf_show_rules(vm, app);

done:
  vec_free (name);
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_show_app_command, static) =
{
  .path = "show upf application",
  .short_help = "show upf application <name>",
  .function = upf_show_app_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
upf_show_apps_command_fn (vlib_main_t * vm,
			  unformat_input_t * input,
			  vlib_cli_command_t * cmd)
{
  upf_main_t * sm = &upf_main;
  u8 *name = NULL;
  u32 index = 0;
  int verbose = 0;
  clib_error_t *error = NULL;
  unformat_input_t _line_input, *line_input = &_line_input;

  /* Get a line of input. */
  if (unformat_user (input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (line_input, "verbose"))
	    {
	      verbose = 1;
	      break;
	    }
	  else
	    {
	      error = clib_error_return (0, "unknown input `%U'",
					 format_unformat_error, input);
	      unformat_free (line_input);
	      return error;
	    }
	}

      unformat_free (line_input);
    }

  /* *INDENT-OFF* */
  hash_foreach(name, index, sm->upf_app_by_name,
  ({
     upf_adf_app_t *app = NULL;
     app = pool_elt_at_index(sm->upf_apps, index);
     vlib_cli_output (vm, "app: %v", app->name);

     if (verbose)
       {
	 upf_show_rules(vm, app);
       }
  }));
  /* *INDENT-ON* */

  return NULL;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_show_apps_command, static) =
{
  .path = "show upf applications",
  .short_help = "show upf applications [verbose]",
  .function = upf_show_apps_command_fn,
};
/* *INDENT-ON* */

void
foreach_upf_flows (BVT (clib_bihash_kv) * kvp,
		   void * arg)
{
  dlist_elt_t *ht_line = NULL;
  u32 index = 0;
  flow_entry_t *flow = NULL;
  flowtable_main_per_cpu_t *fmt = arg;
  u32 ht_line_head_index = (u32) kvp->value;
  flowtable_main_t * fm = &flowtable_main;
  u8 *app_name = NULL;
  upf_main_t * sm = &upf_main;
  vlib_main_t *vm = sm->vlib_main;

  if (dlist_is_empty(fmt->ht_lines, ht_line_head_index))
    return;

  ht_line = pool_elt_at_index(fmt->ht_lines, ht_line_head_index);
  index = ht_line->next;

  while (index != ht_line_head_index)
    {
      dlist_elt_t * e = pool_elt_at_index(fmt->ht_lines, index);
      flow = pool_elt_at_index(fm->flows, e->value);
      index = e->next;

      if (flow->application_id != ~0)
	{
	  upf_adf_app_t *app = pool_elt_at_index (sm->upf_apps, flow->application_id);
	  app_name = format (0, "%v", app->name);
	}
      else
	app_name = format (0, "%s", "None");

      vlib_cli_output (vm, "proto 0x%x, %U(%u) <-> %U(%u), "
		       "UL pkt %u, DL pkt %u, "
		       "Src Intf %u, Forward PDR %u, Reverse PDR %u, "
		       "app %v, lifetime %u",
		       flow->sig.s.ip4.proto,
		       format_ip4_address, &flow->sig.s.ip4.src,
		       ntohs(flow->sig.s.ip4.port_src),
		       format_ip4_address, &flow->sig.s.ip4.dst,
		       ntohs(flow->sig.s.ip4.port_dst),
		       flow->stats[0].pkts,
		       flow->stats[1].pkts,
		       flow->src_intf,
		       flow->pdr_id[FT_FORWARD],
		       flow->pdr_id[FT_REVERSE],
		       app_name,
		       flow->lifetime);

      vec_free(app_name);
    }
}

static clib_error_t *
vnet_upf_flow_timeout_update(flowtable_timeout_type_t type, u16 timeout)
{
  return flowtable_lifetime_update(type, timeout);
}

int upf_flow_timeout_update (flowtable_timeout_type_t type, u16 timeout)
{
  int rv = 0;

  vnet_upf_flow_timeout_update(type, timeout);

  return rv;
}

static u16
vnet_upf_get_flow_timeout(flowtable_timeout_type_t type)
{
  return flowtable_lifetime_get(type);
}

static clib_error_t *
upf_flow_timeout_command_fn (vlib_main_t * vm,
			     unformat_input_t * input,
			     vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u16 timeout = 0;
  clib_error_t *error = NULL;
  flowtable_timeout_type_t type = FT_TIMEOUT_TYPE_UNKNOWN;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return error;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "ip4 %u", &timeout))
	{
	  type = FT_TIMEOUT_TYPE_IPV4;
	  break;
	}
      if (unformat (line_input, "ip6 %u", &timeout))
	{
	  type = FT_TIMEOUT_TYPE_IPV6;
	  break;
	}
      if (unformat (line_input, "icmp %u", &timeout))
	{
	  type = FT_TIMEOUT_TYPE_ICMP;
	  break;
	}
      if (unformat (line_input, "udp %u", &timeout))
	{
	  type = FT_TIMEOUT_TYPE_UDP;
	  break;
	}
      if (unformat (line_input, "tcp %u", &timeout))
	{
	  type = FT_TIMEOUT_TYPE_TCP;
	  break;
	}
      else
	{
	  error = unformat_parse_error (line_input);
	  goto done;
	}
    }

  error = vnet_upf_flow_timeout_update(type, timeout);

done:
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_flow_timeout_command, static) =
{
  .path = "upf flow timeout",
  .short_help = "upf flow timeout (default | ip4 | ip6 | icmp | udp | tcp) <seconds>",
  .function = upf_flow_timeout_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
upf_show_flow_timeout_command_fn (vlib_main_t * vm,
				  unformat_input_t * input,
				  vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u16 timeout = 0;
  clib_error_t *error = NULL;
  flowtable_timeout_type_t type = FT_TIMEOUT_TYPE_UNKNOWN;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return error;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "ip4"))
	{
	  type = FT_TIMEOUT_TYPE_IPV4;
	  break;
	}
      if (unformat (line_input, "ip6"))
	{
	  type = FT_TIMEOUT_TYPE_IPV6;
	  break;
	}
      if (unformat (line_input, "icmp"))
	{
	  type = FT_TIMEOUT_TYPE_ICMP;
	  break;
	}
      if (unformat (line_input, "udp"))
	{
	  type = FT_TIMEOUT_TYPE_UDP;
	  break;
	}
      if (unformat (line_input, "tcp"))
	{
	  type = FT_TIMEOUT_TYPE_TCP;
	  break;
	}
      else
	{
	  error = unformat_parse_error (line_input);
	  goto done;
	}
    }

  timeout = vnet_upf_get_flow_timeout(type);
  vlib_cli_output (vm, "%u", timeout);

done:
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_show_flow_timeout_command, static) =
{
  .path = "show upf flow timeout",
  .short_help = "upf flow timeout (default | ip4 | ip6 | icmp | udp | tcp)",
  .function = upf_show_flow_timeout_command_fn,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
