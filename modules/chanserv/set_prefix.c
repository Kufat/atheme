/*
 * Copyright (c) 2006-2010 Atheme Development Group
 * Rights to this code are documented in doc/LICENSE.
 *
 * This file contains routines to handle the CService SET PREFIX command.
 */

#include "atheme.h"

static void cs_set_prefix_config_ready(void *unused);
static void cs_cmd_set_prefix(struct sourceinfo *si, int parc, char *parv[]);

static struct command cs_set_prefix = { "PREFIX", N_("Sets the channel PREFIX."), AC_NONE, 2, cs_cmd_set_prefix, { .path = "cservice/set_prefix" } };

mowgli_patricia_t **cs_set_cmdtree;

static void
mod_init(struct module *const restrict m)
{
	MODULE_TRY_REQUEST_SYMBOL(m, cs_set_cmdtree, "chanserv/set_core", "cs_set_cmdtree");

	command_add(&cs_set_prefix, *cs_set_cmdtree);

	hook_add_event("config_ready");
	hook_add_config_ready(cs_set_prefix_config_ready);
}

static void
mod_deinit(const enum module_unload_intent ATHEME_VATTR_UNUSED intent)
{
	command_delete(&cs_set_prefix, *cs_set_cmdtree);

	hook_del_config_ready(cs_set_prefix_config_ready);
}

static void
cs_set_prefix_config_ready(void *unused)
{
	if (chansvs.fantasy)
		cs_set_prefix.access = NULL;
	else
		cs_set_prefix.access = AC_DISABLED;
}

static int
goodprefix(const char *p)
{
	int i;
	int haschar = 0;
	int hasnonprint = 0;

	for (i = 0; p[i]; i++) {
		if (!isspace((unsigned char)p[i])) { haschar = 1; }
		if (!isprint((unsigned char)p[i])) { hasnonprint = 1; }
	}

	return haschar && !hasnonprint;
}

static void
cs_cmd_set_prefix(struct sourceinfo *si, int parc, char *parv[])
{
	struct mychan *mc;
	char *prefix = parv[1];

	if (!(mc = mychan_find(parv[0])))
	{
		command_fail(si, fault_nosuch_target, _("Channel \2%s\2 is not registered."), parv[0]);
		return;
	}

	if (!chanacs_source_has_flag(mc, si, CA_SET))
	{
		command_fail(si, fault_noprivs, _("You are not authorized to execute this command."));
		return;
	}

	if (!prefix || !strcasecmp(prefix, "DEFAULT"))
	{
		metadata_delete(mc, "private:prefix");
		logcommand(si, CMDLOG_SET, "SET:PREFIX: \2%s\2 reset", mc->name);
		verbose(mc, _("The fantasy prefix for the channel has been reset by \2%s\2"), get_source_name(si));
		command_success_nodata(si, _("The fantasy prefix for channel \2%s\2 has been reset."), parv[0]);
		return;
	}

	if (!goodprefix(prefix))
	{
		command_fail(si, fault_badparams, _("Prefix '%s' is invalid. The prefix may "
		             "contain only printable characters, and must contain at least "
		             "one non-space character."), prefix);
		return;
	}

	metadata_add(mc, "private:prefix", prefix);
	logcommand(si, CMDLOG_SET, "SET:PREFIX: \2%s\2 \2%s\2", mc->name, prefix);
	verbose(mc, _("\2%s\2 set the fantasy prefix to \2%s\2"), get_source_name(si), prefix);
	command_success_nodata(si, _("The fantasy prefix for channel \2%s\2 has been set to \2%s\2."),
                               parv[0], prefix);

}

SIMPLE_DECLARE_MODULE_V1("chanserv/set_prefix", MODULE_UNLOAD_CAPABILITY_OK)
