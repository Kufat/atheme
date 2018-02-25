/*
 * Copyright (c) 2010 Atheme Development Group
 * Rights to this code are as documented in doc/LICENSE.
 *
 * This file contains code for the NickServ SET ENFORCETIMEOUT function.
 */

#include "atheme.h"

mowgli_patricia_t **ns_set_cmdtree;

static void ns_cmd_set_enforcetime(struct sourceinfo *si, int parc, char *parv[]);

static struct command ns_set_enforcetime = { "ENFORCETIME", N_("Amount of time it takes before nickname protection occurs."), AC_NONE, 1, ns_cmd_set_enforcetime, { .path = "nickserv/set_enforcetime" } };

static void
mod_init(struct module *const restrict m)
{
	MODULE_TRY_REQUEST_DEPENDENCY(m, "nickserv/enforce");
	MODULE_TRY_REQUEST_SYMBOL(m, ns_set_cmdtree, "nickserv/set_core", "ns_set_cmdtree");

	command_add(&ns_set_enforcetime, *ns_set_cmdtree);
}

static void
mod_deinit(const enum module_unload_intent ATHEME_VATTR_UNUSED intent)
{
	command_delete(&ns_set_enforcetime, *ns_set_cmdtree);
}

static void
ns_cmd_set_enforcetime(struct sourceinfo *si, int parc, char *parv[])
{
	char *setting = parv[0];

	if (!setting)
	{
		command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "ENFORCETIME");
		command_fail(si, fault_needmoreparams, _("Syntax: SET ENFORCETIME TIME|DEFAULT"));
		return;
	}

	int enforcetime = atoi(parv[0]);

	if (strcasecmp(setting, "DEFAULT") == 0)
	{
		if (metadata_find(si->smu, "private:doenforce"))
		{
			logcommand(si, CMDLOG_SET, "SET:ENFORCETIME:DEFAULT");
			metadata_delete(si->smu, "private:enforcetime");
			command_success_nodata(si, _("The \2%s\2 for account \2%s\2 has been reset to default, which is \2%d\2 seconds."), "ENFORCETIME", entity(si->smu)->name, nicksvs.enforce_delay);
		}
		else
		{
			command_fail(si, fault_nochange, _("The \2%s\2 flag is not set for account \2%s\2."), "ENFORCE", entity(si->smu)->name);
		}
	}
	else if (enforcetime > 0 && enforcetime <= 180)
	{
		if (metadata_find(si->smu, "private:doenforce"))
		{
			logcommand(si, CMDLOG_SET, "SET:ENFORCETIME: %d", enforcetime);
			metadata_add(si->smu, "private:enforcetime", setting);
			command_success_nodata(si, _("The \2%s\2 for account \2%s\2 has been set to \2%d\2 seconds."), "ENFORCETIME", entity(si->smu)->name, enforcetime);
		}
		else
		{
			command_fail(si, fault_nochange, _("The \2%s\2 flag is not set for account \2%s\2."), "ENFORCE", entity(si->smu)->name);
		}
	}
	else
	{
		command_fail(si, fault_badparams, STR_INVALID_PARAMS, "ENFORCETIME");
	}
}

SIMPLE_DECLARE_MODULE_V1("nickserv/set_enforcetime", MODULE_UNLOAD_CAPABILITY_OK)
