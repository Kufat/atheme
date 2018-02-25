/*
 * Copyright (c) 2006 Jilles Tjoelker
 * Rights to this code are as documented in doc/LICENSE.
 *
 * Module to disable protect (+a) mode.
 * This will stop Atheme setting this mode by itself, but it can still
 * be used via OperServ MODE etc.
 */

#include "atheme.h"

static void
mod_init(struct module *const restrict m)
{
	if (ircd == NULL)
	{
		slog(LG_ERROR, "Module %s must be loaded after a protocol module.", m->name);
		m->mflags = MODTYPE_FAIL;
		return;
	}
	if (cnt.mychan > 0)
	{
		slog(LG_ERROR, "Module %s must be loaded from the configuration file, not via MODLOAD.", m->name);
		m->mflags = MODTYPE_FAIL;
		return;
	}

	ircd->uses_protect = false;
	update_chanacs_flags();
}

static void
mod_deinit(const enum module_unload_intent ATHEME_VATTR_UNUSED intent)
{

}

SIMPLE_DECLARE_MODULE_V1("protocol/mixin_noprotect", MODULE_UNLOAD_CAPABILITY_NEVER)
