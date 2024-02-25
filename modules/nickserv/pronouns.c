/* Original code: https://gist.github.com/alexwilson/95cbb8ad0f7969a6387571e51bc8bbfb
 * Copyright (c) 2017 Alex Wilson <a@ax.gy>
 * New code:
 * Copyright (c) Kufat <kufat@kufat.net>
 * 
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * Sets and displays pronoun info.
 */
 
#include "atheme.h"

#define BUF_LEN 50
#define MAX_VALS 15
// Used to stringify an array's contents
#define BIG_BUF_LEN (BUF_LEN * MAX_VALS)

// For default (no special keyword) ns_keyword should be null in the LAST entry

 struct pronoun_def
 {
	 const char* ns_keyword;
	 const char* ns_describe;
	 const char* metadata_key;
	 const char* ircd_metakey; // used to send whois info to inspircd
 };


struct pronoun_def pronoun_defs[] = 
{
	{"ACCEPTED", _("accepts the following pronouns"),
		"private:pronouns:accepted", "pronounAccepted"},
	{"UNACCEPTED", _("does NOT accept the following pronouns"),
		"private:pronouns:unaccepted", "pronounNotAccepted"},
	{NULL, _("uses the following pronouns"), // default must be last (see above)
		"private:pronouns", "pronoun"}
};

// Could iterate backwards or something clever but decoupling parse
// and display order seems tidier
const struct pronoun_def* pronoun_defs_display_order[] = { pronoun_defs+2,
	pronoun_defs , pronoun_defs+1 };

const int pronoun_def_count = sizeof(pronoun_defs) / sizeof(pronoun_defs[0]);
static struct atheme_regex *re;

static void
ircd_send_meta(stringref uid, const char * const key, char* value)
{
	if (PROTOCOL_INSPIRCD == ircd->type)
	{
		sts(":%s METADATA %s %s :%s", me.numeric, uid, key, value);
	}
}

static void
stringify_pronouns(const char * pronounstring,
				   char* sep,
				   char* buf,
				   int bufleft)
{
	int temp = 0;
	char dupstr[BIG_BUF_LEN] = {0};
	char* token = 0;
	int i = 0;

	strncpy(dupstr, pronounstring, sizeof(dupstr));
	token = strtok(dupstr, " ");
	while(token && bufleft)
	{
		temp = snprintf(buf, bufleft, "%s%s", ( i > 0 ? sep : "" ), token);
		bufleft -= temp;
		buf += temp;
		++i;
		token = strtok(0, " ");
	}
}

static void
user_info_hook(struct hook_user_req *hdata)
{
	char buf[BIG_BUF_LEN] = {0};

	for (int i = 0; i < pronoun_def_count; ++i)
	{
		const struct pronoun_def* cur = pronoun_defs_display_order[i];
		struct metadata* md;
		buf[0] = 0; // safety

		if(md = metadata_find(hdata->mu, cur->metadata_key))
		{
			stringify_pronouns(md->value, ", ", buf, BIG_BUF_LEN);
			command_success_nodata(hdata->si, "\2%s\2 %s: %s",
				entity(hdata->mu)->name,
				cur->ns_describe,
				buf);
		}
	}

}

static void
user_identify_hook(struct user *u)
{
	char buf[BIG_BUF_LEN] = {0};

	if (!u) // Shouldn't be possible
	{
		return;
	}
	for (int i = 0; i < pronoun_def_count; ++i)
	{
		const struct pronoun_def* cur = pronoun_defs_display_order[i];
		struct metadata *md;
		buf[0] = 0; // safety

		if(md = metadata_find(u->myuser, cur->metadata_key))
		{
			stringify_pronouns(md->value, ", ", buf, BIG_BUF_LEN);
			ircd_send_meta(u->uid, cur->ircd_metakey, buf);
		}
		else
		{
			ircd_send_meta(u->uid, cur->ircd_metakey, "");
		}
	}
}

static void
do_set_pronouns(struct sourceinfo *si,
				const struct pronoun_def* def,
				int parc,
				char*parv[])
{
	char buf[BIG_BUF_LEN] = {0}, *bufpos = buf;
	int bufleft = BIG_BUF_LEN, temp;

	const char* extraspace = def->ns_keyword ? " " : "";
	const char* keyword = def->ns_keyword ? def->ns_keyword : "";
	if (0 == parc)
	{
		metadata_delete(si->smu, def->metadata_key);
		command_success_nodata(si,
			_("Successfully cleared PRONOUNS%s%s."),
			extraspace,
			keyword);
		return;
	}

	for (int i = 0; i < parc; ++i)
	{
		if (!regex_match(re, parv[i]))
		{
			command_fail(si,
				fault_badparams,
				_("Invalid input: '%s'. Please use a space-separated list "
				"of words containing only letters, hyphens, and "
				"apostrophes with \2%s\2."),
				parv[i],
				"SET PRONOUNS");
			return;
		}
		else
		{
			if(bufleft <= 0)
			{
				command_fail(si,
					fault_internalerror,
					_("Internal error calling SET PRONOUNS."));
			}
			temp = snprintf(bufpos, bufleft, "%s%s", ( i > 0 ? " " : "" ), parv[i]);
			bufleft -= temp;
			bufpos += temp;
		}
	}

	metadata_add(si->smu, def->metadata_key, buf);

	// "SET PRONOUNS to" vs "SET PRONOUNS ACCEPTED to"; latter needs an extra space
	command_success_nodata(si,
		_("Successfully set PRONOUNS%s%s to \2%s\2."), 
		extraspace,
		keyword,
		buf);
	logcommand(si, CMDLOG_SET, "PRONOUNS%s%s: \2%s\2", extraspace, keyword, buf);
	if (si->su) // false if e.g. /os override
	{
		user_identify_hook(si->su);
	}
}

// PRONOUNS [ACCEPTED|UNACCEPTED] [PRONOUN]*

static void
ns_cmd_pronouns(struct sourceinfo *si, int parc, char *parv[])
{
	if (parc > MAX_VALS + 1)
	{
		command_fail(si,
			fault_badparams,
			_("Too many parameters for \2%s\2."),
			"SET PRONOUNS");
	}
	for (int i = 0; i < pronoun_def_count; ++i)
	{
		if (pronoun_defs[i].ns_keyword)
		{
			if (parc > 0 && !strcasecmp(parv[0], pronoun_defs[i].ns_keyword))
			{
				do_set_pronouns(si, pronoun_defs+i, parc-1, parv+1);
				return;
			}
		}
		else // default option; this is why the last entry's ns_keyword = 0
		{
			do_set_pronouns(si, pronoun_defs+i, parc, parv);
		}
	}
}

static struct command ns_pronouns = {
	.name		= "PRONOUNS",
	.desc		= N_("Set pronouns."),
	.access		= AC_AUTHENTICATED,
	.maxparc	= ( MAX_VALS + 2 ),
	.cmd		= &ns_cmd_pronouns,
	.help		= { .path = "nickserv/pronouns" },
};

static void
mod_init(struct module *const restrict m)
{
	struct user* u;
	mowgli_patricia_iteration_state_t state;

	re = regex_create("^[a-zA-Z\\-\']*$", AREGEX_PCRE);

	hook_add_user_info(user_info_hook);
	hook_add_user_identify(user_identify_hook);

	MODULE_TRY_REQUEST_DEPENDENCY(m, "nickserv/main")

	(void) service_named_bind_command("nickserv", &ns_pronouns);

	MOWGLI_PATRICIA_FOREACH(u, &state, userlist)
	{
		if(u->myuser)
		{
			user_identify_hook(u);
		}
	}
}

static void
mod_deinit(const enum module_unload_intent ATHEME_VATTR_UNUSED intent)
{
	hook_del_user_info(user_info_hook);
	hook_del_user_identify(user_identify_hook);

	(void) service_named_unbind_command("nickserv", &ns_pronouns);
}


VENDOR_DECLARE_MODULE_V1("nickserv/pronouns", MODULE_UNLOAD_CAPABILITY_OK, "Kufat <http://www.kufat.net>")