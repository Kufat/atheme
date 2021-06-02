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
 
#include <atheme.h>

#define BUF_LEN 50
#define MAX_VALS 15
// Used to stringify an array's contents
#define BIG_BUF_LEN (BUF_LEN * MAX_VALS)

static mowgli_patricia_t **ns_set_cmdtree = NULL;

// For default (no special keyword) ns_keyword should be null in the LAST entry

 struct pronoun_def
 {
     const char* ns_keyword;
     const char* ns_describe;
     const char* metadata_basekey;
     const char* inspircd_metakey; // used to send whois info to inspircd
 };


struct pronoun_def pronoun_defs[] = 
{
    {"ACCEPTED", _("accepts the following pronouns"), 
        "private:pronouns:accepted", "pronounAccepted"},
    {"UNACCEPTED", _("does NOT accept the following pronouns"), 
        "private:pronouns:unaccepted", "pronounNotAccepted"},
    {NULL, _("uses the following pronouns"), 
        "private:pronouns", "pronoun"}
};

// Could iterate backwards or something clever but decoupling parse and display order seems tidier
const struct pronoun_def* pronoun_defs_display_order[] = { pronoun_defs+2, pronoun_defs , pronoun_defs+1 };

const int pronoun_def_count = sizeof(pronoun_defs) / sizeof(pronoun_defs[0]);
static struct atheme_regex *re;

/*
 * Atheme doesn't provide a good way to do array storage.
 * This functiont takes a metadata key, like "private:foos", and 
 * a number of values, and stores the number of values in "private:foos"
 * while storing the values in "private:foos_00", "private:foos_01", etc.
 */

static void
delete_meta_range(struct myuser * smu, 
                  const char* basekey, 
                  int low,  //inclusive
                  int high) //exclusive
{
    char buffer[BUF_LEN] = {0};
    for (int i = low; i < high; ++i)
    {
        snprintf(buffer, BUF_LEN, "%s_%d", basekey, i);
        metadata_delete(smu, buffer);
    }
}

// Returns 0 for either "array doesn't exist" or "array has 0 elements"
static int
get_meta_array_count(struct myuser * smu, const char* basekey)
{
    struct metadata *md;
	if (md = metadata_find(smu, basekey))
    {
        return (int) strtol(md->value, NULL, 10);
    }
    else
    {
        return 0;
    }
}

static void
store_meta_array(struct myuser * smu, 
                 const char* basekey, 
                 int valcount, 
                 char** vals)
{
    char buffer[BUF_LEN] = {0};
    int count = MIN(MAX_VALS, valcount);
    int oldcount = get_meta_array_count(smu, basekey);
    
    // Tidy up old entries that won't be overwritten below
    if (oldcount > count)
    {
        delete_meta_range(smu, basekey, count, oldcount);
    }

    // Print value (array size) into buffer
    snprintf(buffer, BUF_LEN, "%d", count);
    metadata_add(smu, basekey, buffer); 
    for (int i = 0; i < count; ++i)
    {
        // Print key (base key + index) into buffer
        snprintf(buffer, BUF_LEN, "%s_%d", basekey, i);
        metadata_add(smu, buffer, vals[i]);
    }
}

// Returns null pointer if value doesn't exist
static const char*
get_meta_array_value(struct myuser * smu, const char* basekey, int offset)
{
    char buffer[BUF_LEN] = {0};
    struct metadata *md;

    snprintf(buffer, BUF_LEN, "%s_%d", basekey, offset);

	if (md = metadata_find(smu, buffer))
    {
        return md->value;
    }
    else
    {
        return NULL;
    }
}

static bool
stringify_meta_array(struct myuser * smu, 
                     const char* basekey,
                     char* sep,
                     char* buf,
                     int bufleft)
{
    int count = get_meta_array_count(smu, basekey);
    int temp = 0;
    if (!count)
    {
        return false;
    }
    for (int i = 0; i < count; ++i)
    {
        const char* val = get_meta_array_value(smu, basekey, i);
        temp = snprintf(buf, bufleft, "%s%s", ( i > 0 ? sep : "" ), val);
        bufleft -= temp;
        buf += temp;
    }
    return true;
}

static void
delete_meta_array(struct myuser * smu, const char* basekey)
{
    // Excess of caution in case we end up in a bad state:
    int deletecount = MAX(MAX_VALS, get_meta_array_count(smu, basekey));
    metadata_delete(smu, basekey);
    delete_meta_range(smu, basekey, 0, deletecount);
}

static void
inspircd_send_meta(stringref uid, const char * const key, char* value)
{
    if (PROTOCOL_INSPIRCD == ircd->type)
    {
        sts(":%s METADATA %s %s :%s", me.numeric, uid, key, value);
    }
}

static void
user_info_hook(struct hook_user_req *hdata)
{
    char buf[BIG_BUF_LEN] = {0};

	/*if (md = metadata_find(hdata->mu, "private:gender"))
    {
		command_success_nodata(hdata->si, _("identifies as: %s"),
		                            md->value);
    }*/

    for (int i = 0; i < pronoun_def_count; ++i)
    {
        const struct pronoun_def* cur = pronoun_defs_display_order[i];
        
        if(get_meta_array_count(hdata->mu, cur->metadata_basekey))
        {
            if(stringify_meta_array(hdata->mu, cur->metadata_basekey, ", ", buf, BIG_BUF_LEN))
            {
                command_success_nodata(hdata->si, "\2%s\2 %s: %s", 
                                       entity(hdata->mu)->name, 
                                       cur->ns_describe, 
                                       buf);
            }
        }
    }

}

static void
user_identify_hook(struct user *u)
{
    char buf[BIG_BUF_LEN] = {0};
    for (int i = 0; i < pronoun_def_count; ++i)
    {
        if(get_meta_array_count(u->myuser, pronoun_defs[i].metadata_basekey))
        {
            if(stringify_meta_array(u->myuser, pronoun_defs[i].metadata_basekey, ", ", buf, BIG_BUF_LEN))
            {
                inspircd_send_meta(u->uid, pronoun_defs[i].inspircd_metakey, buf);
            }

        }
    }
}

static void
do_set_pronouns(struct sourceinfo *si,
                const struct pronoun_def* def, 
                int parc, 
                char*parv[])
{
    char buf[BIG_BUF_LEN] = {0};

    const char* extraspace = def->ns_keyword ? " " : "";
    const char* keyword = def->ns_keyword ? def->ns_keyword : "";
    if (0 == parc)
    {
        delete_meta_array(si->smu, def->metadata_basekey);
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
                     _("Invalid input: '%s'. Please use a space-separated list of words containing only letters, hyphens, and apostrophes with \2%s\2."),
                     parv[i],
                     "SET PRONOUNS");
            return;
        }
    }

    store_meta_array(si->smu, def->metadata_basekey, parc, parv);

    // Do a readback
    if (!stringify_meta_array(si->smu, def->metadata_basekey, ", ", buf, BIG_BUF_LEN))
    {
        command_fail(si,
                     fault_internalerror, 
                     _("Internal error calling SET PRONOUNS."));
        //delete_meta_array(si->smu, def->metadata_basekey);
        return;
    }
    else
    {
        // "SET PRONOUNS to" vs "SET PRONOUNS ACCEPTED to"; latter needs an extra space
        command_success_nodata(si, 
                            _("Successfully SET PRONOUNS%s%s to \2%s\2."), 
                            extraspace,
                            keyword,
                            buf);
    }
    logcommand(si, CMDLOG_SET, "SET:PRONOUNS: \2%s\2", buf);
    inspircd_send_meta(si->su->uid, def->inspircd_metakey, buf);
}

// SET PRONOUNS [ACCEPTED|UNACCEPTED] [PRONOUN]*

static void
ns_cmd_set_pronouns(struct sourceinfo *si, int parc, char *parv[])
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
            //command_success_nodata(si, "Comparing %s and %s", parv[0], pronoun_defs[i].ns_keyword);
            if (parc > 0 && !strcasecmp(parv[0], pronoun_defs[i].ns_keyword))
            {
                do_set_pronouns(si, pronoun_defs+i, parc-1, parv+1);
                return;
            }
        }
        else // default option
        {
            do_set_pronouns(si, pronoun_defs+i, parc, parv);
        }
        
    }
}

static struct command ns_set_pronouns = {
	.name           = "PRONOUNS",
	.desc           = N_("Set pronouns."),
	.access         = AC_NONE,
	.maxparc        = ( MAX_VALS + 2 ),
	.cmd            = &ns_cmd_set_pronouns,
	.help           = { .path = "nickserv/set_pronouns" },
};

static void
mod_init(struct module *const restrict m)
{
	MODULE_TRY_REQUEST_SYMBOL(m, ns_set_cmdtree, "nickserv/set_core", "ns_set_cmdtree")

    re = regex_create("^[a-zA-Z\\-\']*$", AREGEX_PCRE);

    hook_add_user_info(user_info_hook);
    hook_add_user_identify(user_identify_hook);

	command_add(&ns_set_pronouns, *ns_set_cmdtree);
}

static void
mod_deinit(const enum module_unload_intent ATHEME_VATTR_UNUSED intent)
{
    hook_del_user_info(user_info_hook);
    hook_del_user_identify(user_identify_hook);

	command_delete(&ns_set_pronouns, *ns_set_cmdtree);
}


SIMPLE_DECLARE_MODULE_V1("nickserv/set_pronouns", MODULE_UNLOAD_CAPABILITY_OK)