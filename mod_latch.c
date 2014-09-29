/*
 * This Apache module implements a latch-protected directory
 * Copyright (C) 2014 Eleven Paths

 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.

 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.

 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <stdio.h>
#include "apr_hash.h"
#include "ap_config.h"
#include "ap_provider.h"
#include "httpd.h"
#include "http_core.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "latch.h"

/*$1
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    Configuration structure
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */

typedef struct
{
    char    context[256];
    char    appid[21];
    char    secretkey[41];
    char    accountid[65];
    int     enabled;
} latch_config;

/*$1
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    Prototypes
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */

static int    latch_handler(request_rec *r);
const char    *latch_set_enabled(cmd_parms *cmd, void *cfg, const char *arg);
const char    *latch_set_appid(cmd_parms *cmd, void *cfg, const char *arg);
const char    *latch_set_secretkey(cmd_parms *cmd, void *cfg, const char *arg);
const char    *latch_set_accountid(cmd_parms *cmd, void *cfg, const char *arg);
void          *create_dir_conf(apr_pool_t *pool, char *context);
void          *merge_dir_conf(apr_pool_t *pool, void *BASE, void *ADD);
static void   register_hooks(apr_pool_t *pool);

/*$1
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    Configuration directives
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */

static const command_rec    directives[] =
{
    AP_INIT_TAKE1("latchEnabled", latch_set_enabled, NULL, ACCESS_CONF, "Enable or disable mod_latch"),
    AP_INIT_TAKE1("latchAppId", latch_set_appid, NULL, ACCESS_CONF, "Set AppId"),
    AP_INIT_TAKE1("latchSecretKey", latch_set_secretkey, NULL, ACCESS_CONF, "Set SecretKey"),
    AP_INIT_TAKE1("latchAccountId", latch_set_accountid, NULL, ACCESS_CONF, "Set AccountId"),
    { NULL }
};

/*$1
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    Our name tag
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */

module AP_MODULE_DECLARE_DATA    latch_module =
{
    STANDARD20_MODULE_STUFF,
    create_dir_conf,    /* Per-directory configuration handler */
    merge_dir_conf,     /* Merge handler for per-directory configurations */
    NULL,               /* Per-server configuration handler */
    NULL,               /* Merge handler for per-server configurations */
    directives,         /* Any directives we may have for httpd */
    register_hooks      /* Our hook registering function */
};

/*
 =======================================================================================================================
    Hook registration function
 =======================================================================================================================
 */
static void register_hooks(apr_pool_t *pool)
{
     ap_hook_access_checker(latch_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

/*
 =======================================================================================================================
    Our example web service handler
 =======================================================================================================================
 */
static int latch_handler(request_rec *r)
{
    char *pairResponse;
    char *statusResponse;
    //if(!r->handler || strcmp(r->handler, "latch-handler")) return(DECLINED);

    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
    latch_config    *config = (latch_config *) ap_get_module_config(r->per_dir_config, &latch_module);
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/


    if ((config->enabled) && (strlen(config->appid) == 20) && (strlen(config->secretkey) == 40) && (strlen(config->accountid) == 64)) {
        if (config->enabled) {
            statusResponse = status(config->accountid);
            //ap_rprintf(r, "%s\n", statusResponse);
            if (strstr(statusResponse, "\"status\":\"off\"") != NULL) {
                return HTTP_NOT_FOUND;
            } else {
                return OK;
            }
        } else {
            return DECLINED;
        }
    } else {
        return DECLINED;
    }

    return OK;
}

/*
 =======================================================================================================================
    Handler for the "latchEnabled" directive
 =======================================================================================================================
 */
const char *latch_set_enabled(cmd_parms *cmd, void *cfg, const char *arg)
{
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
    latch_config    *conf = (latch_config *) cfg;
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

    if(conf)
    {
        if(!strcasecmp(arg, "on"))
            conf->enabled = 1;
        else
            conf->enabled = 0;
    }

    return NULL;
}

/*
 =======================================================================================================================
    Handler for the "latchAppId" directive
 =======================================================================================================================
 */
const char *latch_set_appid(cmd_parms *cmd, void *cfg, const char *arg)
{
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
    latch_config    *conf = (latch_config *) cfg;
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

    if(conf)
    {
        strcpy(conf->appid, arg);
    }

    return NULL;
}

/*
 =======================================================================================================================
    Handler for the "latchSecretKey" directive
 =======================================================================================================================
 */
const char *latch_set_secretkey(cmd_parms *cmd, void *cfg, const char *arg)
{
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
    latch_config    *conf = (latch_config *) cfg;
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

    if(conf)
    {
        strcpy(conf->secretkey, arg);
    }

    return NULL;
}

/*
 =======================================================================================================================
    Handler for the "latchAccountId" directive
 =======================================================================================================================
 */
const char *latch_set_accountid(cmd_parms *cmd, void *cfg, const char *arg)
{
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
    latch_config    *conf = (latch_config *) cfg;
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

    if(conf)
    {
        strcpy(conf->accountid, arg);
        if ((conf->appid) && (conf->secretkey)) {
            init(conf->appid, conf->secretkey);
        } 
    }

    return NULL;
}

/*
 =======================================================================================================================
    Function for creating new configurations for per-directory contexts
 =======================================================================================================================
 */
void *create_dir_conf(apr_pool_t *pool, char *context)
{
    context = context ? context : "Newly created configuration";

    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
    latch_config    *cfg = apr_pcalloc(pool, sizeof(latch_config));
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

    if(cfg)
    {
        {
            /* Set some default values */
            strcpy(cfg->context, context);
            cfg->enabled = 0;
            memset(cfg->appid, 0, 21);
            memset(cfg->secretkey, 0, 41);
            memset(cfg->accountid, 0, 65);
        }
    }

    return cfg;
}

/*
 =======================================================================================================================
    Merging function for configurations
 =======================================================================================================================
 */
void *merge_dir_conf(apr_pool_t *pool, void *BASE, void *ADD)
{
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
    latch_config    *base = (latch_config *) BASE;
    latch_config    *add = (latch_config *) ADD;
    latch_config    *conf = (latch_config *) create_dir_conf(pool, "Merged configuration");
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

    conf->enabled = (add->enabled == 0) ? base->enabled : add->enabled;
    strcpy(conf->appid, strlen(add->appid) ? add->appid : base->appid);
    strcpy(conf->secretkey, strlen(add->secretkey) ? add->secretkey: base->secretkey);
    strcpy(conf->accountid, strlen(add->accountid) ? add->accountid : base->accountid);
    return conf;
}
