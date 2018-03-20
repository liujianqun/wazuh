/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "syscheck.h"
#include "config/config.h"
#include "rootcheck/rootcheck.h"

#ifdef WIN32
static char *SYSCHECK_EMPTY[] = { NULL };
static registry REGISTRY_EMPTY[] = { { NULL, 0 } };
#endif


int Read_Syscheck_Config(const char *cfgfile)
{
    int modules = 0;

    modules |= CSYSCHECK;

    syscheck.rootcheck      = 0;
    syscheck.disabled       = 0;
    syscheck.skip_nfs       = 0;
    syscheck.scan_on_start  = 1;
    syscheck.time           = SYSCHECK_WAIT * 2;
    syscheck.ignore         = NULL;
    syscheck.ignore_regex   = NULL;
    syscheck.nodiff         = NULL;
    syscheck.nodiff_regex   = NULL;
    syscheck.scan_day       = NULL;
    syscheck.scan_time      = NULL;
    syscheck.dir            = NULL;
    syscheck.opts           = NULL;
    syscheck.realtime       = NULL;
#ifdef WIN32
    syscheck.registry       = NULL;
    syscheck.reg_fp         = NULL;
#endif
    syscheck.prefilter_cmd  = NULL;

    mdebug2("Reading Configuration [%s]", cfgfile);

    /* Read config */
    if (ReadConfig(modules, cfgfile, &syscheck, NULL) < 0) {
        return (OS_INVALID);
    }

#ifdef CLIENT
    mdebug2("Reading Client Configuration [%s]", cfgfile);

    /* Read shared config */
    modules |= CAGENT_CONFIG;
    ReadConfig(modules, AGENTCONFIG, &syscheck, NULL);
#endif

#ifndef WIN32
    /* We must have at least one directory to check */
    if (!syscheck.dir || syscheck.dir[0] == NULL) {
        return (1);
    }
#else
    /* We must have at least one directory or registry key to check. Since
       it's possible on Windows to have syscheck enabled but only monitoring
       either the filesystem or the registry, both lists must be valid,
       even if empty.
     */
    if (!syscheck.dir) {
        syscheck.dir = SYSCHECK_EMPTY;
    }
    if (!syscheck.registry) {
            syscheck.registry = REGISTRY_EMPTY;
    }
    if ((syscheck.dir[0] == NULL) && (syscheck.registry[0].entry == NULL)) {
        return (1);
    }
#endif

    return (0);
}

cJSON *getSyscheckConfig(void) {

    if (!syscheck.dir) {
        return NULL;
    }

    cJSON *root = cJSON_CreateObject();
    cJSON *syscfg = cJSON_CreateObject();
    unsigned int i;

    if (syscheck.disabled) cJSON_AddStringToObject(syscfg,"disabled","yes"); else cJSON_AddStringToObject(syscfg,"disabled","no");
    cJSON_AddNumberToObject(syscfg,"frequency",syscheck.time);
    if (syscheck.skip_nfs) cJSON_AddStringToObject(syscfg,"skip_nfs","yes"); else cJSON_AddStringToObject(syscfg,"skip_nfs","no");
    if (syscheck.scan_on_start) cJSON_AddStringToObject(syscfg,"scan_on_start","yes"); else cJSON_AddStringToObject(syscfg,"scan_on_start","no");
    if (syscheck.scan_day) cJSON_AddStringToObject(syscfg,"scan_day",syscheck.scan_day);
    if (syscheck.scan_time) cJSON_AddStringToObject(syscfg,"scan_time",syscheck.scan_time);
    if (syscheck.dir) {
        cJSON *dirs = cJSON_CreateArray();
        for (i=0;syscheck.dir[i];i++) {
            cJSON_AddItemToArray(dirs, cJSON_CreateString(syscheck.dir[i]));
        }
        cJSON_AddItemToObject(syscfg,"directories",dirs);
    }
    if (syscheck.nodiff) {
        cJSON *ndfs = cJSON_CreateArray();
        for (i=0;syscheck.nodiff[i];i++) {
            cJSON_AddItemToArray(ndfs, cJSON_CreateString(syscheck.nodiff[i]));
        }
        cJSON_AddItemToObject(syscfg,"nodiff",ndfs);
    }
    if (syscheck.ignore) {
        cJSON *igns = cJSON_CreateArray();
        for (i=0;syscheck.ignore[i];i++) {
            cJSON_AddItemToArray(igns, cJSON_CreateString(syscheck.ignore[i]));
        }
        cJSON_AddItemToObject(syscfg,"ignore",igns);
    }
#ifdef WIN32
    if (syscheck.registry) {
        cJSON *rg = cJSON_CreateArray();
        for (i=0;syscheck.registry[i].entry;i++) {
            cJSON *pair = cJSON_CreateObject();
            cJSON_AddStringToObject(pair,"entry",syscheck.registry[i].entry);
            cJSON_AddNumberToObject(pair,"arch",syscheck.registry[i].arch);
            cJSON_AddItemToArray(rg, pair);
        }
        cJSON_AddItemToObject(syscfg,"registry",rg);
    }
    if (syscheck.registry_ignore) {
        cJSON *rgi = cJSON_CreateArray();
        for (i=0;syscheck.registry_ignore[i].entry;i++) {
            cJSON *pair = cJSON_CreateObject();
            cJSON_AddStringToObject(pair,"entry",syscheck.registry_ignore[i].entry);
            cJSON_AddNumberToObject(pair,"arch",syscheck.registry_ignore[i].arch);
            cJSON_AddItemToArray(rgi, pair);
        }
        cJSON_AddItemToObject(syscfg,"registry_ignore",rgi);
    }
#endif
    if (syscheck.prefilter_cmd) cJSON_AddStringToObject(syscfg,"prefilter_cmd",syscheck.prefilter_cmd);

    cJSON_AddItemToObject(root,"syscheck",syscfg);

    return root;
}


cJSON *getSyscheckInternalOptions(void) {

    cJSON *root = cJSON_CreateObject();
    cJSON *internals = cJSON_CreateObject();

    cJSON_AddNumberToObject(internals,"syscheck.sleep",syscheck.tsleep);
    cJSON_AddNumberToObject(internals,"syscheck.sleep_after",syscheck.sleep_after);
    cJSON_AddNumberToObject(internals,"syscheck.debug",sys_debug_level);
    cJSON_AddNumberToObject(internals,"rootcheck.sleep",rootcheck.tsleep);

    cJSON_AddItemToObject(root,"internal_options",internals);

    return root;
}
