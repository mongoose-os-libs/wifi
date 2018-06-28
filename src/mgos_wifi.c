/*
 * Copyright (c) 2014-2018 Cesanta Software Limited
 * All rights reserved
 *
 * Licensed under the Apache License, Version 2.0 (the ""License"");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an ""AS IS"" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "mgos_wifi.h"
#include "mgos_wifi_hal.h"

#include <stdbool.h>
#include <stdlib.h>

#include "common/cs_dbg.h"
#include "common/queue.h"

#include "mgos_gpio.h"
#include "mgos_mongoose.h"
#include "mgos_net_hal.h"
#include "mgos_sys_config.h"
#include "mgos_system.h"
#include "mgos_timers.h"
#include "mgos_event.h"

#include "mongoose.h"

#define NUM_STA_CFG 3

struct cb_info {
  void *cb;
  void *arg;
  SLIST_ENTRY(cb_info) next;
};
static SLIST_HEAD(s_wifi_cbs, cb_info) s_wifi_cbs;
static SLIST_HEAD(s_scan_cbs, cb_info) s_scan_cbs;
static bool s_scan_in_progress = false;

enum mgos_wifi_status s_sta_status = MGOS_WIFI_DISCONNECTED;
static bool s_sta_should_reconnect = false;

struct mgos_rlock_type *s_wifi_lock = NULL;

static int s_cur_sta_cfg_idx = -1;
static struct mgos_config_wifi *s_cur_cfg = NULL;
static mgos_timer_id s_connect_timer_id = MGOS_INVALID_TIMER_ID;

static inline void wifi_lock(void) {
  mgos_rlock(s_wifi_lock);
}

static inline void wifi_unlock(void) {
  mgos_runlock(s_wifi_lock);
}

static const struct mgos_config_wifi_sta *mgos_wifi_get_sta_cfg(
    const struct mgos_config_wifi *cfg, int idx) {
  if (cfg == NULL) return NULL;
  switch (idx) {
    case 0:
      return &cfg->sta;
    case 1:
      return (const struct mgos_config_wifi_sta *) &cfg->sta1;
    case 2:
      return (const struct mgos_config_wifi_sta *) &cfg->sta2;
  }
  return NULL;
}

static int mgos_wifi_get_next_sta_cfg_idx(const struct mgos_config_wifi *cfg,
                                          int start) {
  if (cfg == NULL) return -1;
  int idx = start;
  char *msg = NULL;
  do {
    const struct mgos_config_wifi_sta *sta_cfg =
        mgos_wifi_get_sta_cfg(cfg, idx);
    if (sta_cfg && sta_cfg->enable) {
      if (mgos_wifi_validate_sta_cfg(sta_cfg, &msg)) {
        LOG(LL_INFO, ("WiFi STA: Using config %d", idx));
        return idx;
      } else {
        free(msg);
        msg = NULL;
      }
    }
    idx = (idx + 1) % NUM_STA_CFG;
  } while (idx != start);
  return -1;
}

static void mgos_wifi_sta_connect_timeout_timer_cb(void *arg);

static void mgos_wifi_on_change_cb(void *arg) {
  bool reconnect = false;
  enum mgos_net_event ev = (enum mgos_net_event)(intptr_t) arg;
  switch (ev) {
    case MGOS_NET_EV_DISCONNECTED: {
      if ((s_sta_status == MGOS_WIFI_CONNECTED ||
           s_sta_status == MGOS_WIFI_IP_ACQUIRED) &&
          s_sta_should_reconnect) {
        reconnect = s_sta_should_reconnect;
      }
      s_sta_status = MGOS_WIFI_DISCONNECTED;
      break;
    }
    case MGOS_NET_EV_CONNECTING: {
      s_sta_status = MGOS_WIFI_CONNECTING;
      break;
    }
    case MGOS_NET_EV_CONNECTED: {
      s_sta_status = MGOS_WIFI_CONNECTED;
      break;
    }
    case MGOS_NET_EV_IP_ACQUIRED: {
      s_sta_status = MGOS_WIFI_IP_ACQUIRED;
      mgos_clear_timer(s_connect_timer_id);
      s_connect_timer_id = MGOS_INVALID_TIMER_ID;
      if (s_cur_cfg && s_cur_cfg->sta_cfg_idx != s_cur_sta_cfg_idx) {
        LOG(LL_INFO, ("WiFi STA: New current config: %d", s_cur_sta_cfg_idx));
        s_cur_cfg->sta_cfg_idx = s_cur_sta_cfg_idx;
        if (s_cur_cfg == mgos_sys_config_get_wifi()) {
          save_cfg(&mgos_sys_config, NULL);
        }
      }
      break;
    }
  }

  mgos_net_dev_event_cb(MGOS_NET_IF_TYPE_WIFI, MGOS_NET_IF_WIFI_STA, ev);

  struct cb_info *e, *te;
  wifi_lock();
  enum mgos_wifi_status ws = s_sta_status;
  SLIST_FOREACH_SAFE(e, &s_wifi_cbs, next, te) {
    wifi_unlock();
    ((mgos_wifi_changed_t) e->cb)(ws, e->arg);
    wifi_lock();
  }
  wifi_unlock();

  if (reconnect && s_sta_should_reconnect) {
    mgos_wifi_connect();
  }
}

void mgos_wifi_dev_ap_on_change_cb(enum mgos_wifi_event ev){
  // struct mgos_wifi_ap_sta_connected_arg evd = {
  //     //
  // };
  // mgos_event_trigger(ev, &evd);
  mgos_event_trigger(ev, NULL); // not sure correct way to pass ev info from platform specific files
}

void mgos_wifi_dev_on_change_cb(enum mgos_net_event ev) {
  mgos_invoke_cb(mgos_wifi_on_change_cb, (void *) ev, false /* from_isr */);
}

void mgos_wifi_add_on_change_cb(mgos_wifi_changed_t cb, void *arg) {
  struct cb_info *e = (struct cb_info *) calloc(1, sizeof(*e));
  if (e == NULL) return;
  e->cb = cb;
  e->arg = arg;
  SLIST_INSERT_HEAD(&s_wifi_cbs, e, next);
}

void mgos_wifi_remove_on_change_cb(mgos_wifi_changed_t cb, void *arg) {
  struct cb_info *e;
  SLIST_FOREACH(e, &s_wifi_cbs, next) {
    if (e->cb == cb && e->arg == arg) {
      SLIST_REMOVE(&s_wifi_cbs, e, cb_info, next);
      return;
    }
  }
}

bool mgos_wifi_validate_sta_cfg(const struct mgos_config_wifi_sta *cfg,
                                char **msg) {
  if (!cfg->enable) return true;
  if (mgos_conf_str_empty(cfg->ssid) || strlen(cfg->ssid) > 31) {
    if (!mg_asprintf(msg, 0, "%s %s must be between %d and %d chars", "STA",
                     "SSID", 1, 31)) {
    }
    return false;
  }
  /* Note: WEP allows 5 char passwords. */
  if (!mgos_conf_str_empty(cfg->pass) &&
      (strlen(cfg->pass) < 5 || strlen(cfg->pass) > 63)) {
    if (!mg_asprintf(msg, 0, "%s %s must be between %d and %d chars", "STA",
                     "password", 8, 63)) {
    }
    return false;
  }
  if (!mgos_conf_str_empty(cfg->ip)) {
    if (mgos_conf_str_empty(cfg->netmask)) {
      if (!mg_asprintf(msg, 0,
                       "Station static IP is set but no netmask provided")) {
      }
      return false;
    }
    /* TODO(rojer): More validation here: IP & gw within the same net. */
  }
  return true;
}

bool mgos_wifi_validate_ap_cfg(const struct mgos_config_wifi_ap *cfg,
                               char **msg) {
  if (!cfg->enable) return true;
  if (mgos_conf_str_empty(cfg->ssid) || strlen(cfg->ssid) > 31) {
    if (!mg_asprintf(msg, 0, "%s %s must be between %d and %d chars", "AP",
                     "SSID", 1, 31)) {
    }
    return false;
  }
  if (!mgos_conf_str_empty(cfg->pass) &&
      (strlen(cfg->pass) < 8 || strlen(cfg->pass) > 63)) {
    if (!mg_asprintf(msg, 0, "%s %s must be between %d and %d chars", "AP",
                     "password", 8, 63)) {
    }
    return false;
  }
  if (mgos_conf_str_empty(cfg->ip) || mgos_conf_str_empty(cfg->netmask) ||
      mgos_conf_str_empty(cfg->dhcp_start) ||
      mgos_conf_str_empty(cfg->dhcp_end)) {
    *msg = strdup("AP IP, netmask, DHCP start and end addresses must be set");
    return false;
  }
  /* TODO(rojer): More validation here. DHCP range, netmask, GW (if set). */
  return true;
}

static bool validate_wifi_cfg(const struct mgos_config *cfg, char **msg) {
  return (mgos_wifi_validate_ap_cfg(&cfg->wifi.ap, msg) &&
          mgos_wifi_validate_sta_cfg(&cfg->wifi.sta, msg));
}

bool mgos_wifi_setup_sta(const struct mgos_config_wifi_sta *cfg) {
  char *err_msg = NULL;
  if (!mgos_wifi_validate_sta_cfg(cfg, &err_msg)) {
    LOG(LL_ERROR, ("WiFi STA: %s", err_msg));
    free(err_msg);
    return false;
  }
  wifi_lock();
  bool ret = mgos_wifi_dev_sta_setup(cfg);
  if (ret && cfg->enable) {
    LOG(LL_INFO, ("WiFi STA: Connecting to %s", cfg->ssid));
    ret = mgos_wifi_connect();
  }
  if (ret) s_cur_cfg = NULL;
  wifi_unlock();
  return ret;
}

static void wifi_ap_disable_timer_cb(void *arg) {
  if (!mgos_sys_config_get_wifi_ap_enable()) return;
  LOG(LL_INFO, ("Disabling AP"));
  mgos_sys_config_set_wifi_ap_enable(false);
  save_cfg(&mgos_sys_config, NULL);
  mgos_wifi_setup_ap(&mgos_sys_config.wifi.ap);
  (void) arg;
}

bool mgos_wifi_setup_ap(const struct mgos_config_wifi_ap *cfg) {
  char *err_msg = NULL;
  if (!mgos_wifi_validate_ap_cfg(cfg, &err_msg)) {
    LOG(LL_ERROR, ("WiFi AP: %s", err_msg));
    free(err_msg);
    return false;
  }
  wifi_lock();
  bool ret = mgos_wifi_dev_ap_setup(cfg);
  wifi_unlock();
  if (cfg->enable && ret && cfg->disable_after > 0) {
    LOG(LL_INFO, ("WiFi AP: Enabled for %d seconds", cfg->disable_after));
    mgos_set_timer(cfg->disable_after * 1000, 0, wifi_ap_disable_timer_cb,
                   NULL);
  }
  return ret;
}

bool mgos_wifi_connect(void) {
  wifi_lock();
  bool ret = mgos_wifi_dev_sta_connect();
  s_sta_should_reconnect = ret;
  if (ret) {
    mgos_wifi_dev_on_change_cb(MGOS_NET_EV_CONNECTING);
    if (s_cur_cfg != NULL && s_cur_cfg->sta_connect_timeout > 0 &&
        s_connect_timer_id == MGOS_INVALID_TIMER_ID) {
      s_connect_timer_id =
          mgos_set_timer(s_cur_cfg->sta_connect_timeout * 1000, 0,
                         mgos_wifi_sta_connect_timeout_timer_cb, NULL);
    }
  }
  wifi_unlock();
  return ret;
}

bool mgos_wifi_disconnect(void) {
  if (s_cur_sta_cfg_idx < 0) return false;  // Not inited.
  wifi_lock();
  s_sta_should_reconnect = false;
  bool ret = mgos_wifi_dev_sta_disconnect();
  if (ret) {
    mgos_clear_timer(s_connect_timer_id);
    s_connect_timer_id = MGOS_INVALID_TIMER_ID;
  }
  wifi_unlock();
  return ret;
}

static void mgos_wifi_sta_connect_timeout_timer_cb(void *arg) {
  wifi_lock();
  int new_idx = -1;
  struct mgos_config_wifi *cfg = s_cur_cfg;
  s_connect_timer_id = MGOS_INVALID_TIMER_ID;
  LOG(LL_ERROR, ("WiFi STA: Connect timeout"));
  if (cfg == NULL) goto out;
  new_idx = mgos_wifi_get_next_sta_cfg_idx(
      cfg, (s_cur_sta_cfg_idx + 1) % NUM_STA_CFG);
  /* Note: even if the config didn't change, disconnect and
   * reconnect to re-init WiFi. */
  mgos_wifi_disconnect();
  mgos_wifi_setup_sta(mgos_wifi_get_sta_cfg(cfg, new_idx));
  s_cur_cfg = cfg;
  s_cur_sta_cfg_idx = new_idx;
out:
  wifi_unlock();
  (void) arg;
}

enum mgos_wifi_status mgos_wifi_get_status(void) {
  return s_sta_status;
}

char *mgos_wifi_get_status_str(void) {
  const char *s = NULL;
  enum mgos_wifi_status st = mgos_wifi_get_status();
  switch (st) {
    case MGOS_WIFI_DISCONNECTED:
      s = "disconnected";
      break;
    case MGOS_WIFI_CONNECTING:
      s = "connecting";
      break;
    case MGOS_WIFI_CONNECTED:
      s = "connected";
      break;
    case MGOS_WIFI_IP_ACQUIRED:
      s = "got ip";
      break;
  }
  return (s != NULL ? strdup(s) : NULL);
}

struct scan_result_info {
  int num_res;
  struct mgos_wifi_scan_result *res;
};

static void scan_cb_cb(void *arg) {
  struct scan_result_info *ri = (struct scan_result_info *) arg;
  wifi_lock();
  SLIST_HEAD(scan_cbs, cb_info) scan_cbs;
  memcpy(&scan_cbs, &s_scan_cbs, sizeof(scan_cbs));
  memset(&s_scan_cbs, 0, sizeof(s_scan_cbs));
  wifi_unlock();
  struct cb_info *cbi, *cbit;
  SLIST_FOREACH_SAFE(cbi, &scan_cbs, next, cbit) {
    ((mgos_wifi_scan_cb_t) cbi->cb)(ri->num_res, ri->res, cbi->arg);
    free(cbi);
  }
  free(ri->res);
  free(ri);
}

void mgos_wifi_dev_scan_cb(int num_res, struct mgos_wifi_scan_result *res) {
  if (!s_scan_in_progress) return;
  LOG(LL_INFO, ("WiFi scan done, num_res %d", num_res));
  struct scan_result_info *ri =
      (struct scan_result_info *) calloc(1, sizeof(*ri));
  ri->num_res = num_res;
  ri->res = res;
  s_scan_in_progress = false;
  mgos_invoke_cb(scan_cb_cb, ri, false /* from_isr */);
}

void mgos_wifi_scan(mgos_wifi_scan_cb_t cb, void *arg) {
  struct cb_info *cbi = (struct cb_info *) calloc(1, sizeof(*cbi));
  if (cbi == NULL) return;
  cbi->cb = cb;
  cbi->arg = arg;
  wifi_lock();
  SLIST_INSERT_HEAD(&s_scan_cbs, cbi, next);
  if (!s_scan_in_progress) {
    s_scan_in_progress = true;
    if (!mgos_wifi_dev_start_scan()) {
      mgos_wifi_dev_scan_cb(-1, NULL);
    }
  }
  wifi_unlock();
}

bool mgos_wifi_setup(struct mgos_config_wifi *cfg) {
  bool result = false, trigger_ap = false;
  int gpio = cfg->ap.trigger_on_gpio;

  if (gpio >= 0) {
    mgos_gpio_set_mode(gpio, MGOS_GPIO_MODE_INPUT);
    mgos_gpio_set_pull(gpio, MGOS_GPIO_PULL_UP);
    trigger_ap = (mgos_gpio_read(gpio) == 0);
  }

  int sta_cfg_idx = mgos_wifi_get_next_sta_cfg_idx(cfg, cfg->sta_cfg_idx);
  const struct mgos_config_wifi_sta *sta_cfg =
      mgos_wifi_get_sta_cfg(cfg, sta_cfg_idx);

  if (trigger_ap || (cfg->ap.enable && sta_cfg == NULL)) {
    struct mgos_config_wifi_ap ap_cfg;
    memcpy(&ap_cfg, &cfg->ap, sizeof(ap_cfg));
    ap_cfg.enable = true;
    LOG(LL_INFO, ("WiFi mode: %s", "AP"));
    result = mgos_wifi_setup_ap(&ap_cfg);
#ifdef MGOS_WIFI_ENABLE_AP_STA /* ifdef-ok */
  } else if (cfg->ap.enable && sta_cfg != NULL && cfg->ap.keep_enabled) {
    LOG(LL_INFO, ("WiFi mode: %s", "AP+STA"));
    result = (mgos_wifi_setup_ap(&cfg->ap) && mgos_wifi_setup_sta(sta_cfg));
#endif
  } else if (sta_cfg != NULL) {
    LOG(LL_INFO, ("WiFi mode: %s", "STA"));
    result = mgos_wifi_setup_sta(sta_cfg);
  } else {
    LOG(LL_INFO, ("WiFi mode: %s", "off"));
    result = true;
  }

  if (result) {
    s_cur_cfg = cfg;
    s_cur_sta_cfg_idx = sta_cfg_idx;
    mgos_clear_timer(s_connect_timer_id);
    s_connect_timer_id = MGOS_INVALID_TIMER_ID;
    if (sta_cfg != NULL && cfg->sta_connect_timeout > 0) {
      s_connect_timer_id =
          mgos_set_timer(cfg->sta_connect_timeout * 1000, 0,
                         mgos_wifi_sta_connect_timeout_timer_cb, NULL);
    }
  }

  return result;
}

/*
 * Handler of DNS requests, it resolves mgos_sys_config_get_wifi_ap_hostname()
 * to the IP address of wifi AP (mgos_sys_config_get_wifi_ap_ip()).
 */
static void dns_ev_handler(struct mg_connection *c, int ev, void *ev_data,
                           void *user_data) {
  struct mg_dns_message *msg = (struct mg_dns_message *) ev_data;
  struct mbuf reply_buf;
  int i;

  if (ev != MG_DNS_MESSAGE) return;

  mbuf_init(&reply_buf, 512);
  struct mg_dns_reply reply = mg_dns_create_reply(&reply_buf, msg);
  for (i = 0; i < msg->num_questions; i++) {
    char rname[256];
    struct mg_dns_resource_record *rr = &msg->questions[i];
    mg_dns_uncompress_name(msg, &rr->name, rname, sizeof(rname) - 1);
    if (rr->rtype == MG_DNS_A_RECORD &&
        strcmp(rname, mgos_sys_config_get_wifi_ap_hostname()) == 0) {
      uint32_t ip;
      if (inet_pton(AF_INET, mgos_sys_config_get_wifi_ap_ip(), &ip)) {
        mg_dns_reply_record(&reply, rr, NULL, rr->rtype, 10, &ip, 4);
      }
    }
  }
  mg_dns_send_reply(c, &reply);
  mbuf_free(&reply_buf);
  (void) user_data;
}

bool mgos_wifi_init(void) {

  if (!mgos_event_register_base(MGOS_WIFI_EV_BASE, "wfi")) {
    // return MGOS_INIT_NET_INIT_FAILED; // Should we trigger NET init event failed?? Or add a new one in mgos_init.h for wifi?
  }

  s_wifi_lock = mgos_rlock_create();
  mgos_register_config_validator(validate_wifi_cfg);
  mgos_wifi_dev_init();
  bool ret =
      mgos_wifi_setup((struct mgos_config_wifi *) mgos_sys_config_get_wifi());
  if (!ret) {
    return ret;
  }

  /* Setup DNS handler if needed */
  if (mgos_sys_config_get_wifi_ap_enable() &&
      mgos_sys_config_get_wifi_ap_hostname() != NULL) {
    char buf[50];
    sprintf(buf, "udp://%s:53", mgos_sys_config_get_wifi_ap_ip());
    struct mg_connection *dns_conn =
        mg_bind(mgos_get_mgr(), buf, dns_ev_handler, 0);
    mg_set_protocol_dns(dns_conn);
  }

  s_cur_sta_cfg_idx = 0;

  return true;
}

void mgos_wifi_deinit(void) {
  mgos_wifi_dev_deinit();
}
