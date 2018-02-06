/*
 * Copyright (c) 2014-2016 Cesanta Software Limited
 * All rights reserved
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

#include "mongoose/mongoose.h"

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

static inline void wifi_lock(void) {
  mgos_rlock(s_wifi_lock);
}

static inline void wifi_unlock(void) {
  mgos_runlock(s_wifi_lock);
}

static void mgos_wifi_on_change_cb(void *arg) {
  enum mgos_net_event ev = (enum mgos_net_event)(intptr_t) arg;
  enum mgos_wifi_status ws = MGOS_WIFI_DISCONNECTED;
  switch (ev) {
    case MGOS_NET_EV_DISCONNECTED: {
      ws = MGOS_WIFI_DISCONNECTED;
      if (s_sta_should_reconnect) mgos_wifi_connect();
      break;
    }
    case MGOS_NET_EV_CONNECTING: {
      s_sta_status = MGOS_WIFI_CONNECTING;
      ws = MGOS_WIFI_CONNECTING;
      break;
    }
    case MGOS_NET_EV_CONNECTED: {
      s_sta_status = MGOS_WIFI_CONNECTED;
      ws = MGOS_WIFI_CONNECTED;
      break;
    }
    case MGOS_NET_EV_IP_ACQUIRED: {
      s_sta_status = MGOS_WIFI_IP_ACQUIRED;
      ws = MGOS_WIFI_IP_ACQUIRED;
      break;
    }
  }

  mgos_net_dev_event_cb(MGOS_NET_IF_TYPE_WIFI, MGOS_NET_IF_WIFI_STA, ev);

  struct cb_info *e, *te;
  wifi_lock();
  SLIST_FOREACH_SAFE(e, &s_wifi_cbs, next, te) {
    wifi_unlock();
    ((mgos_wifi_changed_t) e->cb)(ws, e->arg);
    wifi_lock();
  }
  wifi_unlock();
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
  if (!mgos_conf_str_empty(cfg->pass) &&
      (strlen(cfg->pass) < 8 || strlen(cfg->pass) > 63)) {
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
  }
  wifi_unlock();
  return ret;
}

bool mgos_wifi_disconnect(void) {
  wifi_lock();
  s_sta_should_reconnect = false;
  bool ret = mgos_wifi_dev_sta_disconnect();
  wifi_unlock();
  return ret;
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

bool mgos_wifi_setup(const struct mgos_config_wifi *cfg) {
  bool result = false, trigger_ap = false;
  int gpio = cfg->ap.trigger_on_gpio;

  if (gpio >= 0) {
    mgos_gpio_set_mode(gpio, MGOS_GPIO_MODE_INPUT);
    mgos_gpio_set_pull(gpio, MGOS_GPIO_PULL_UP);
    trigger_ap = (mgos_gpio_read(gpio) == 0);
  }

  if (trigger_ap || (cfg->ap.enable && !cfg->sta.enable)) {
    struct mgos_config_wifi_ap ap_cfg;
    memcpy(&ap_cfg, &cfg->ap, sizeof(ap_cfg));
    ap_cfg.enable = true;
    LOG(LL_INFO, ("WiFi mode: %s", "AP"));
    result = mgos_wifi_setup_ap(&ap_cfg);
#ifdef MGOS_WIFI_ENABLE_AP_STA /* ifdef-ok */
  } else if (cfg->ap.enable && cfg->sta.enable && cfg->ap.keep_enabled) {
    LOG(LL_INFO, ("WiFi mode: %s", "AP+STA"));
    result = (mgos_wifi_setup_ap(&cfg->ap) && mgos_wifi_setup_sta(&cfg->sta));
#endif
  } else if (cfg->sta.enable) {
    LOG(LL_INFO, ("WiFi mode: %s", "STA"));
    result = mgos_wifi_setup_sta(&cfg->sta);
  } else {
    LOG(LL_INFO, ("WiFi mode: %s", "off"));
    result = true;
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
  s_wifi_lock = mgos_rlock_create();
  mgos_register_config_validator(validate_wifi_cfg);
  mgos_wifi_dev_init();
  bool ret = mgos_wifi_setup(mgos_sys_config_get_wifi());
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

  return true;
}

void mgos_wifi_deinit(void) {
  mgos_wifi_dev_deinit();
}
