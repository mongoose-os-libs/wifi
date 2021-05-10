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
#include "mgos_time.h"
#include "mgos_timers.h"

#include "mongoose.h"

#include "mgos_wifi_sta.h"

struct cb_info {
  void *cb;
  void *arg;
  SLIST_ENTRY(cb_info) next;
};
static SLIST_HEAD(s_scan_cbs, cb_info) s_scan_cbs;
static bool s_scan_in_progress = false;

struct mgos_rlock_type *s_wifi_lock = NULL;

void wifi_lock(void) {
  mgos_rlock(s_wifi_lock);
}

void wifi_unlock(void) {
  mgos_runlock(s_wifi_lock);
}

static void mgos_wifi_event_cb(void *arg) {
  bool net_event = true;
  struct mgos_wifi_dev_event_info *dei =
      (struct mgos_wifi_dev_event_info *) arg;
  void *ev_arg = NULL;
  enum mgos_net_event nev = MGOS_NET_EV_DISCONNECTED;
  switch (dei->ev) {
    case MGOS_WIFI_EV_STA_DISCONNECTED: {
      ev_arg = &dei->sta_disconnected;
      nev = MGOS_NET_EV_DISCONNECTED;
      LOG(LL_INFO,
          ("WiFi STA: Disconnected, reason: %d", dei->sta_disconnected.reason));
      break;
    }
    case MGOS_WIFI_EV_STA_CONNECTING: {
      nev = MGOS_NET_EV_CONNECTING;
      break;
    }
    case MGOS_WIFI_EV_STA_CONNECTED: {
      ev_arg = &dei->sta_connected;
      nev = MGOS_NET_EV_CONNECTED;
      struct mgos_wifi_sta_connected_arg *ea = &dei->sta_connected;
      ea->rssi = mgos_wifi_sta_get_rssi();
      LOG(LL_INFO, ("WiFi STA: Connected, BSSID %02x:%02x:%02x:%02x:%02x:%02x "
                    "ch %d RSSI %d",
                    ea->bssid[0], ea->bssid[1], ea->bssid[2], ea->bssid[3],
                    ea->bssid[4], ea->bssid[5], ea->channel, ea->rssi));
      break;
    }
    case MGOS_WIFI_EV_STA_IP_ACQUIRED: {
      nev = MGOS_NET_EV_IP_ACQUIRED;
      break;
    }
    case MGOS_WIFI_EV_AP_STA_CONNECTED:
    case MGOS_WIFI_EV_AP_STA_DISCONNECTED: {
      struct mgos_wifi_ap_sta_connected_arg *ea = &dei->ap_sta_connected;
      LOG(LL_INFO,
          ("%02x:%02x:%02x:%02x:%02x:%02x %s", ea->mac[0], ea->mac[1],
           ea->mac[2], ea->mac[3], ea->mac[4], ea->mac[5],
           (dei->ev == MGOS_WIFI_EV_AP_STA_CONNECTED ? "connected"
                                                     : "disconnected")));
      net_event = false;
      ev_arg = &dei->ap_sta_connected;
      (void) ea;
      break;
    }
  }

  mgos_event_trigger(dei->ev, ev_arg);

  if (net_event) {
    mgos_net_dev_event_cb(MGOS_NET_IF_TYPE_WIFI, MGOS_NET_IF_WIFI_STA, nev);
  }

  free(dei);
}

void mgos_wifi_dev_event_cb(const struct mgos_wifi_dev_event_info *dei) {
  struct mgos_wifi_dev_event_info *deic =
      (struct mgos_wifi_dev_event_info *) calloc(1, sizeof(*deic));
  if (deic == NULL) return;
  memcpy(deic, dei, sizeof(*deic));
  mgos_invoke_cb(mgos_wifi_event_cb, deic, false /* from_isr */);
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
  int ret = true;
  char *err_msg = NULL;
  if (!mgos_wifi_validate_sta_cfg(cfg, &err_msg)) {
    LOG(LL_ERROR, ("WiFi STA: %s", err_msg));
    free(err_msg);
    return false;
  }
  mgos_wifi_sta_clear_cfgs();
  ret = mgos_wifi_sta_add_cfg(cfg);
  if (ret && cfg->enable) {
    LOG(LL_INFO, ("WiFi STA: Connecting to %s", cfg->ssid));
    ret = mgos_wifi_connect();
  }
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
  LOG(LL_DEBUG, ("WiFi scan done, num_res %d", num_res));
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
    if (mgos_wifi_dev_start_scan()) {
      s_scan_in_progress = true;
    } else {
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

  const struct mgos_config_wifi_ap dummy_ap_cfg = {.enable = false};
  const struct mgos_config_wifi_sta dummy_sta_cfg = {.enable = false};

  const struct mgos_config_wifi_sta *sta_cfg = mgos_sys_config_get_wifi_sta();
  const struct mgos_config_wifi_sta *sta_cfg1 = mgos_sys_config_get_wifi_sta1();
  const struct mgos_config_wifi_sta *sta_cfg2 = mgos_sys_config_get_wifi_sta2();

  if (trigger_ap || (cfg->ap.enable && sta_cfg == NULL)) {
    struct mgos_config_wifi_ap ap_cfg;
    memcpy(&ap_cfg, &cfg->ap, sizeof(ap_cfg));
    ap_cfg.enable = true;
    LOG(LL_INFO, ("WiFi mode: %s", "AP"));
    /* Disable STA if it was enabled. */
    mgos_wifi_setup_sta(&dummy_sta_cfg);
    result = mgos_wifi_setup_ap(&ap_cfg);
#ifdef MGOS_WIFI_ENABLE_AP_STA /* ifdef-ok */
  } else if (cfg->ap.enable && sta_cfg != NULL && cfg->ap.keep_enabled) {
    LOG(LL_INFO, ("WiFi mode: %s", "AP+STA"));
    result = (mgos_wifi_setup_ap(&cfg->ap) && mgos_wifi_setup_sta(sta_cfg));
#endif
  } else if (sta_cfg->enable || sta_cfg1->enable || sta_cfg2->enable) {
    LOG(LL_INFO, ("WiFi mode: %s", "STA"));
    /* Disable AP if it was enabled. */
    mgos_wifi_setup_ap(&dummy_ap_cfg);
    mgos_wifi_sta_clear_cfgs();
    result |= mgos_wifi_sta_add_cfg(sta_cfg);
    result |= mgos_wifi_sta_add_cfg(sta_cfg1);
    result |= mgos_wifi_sta_add_cfg(sta_cfg2);
    if (result) mgos_wifi_connect();
  } else {
    LOG(LL_INFO, ("WiFi mode: %s", "off"));
    mgos_wifi_setup_sta(&dummy_sta_cfg);
    mgos_wifi_setup_ap(&dummy_ap_cfg);
    result = true;
  }

  return result;
}

/*
 * Handler of DNS requests, it resolves mgos_sys_config_get_wifi_ap_hostname()
 * to the IP address of wifi AP (mgos_sys_config_get_wifi_ap_ip()).
 */
static void mgos_wifi_dns_ev_handler(struct mg_connection *c, int ev,
                                     void *ev_data, void *user_data) {
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
      struct sockaddr_in ip;
      if (mgos_net_str_to_ip(mgos_sys_config_get_wifi_ap_ip(), &ip)) {
        mg_dns_reply_record(&reply, rr, NULL, rr->rtype, 10,
                            &ip.sin_addr.s_addr, 4);
      }
    }
  }
  mg_dns_send_reply(c, &reply);
  mbuf_free(&reply_buf);
  (void) user_data;
}

bool mgos_wifi_init(void) {
  s_wifi_lock = mgos_rlock_create();
  mgos_event_register_base(MGOS_WIFI_EV_BASE, "wifi");
  mgos_sys_config_register_validator(validate_wifi_cfg);
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
        mg_bind(mgos_get_mgr(), buf, mgos_wifi_dns_ev_handler, 0);
    mg_set_protocol_dns(dns_conn);
  }

  mgos_wifi_sta_init();
  return true;
}

void mgos_wifi_deinit(void) {
  mgos_wifi_dev_deinit();
}
