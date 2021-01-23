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

#include "esp32_wifi.h"

#include <stdbool.h>
#include <string.h>

#include "dhcpserver/dhcpserver.h"
#include "esp_netif.h"
#include "esp_netif_types.h"
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "esp_wpa2.h"
#include "lwip/ip_addr.h"

#include "common/cs_dbg.h"
#include "common/cs_file.h"
#include "common/queue.h"

#include "mgos_hal.h"
#include "mgos_net_hal.h"
#include "mgos_sys_config.h"
#include "mgos_wifi_hal.h"

static bool s_inited = false;
static bool s_started = false;
static bool s_connecting = false;
static bool s_user_sta_enabled = false;

static esp_err_t esp32_wifi_add_mode(wifi_mode_t mode);
static esp_err_t esp32_wifi_remove_mode(wifi_mode_t mode);

static void esp32_wifi_event_handler(void *ctx, esp_event_base_t ev_base,
                                     int32_t ev_id, void *ev_data) {
  struct mgos_wifi_dev_event_info dei = {0};
  switch (ev_id) {
    case WIFI_EVENT_STA_START: {
      s_started = true;
      break;
    }
    case WIFI_EVENT_STA_STOP: {
      s_started = false;
      mgos_wifi_dev_scan_cb(-2, NULL);
      break;
    }
    case WIFI_EVENT_STA_DISCONNECTED: {
      const wifi_event_sta_disconnected_t *info = ev_data;
      dei.ev = MGOS_WIFI_EV_STA_DISCONNECTED;
      dei.sta_disconnected.reason = info->reason;
      // Getting a DISCONNECTED event does not change the internal mode,
      // wifi lib still thinks we are connecting until disconnect() is called.
      // s_connecting = false;
      break;
    }
    case WIFI_EVENT_STA_CONNECTED: {
      const wifi_event_sta_connected_t *info = ev_data;
      dei.ev = MGOS_WIFI_EV_STA_CONNECTED;
      memcpy(dei.sta_connected.bssid, info->bssid, 6);
      dei.sta_connected.channel = info->channel;
      s_connecting = false;
      break;
    }
    case WIFI_EVENT_AP_STACONNECTED: {
      const wifi_event_ap_staconnected_t *info = ev_data;
      dei.ev = MGOS_WIFI_EV_AP_STA_CONNECTED;
      memcpy(dei.ap_sta_connected.mac, info->mac,
             sizeof(dei.ap_sta_connected.mac));
      break;
    }
    case WIFI_EVENT_AP_STADISCONNECTED: {
      const wifi_event_ap_stadisconnected_t *info = ev_data;
      dei.ev = MGOS_WIFI_EV_AP_STA_DISCONNECTED;
      memcpy(dei.ap_sta_disconnected.mac, info->mac,
             sizeof(dei.ap_sta_disconnected.mac));
      break;
    }
    case WIFI_EVENT_SCAN_DONE: {
      int num_res = -1;
      struct mgos_wifi_scan_result *res = NULL;
      wifi_event_sta_scan_done_t *p = ev_data;
      if (p->status == 0) {
        uint16_t number = p->number;
        wifi_ap_record_t *aps =
            (wifi_ap_record_t *) calloc(number, sizeof(*aps));
        if (esp_wifi_scan_get_ap_records(&number, aps) == ESP_OK) {
          res = (struct mgos_wifi_scan_result *) calloc(number, sizeof(*res));
          struct mgos_wifi_scan_result *r;
          wifi_ap_record_t *ap;
          for (ap = aps, r = res, num_res = 0; num_res < number;
               ap++, r++, num_res++) {
            strncpy(r->ssid, (const char *) ap->ssid, sizeof(r->ssid));
            memcpy(r->bssid, ap->bssid, sizeof(r->bssid));
            r->ssid[sizeof(r->ssid) - 1] = '\0';
            r->auth_mode = (enum mgos_wifi_auth_mode) ap->authmode;
            r->channel = ap->primary;
            r->rssi = ap->rssi;
          }
        } else {
          num_res = -2;
        }
        free(aps);
      }
      mgos_wifi_dev_scan_cb(num_res, res);
      if (!s_user_sta_enabled) esp32_wifi_remove_mode(WIFI_MODE_STA);
      break;
    }
    default:
      break;
  }

  if (dei.ev != 0) {
    mgos_wifi_dev_event_cb(&dei);
  }

  (void) ctx;
  (void) ev_base;
}

static void esp32_wifi_ip_event_handler(void *ctx, esp_event_base_t ev_base,
                                        int32_t ev_id, void *ev_data) {
  struct mgos_wifi_dev_event_info dei = {
      .ev = MGOS_WIFI_EV_STA_IP_ACQUIRED,
  };
  mgos_wifi_dev_event_cb(&dei);
  (void) ctx;
  (void) ev_base;
  (void) ev_id;
  (void) ev_data;
}

static wifi_mode_t esp32_wifi_get_mode(void) {
  wifi_mode_t cur_mode = WIFI_MODE_NULL;
  if (s_inited) {
    if (esp_wifi_get_mode(&cur_mode) != ESP_OK) {
      cur_mode = WIFI_MODE_NULL;
    }
  }
  return cur_mode;
}

// Increase wifi task stack size to support advanced logging.
static int32_t task_create_pinned_to_core_wrapper_mgos(
    void *task_func, const char *name, uint32_t stack_depth, void *param,
    uint32_t prio, void *task_handle, uint32_t core_id) {
  if (stack_depth < 4608) stack_depth = 4608;
  return xTaskCreatePinnedToCore(
      task_func, name, stack_depth, param, prio, task_handle,
      (core_id < portNUM_PROCESSORS ? core_id : tskNO_AFFINITY));
}

static int32_t task_create_wrapper_mgos(void *task_func, const char *name,
                                        uint32_t stack_depth, void *param,
                                        uint32_t prio, void *task_handle) {
  if (stack_depth < 4608) stack_depth = 4608;
  return xTaskCreate(task_func, name, stack_depth, param, prio, task_handle);
}

static esp_err_t esp32_wifi_ensure_init(void) {
  esp_err_t r = ESP_OK;
  if (!s_inited) {
    g_wifi_osi_funcs._task_create = task_create_wrapper_mgos;
    g_wifi_osi_funcs._task_create_pinned_to_core =
        task_create_pinned_to_core_wrapper_mgos;
    wifi_init_config_t icfg = WIFI_INIT_CONFIG_DEFAULT();
    r = esp_wifi_init(&icfg);
    if (r != ESP_OK) {
      LOG(LL_ERROR, ("Failed to init WiFi: %d", r));
      goto out;
    }
    esp_wifi_set_storage(WIFI_STORAGE_RAM);
    s_inited = true;
  }
out:
  return r;
}

static esp_err_t esp32_wifi_ensure_start(void) {
  esp_err_t r = ESP_OK;
  if (!s_started) {
    s_connecting = false;
    r = esp_wifi_start();
    if (r != ESP_OK) {
      LOG(LL_ERROR, ("Failed to start WiFi: %d", r));
      goto out;
    }
    wifi_ps_type_t cur_ps_mode = WIFI_PS_NONE;
    esp_wifi_get_ps(&cur_ps_mode);
    wifi_ps_type_t want_ps_mode =
        (wifi_ps_type_t) mgos_sys_config_get_wifi_sta_ps_mode();
    if (cur_ps_mode != want_ps_mode) {
      LOG(LL_DEBUG, ("WiFi PS %d -> %d", cur_ps_mode, want_ps_mode));
      esp_wifi_set_ps(want_ps_mode);
    }
  }
out:
  return r;
}

static esp_err_t esp32_wifi_set_mode(wifi_mode_t mode) {
  esp_err_t r;

  if ((mode == WIFI_MODE_STA || mode == WIFI_MODE_APSTA) &&
      esp_netif_get_handle_from_ifkey("WIFI_STA_DEF") == NULL) {
    esp_netif_create_default_wifi_sta();
  }

  if (mode == WIFI_MODE_NULL) {
    if (s_started) {
      esp_wifi_set_mode(WIFI_MODE_NULL);
    }
    r = esp_wifi_stop();
    if (r == ESP_ERR_WIFI_NOT_INIT) r = ESP_OK; /* Nothing to stop. */
    if (r == ESP_OK) {
      s_started = false;
      s_connecting = false;
    }
    goto out;
  }

  r = esp32_wifi_ensure_init();

  if (r != ESP_OK) goto out;

  if ((r = esp_wifi_set_mode(mode)) != ESP_OK) {
    LOG(LL_ERROR, ("Failed to set WiFi mode %d: %d", mode, r));
    goto out;
  }

out:
  return r;
}

static esp_err_t esp32_wifi_add_mode(wifi_mode_t mode) {
  esp_err_t r = ESP_OK;
  wifi_mode_t cur_mode = esp32_wifi_get_mode();
  if (cur_mode == mode || cur_mode == WIFI_MODE_APSTA) {
    goto out;
  }

  if ((cur_mode == WIFI_MODE_AP && mode == WIFI_MODE_STA) ||
      (cur_mode == WIFI_MODE_STA && mode == WIFI_MODE_AP)) {
    mode = WIFI_MODE_APSTA;
  }

  r = esp32_wifi_set_mode(mode);

out:
  return r;
}

static esp_err_t esp32_wifi_remove_mode(wifi_mode_t mode) {
  esp_err_t r = ESP_OK;

  wifi_mode_t cur_mode = esp32_wifi_get_mode();
  if (cur_mode == WIFI_MODE_NULL ||
      (mode == WIFI_MODE_STA && cur_mode == WIFI_MODE_AP) ||
      (mode == WIFI_MODE_AP && cur_mode == WIFI_MODE_STA)) {
    /* Nothing to do. */
    goto out;
  }
  if (mode == WIFI_MODE_APSTA ||
      (mode == WIFI_MODE_STA && cur_mode == WIFI_MODE_STA) ||
      (mode == WIFI_MODE_AP && cur_mode == WIFI_MODE_AP)) {
    mode = WIFI_MODE_NULL;
  } else if (mode == WIFI_MODE_STA) {
    mode = WIFI_MODE_AP;
  } else {
    mode = WIFI_MODE_STA;
  }
  /* As a result we will always remain in STA-only or AP-only mode. */
  r = esp32_wifi_set_mode(mode);

out:
  return r;
}

static esp_err_t wifi_sta_set_host_name(
    const struct mgos_config_wifi_sta *cfg) {
  esp_err_t r = ESP_OK;
  const char *host_name =
      cfg->dhcp_hostname ? cfg->dhcp_hostname : mgos_sys_config_get_device_id();
  if (host_name != NULL) {
    esp_netif_t *sta_if = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    r = esp_netif_set_hostname(sta_if, host_name);
  }
  return r;
}

bool mgos_wifi_dev_sta_setup(const struct mgos_config_wifi_sta *cfg) {
  bool result = false;
  esp_err_t r;
  wifi_config_t wcfg;
  memset(&wcfg, 0, sizeof(wcfg));
  wifi_sta_config_t *stacfg = &wcfg.sta;

  s_user_sta_enabled = cfg->enable;

  if (!cfg->enable) {
    result = (esp32_wifi_remove_mode(WIFI_MODE_STA) == ESP_OK);
    goto out;
  }

  r = esp32_wifi_add_mode(WIFI_MODE_STA);
  if (r != ESP_OK) goto out;

  /* In case already connected, disconnect. */
  esp_wifi_disconnect();

  stacfg->scan_method =
      (wifi_scan_method_t) mgos_sys_config_get_wifi_sta_all_chan_scan();

  strncpy((char *) stacfg->ssid, cfg->ssid, sizeof(stacfg->ssid));
  if (mgos_conf_str_empty(cfg->user) /* Not using EAP */ &&
      !mgos_conf_str_empty(cfg->pass)) {
    strncpy((char *) stacfg->password, cfg->pass, sizeof(stacfg->password));
  }

  esp_err_t host_r = wifi_sta_set_host_name(cfg);
  if (host_r != ESP_OK && host_r != ESP_ERR_ESP_NETIF_IF_NOT_READY) {
    LOG(LL_ERROR, ("WiFi STA: Failed to set host name"));
    goto out;
  }

  esp_netif_t *sta_if = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
  if (!mgos_conf_str_empty(cfg->ip) && !mgos_conf_str_empty(cfg->netmask)) {
    esp_netif_dhcpc_stop(sta_if);
    esp_netif_ip_info_t info = {0};
    info.ip.addr = ipaddr_addr(cfg->ip);
    info.netmask.addr = ipaddr_addr(cfg->netmask);
    if (!mgos_conf_str_empty(cfg->gw)) info.gw.addr = ipaddr_addr(cfg->gw);
    r = esp_netif_set_ip_info(sta_if, &info);
    if (r != ESP_OK) {
      LOG(LL_ERROR, ("Failed to set WiFi STA IP config: %d", r));
      goto out;
    }
    LOG(LL_INFO, ("WiFi STA IP: %s/%s gw %s", cfg->ip, cfg->netmask,
                  (cfg->gw ? cfg->gw : "")));
  } else {
    esp_netif_dhcpc_start(sta_if);
  }

  r = esp32_wifi_protocol_setup(WIFI_IF_STA, cfg->protocol);
  if (r != ESP_OK) {
    LOG(LL_ERROR, ("Failed to set STA protocol: %s", esp_err_to_name(r)));
    goto out;
  }
  if (cfg->listen_interval_ms > 0) {
    LOG(LL_INFO, ("WiFi STA listen_interval: %dms", cfg->listen_interval_ms));
    stacfg->listen_interval = cfg->listen_interval_ms / 100;
  }
  r = esp_wifi_set_config(WIFI_IF_STA, &wcfg);
  if (r != ESP_OK) {
    LOG(LL_ERROR, ("Failed to set STA config: %d", r));
    goto out;
  }

  if (!mgos_conf_str_empty(cfg->cert) || !mgos_conf_str_empty(cfg->user)) {
    /* WPA-enterprise mode */
    static char *s_ca_cert_pem = NULL, *s_cert_pem = NULL, *s_key_pem = NULL;
    const char *user = cfg->user;

    if (user == NULL) user = "";

    esp_wifi_sta_wpa2_ent_set_username((unsigned char *) user, strlen(user));

    if (!mgos_conf_str_empty(cfg->anon_identity)) {
      esp_wifi_sta_wpa2_ent_set_identity((unsigned char *) cfg->anon_identity,
                                         strlen(cfg->anon_identity));
    } else {
      /* By default, username is used. */
      esp_wifi_sta_wpa2_ent_set_identity((unsigned char *) user, strlen(user));
    }
    if (!mgos_conf_str_empty(cfg->pass)) {
      esp_wifi_sta_wpa2_ent_set_password((unsigned char *) cfg->pass,
                                         strlen(cfg->pass));
    } else {
      esp_wifi_sta_wpa2_ent_clear_password();
    }

    if (!mgos_conf_str_empty(cfg->ca_cert)) {
      free(s_ca_cert_pem);
      size_t len;
      s_ca_cert_pem = cs_read_file(cfg->ca_cert, &len);
      if (s_ca_cert_pem == NULL) {
        LOG(LL_ERROR, ("Failed to read %s", cfg->ca_cert));
        goto out;
      }
      esp_wifi_sta_wpa2_ent_set_ca_cert((unsigned char *) s_ca_cert_pem,
                                        (int) len);
    } else {
      esp_wifi_sta_wpa2_ent_clear_ca_cert();
    }

    if (!mgos_conf_str_empty(cfg->cert) && !mgos_conf_str_empty(cfg->key)) {
      free(s_cert_pem);
      free(s_key_pem);
      size_t cert_len, key_len;
      s_cert_pem = cs_read_file(cfg->cert, &cert_len);
      if (s_cert_pem == NULL) {
        LOG(LL_ERROR, ("Failed to read %s", cfg->cert));
        goto out;
      }
      s_key_pem = cs_read_file(cfg->key, &key_len);
      if (s_key_pem == NULL) {
        LOG(LL_ERROR, ("Failed to read %s", cfg->key));
        goto out;
      }
      esp_wifi_sta_wpa2_ent_set_cert_key(
          (unsigned char *) s_cert_pem, (int) cert_len,
          (unsigned char *) s_key_pem, (int) key_len,
          NULL /* private_key_passwd */, 0 /* private_key_passwd_len */);
    } else {
      esp_wifi_sta_wpa2_ent_clear_cert_key();
    }

    esp_wifi_sta_wpa2_ent_clear_new_password();
    esp_wifi_sta_wpa2_ent_set_disable_time_check(true /* disable */);
    esp_wifi_sta_wpa2_ent_enable();
  } else {
    esp_wifi_sta_wpa2_ent_disable();
  }

  result = true;

out:
  return result;
}

bool mgos_wifi_dev_ap_setup(const struct mgos_config_wifi_ap *cfg) {
  bool result = false;
  esp_err_t r;
  wifi_config_t wcfg = {0};
  wifi_ap_config_t *apcfg = &wcfg.ap;

  if (!cfg->enable) {
    result = (esp32_wifi_remove_mode(WIFI_MODE_AP) == ESP_OK);
    goto out;
  }

  if (esp32_wifi_add_mode(WIFI_MODE_AP) != ESP_OK) goto out;

  strncpy((char *) apcfg->ssid, cfg->ssid, sizeof(apcfg->ssid));
  mgos_expand_mac_address_placeholders((char *) apcfg->ssid);
  if (!mgos_conf_str_empty(cfg->pass)) {
    strncpy((char *) apcfg->password, cfg->pass, sizeof(apcfg->password));
    apcfg->authmode = WIFI_AUTH_WPA2_PSK;
  } else {
    apcfg->authmode = WIFI_AUTH_OPEN;
  }
  apcfg->channel = cfg->channel;
  apcfg->ssid_hidden = (cfg->hidden != 0);
  apcfg->max_connection = cfg->max_connections;
  apcfg->beacon_interval = 100; /* ms */
  LOG(LL_ERROR, ("WiFi AP: SSID %s, channel %d", apcfg->ssid, apcfg->channel));

  esp_netif_t *ap_if = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
  if (ap_if == NULL) ap_if = esp_netif_create_default_wifi_ap();
  if (ap_if == NULL) goto out;
  // Ensure that DHCP server is not running.
  while (esp_netif_dhcps_stop(ap_if) !=
         ESP_ERR_ESP_NETIF_DHCP_ALREADY_STOPPED) {
  }
  {
    esp_netif_ip_info_t info = {
        .ip.addr = ipaddr_addr(cfg->ip),
        .netmask.addr = ipaddr_addr(cfg->netmask),
    };
    if (!mgos_conf_str_empty(cfg->gw)) info.gw.addr = ipaddr_addr(cfg->gw);
    r = esp_netif_set_ip_info(ap_if, &info);
    if (r != ESP_OK) {
      LOG(LL_ERROR, ("WiFi AP: Failed to set IP config: %d", r));
      goto out;
    }
  }
  {
    dhcps_lease_t opt = {
        .enable = true,
        .start_ip.addr = ipaddr_addr(cfg->dhcp_start),
        .end_ip.addr = ipaddr_addr(cfg->dhcp_end),
    };
    r = esp_netif_dhcps_option(ap_if, ESP_NETIF_OP_SET,
                               ESP_NETIF_REQUESTED_IP_ADDRESS, &opt,
                               sizeof(opt));
    if (r != ESP_OK) {
      LOG(LL_ERROR, ("WiFi AP: Failed to set DHCP config: %d", r));
      goto out;
    }
  }
  if ((r = esp_wifi_set_config(WIFI_IF_AP, &wcfg)) != ESP_OK) {
    LOG(LL_ERROR, ("WiFi AP: Failed to set config: %d", r));
    goto out;
  }
  wifi_bandwidth_t bw = WIFI_BW_HT40;
  if (cfg->bandwidth_20mhz) bw = WIFI_BW_HT20;
  if ((r = esp_wifi_set_bandwidth(WIFI_IF_AP, bw)) != ESP_OK) {
    LOG(LL_ERROR, ("WiFi AP: Failed to set the bandwidth: %d", r));
    goto out;
  }
  r = esp32_wifi_protocol_setup(WIFI_IF_AP, cfg->protocol);
  if (r != ESP_OK) {
    LOG(LL_ERROR, ("Failed to set AP protocol: %s", esp_err_to_name(r)));
    goto out;
  }
  if ((r = esp32_wifi_ensure_start()) != ESP_OK) {
    goto out;
  }
  if ((r = esp_netif_dhcps_start(ap_if)) != ESP_OK &&
      r != ESP_ERR_ESP_NETIF_DHCP_ALREADY_STARTED) {
    LOG(LL_ERROR, ("WiFi AP: Failed to start DHCP server: %d", r));
    goto out;
  }
  LOG(LL_INFO,
      ("WiFi AP IP: %s/%s gw %s, DHCP range %s - %s", cfg->ip, cfg->netmask,
       (cfg->gw ? cfg->gw : "(none)"), cfg->dhcp_start, cfg->dhcp_end));

  result = true;

out:
  return result;
}

bool mgos_wifi_dev_sta_connect(void) {
  if ((esp32_wifi_ensure_init() != ESP_OK) ||
      (esp32_wifi_ensure_start() != ESP_OK))
    return false;
  wifi_mode_t cur_mode = esp32_wifi_get_mode();
  if (cur_mode == WIFI_MODE_NULL || cur_mode == WIFI_MODE_AP) return false;
  esp_err_t r = esp_wifi_connect();
  if (r != ESP_OK) {
    LOG(LL_ERROR, ("WiFi STA: Connect failed: %d", r));
    s_connecting = false;
  } else {
    s_connecting = true;
  }
  return (r == ESP_OK);
}

bool mgos_wifi_dev_sta_disconnect(void) {
  wifi_mode_t cur_mode = esp32_wifi_get_mode();
  if (cur_mode == WIFI_MODE_NULL || cur_mode == WIFI_MODE_AP) return false;
  esp_wifi_disconnect();
  s_connecting = false;
  /* If we are in station-only mode, stop WiFi task as well. */
  if (cur_mode == WIFI_MODE_STA) {
    esp_err_t r = esp_wifi_stop();
    if (r == ESP_ERR_WIFI_NOT_INIT) r = ESP_OK; /* Nothing to stop. */
    if (r == ESP_OK) {
      s_started = false;
    }
  }
  return true;
}

bool mgos_wifi_dev_get_ip_info(int if_instance,
                               struct mgos_net_ip_info *ip_info) {
  esp_netif_ip_info_t info;
  esp_netif_t *netif = esp_netif_get_handle_from_ifkey(
      if_instance == 0 ? "WIFI_STA_DEF" : "WIFI_AP_DEF");
  if ((esp_netif_get_ip_info(netif, &info) != ESP_OK) || info.ip.addr == 0) {
    return false;
  }
  ip_info->ip.sin_addr.s_addr = info.ip.addr;
  ip_info->netmask.sin_addr.s_addr = info.netmask.addr;
  ip_info->gw.sin_addr.s_addr = info.gw.addr;
  return true;
}

void mgos_wifi_dev_init(void) {
  esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                             esp32_wifi_event_handler, NULL);
  esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP,
                             esp32_wifi_ip_event_handler, NULL);
}

void mgos_wifi_dev_deinit(void) {
  if (s_started) {
    esp_wifi_stop();
    s_started = false;
  }
  if (s_inited) {
    esp_wifi_deinit();
    s_inited = false;
  }
}

char *mgos_wifi_get_sta_default_dns() {
  char *dns = NULL;
  const ip_addr_t *dns_addr = dns_getserver(0);
  if (dns_addr == NULL || dns_addr->u_addr.ip4.addr == 0 ||
      dns_addr->type != IPADDR_TYPE_V4) {
    return NULL;
  }
  if (asprintf(&dns, IPSTR, IP2STR(&dns_addr->u_addr.ip4)) < 0) {
    return NULL;
  }
  return dns;
}

int mgos_wifi_sta_get_rssi(void) {
  wifi_ap_record_t info;
  if (esp_wifi_sta_get_ap_info(&info) != ESP_OK) return 0;
  return info.rssi;
}

bool mgos_wifi_dev_start_scan(void) {
  esp_err_t r = ESP_OK;
  wifi_mode_t cur_mode = esp32_wifi_get_mode();
  if (cur_mode != WIFI_MODE_STA && cur_mode != WIFI_MODE_APSTA) {
    r = esp32_wifi_add_mode(WIFI_MODE_STA);
    if (r == ESP_OK) r = esp32_wifi_ensure_start();
  }
  if (r == ESP_OK) {
    wifi_scan_config_t scan_cfg = {
        .scan_type = WIFI_SCAN_TYPE_ACTIVE,
        .scan_time =
            {
                .active =
                    {
                        .min = 150,
                        .max = 200,
                    },
            },
    };
    if (s_connecting) {
      esp_wifi_disconnect();
      s_connecting = false;
    }
    r = esp_wifi_scan_start(&scan_cfg, false /* block */);
  }
  return (r == ESP_OK);
}

esp_err_t esp32_wifi_protocol_setup(wifi_interface_t ifx, const char *prot) {
  if (mgos_conf_str_empty(prot)) return ESP_OK;
  uint8_t protocol = 0;
  if (strcmp(prot, "B") == 0) {
    protocol = WIFI_PROTOCOL_11B;
  } else if (strcmp(prot, "BG") == 0) {
    protocol = (WIFI_PROTOCOL_11B | WIFI_PROTOCOL_11G);
  } else if (strcmp(prot, "BGN") == 0) {
    protocol = (WIFI_PROTOCOL_11B | WIFI_PROTOCOL_11G | WIFI_PROTOCOL_11N);
  } else if (strcmp(prot, "LR") == 0) {
    protocol = WIFI_PROTOCOL_LR;
  } else if (strcmp(prot, "BLR") == 0) {
    protocol = (WIFI_PROTOCOL_11B | WIFI_PROTOCOL_LR);
  } else if (strcmp(prot, "BGLR") == 0) {
    protocol = (WIFI_PROTOCOL_11B | WIFI_PROTOCOL_11G | WIFI_PROTOCOL_LR);
  } else if (strcmp(prot, "BGNLR") == 0) {
    protocol = (WIFI_PROTOCOL_11B | WIFI_PROTOCOL_11G | WIFI_PROTOCOL_11N |
                WIFI_PROTOCOL_LR);
  } else {
    return ESP_ERR_NOT_SUPPORTED;
  }
  LOG(LL_INFO, ("WiFi %s: protocol %s (%#x)",
                (ifx == WIFI_IF_STA ? "STA" : "AP"), prot, protocol));
  return esp_wifi_set_protocol(ifx, protocol);
}
