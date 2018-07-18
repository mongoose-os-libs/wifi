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

#include "esp_wifi.h"
#include "esp_wpa2.h"
#include "tcpip_adapter.h"
#include "apps/dhcpserver.h"
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
static wifi_mode_t s_cur_mode = WIFI_MODE_NULL;
typedef esp_err_t (*wifi_func_t)(void *arg);

esp_err_t esp32_wifi_ev(system_event_t *ev) {
  bool send_ev = false;
  enum mgos_net_event mg_ev;
  system_event_info_t *info = &ev->event_info;
  switch (ev->event_id) {
    case SYSTEM_EVENT_STA_START: {
      break;
    }
    case SYSTEM_EVENT_STA_STOP:
      mgos_wifi_dev_scan_cb(-2, NULL);
      break;
    case SYSTEM_EVENT_STA_DISCONNECTED:
      LOG(LL_INFO, ("Disconnected from %.*s, reason: %d",
                    (int) info->disconnected.ssid_len, info->disconnected.ssid,
                    info->disconnected.reason));
      mg_ev = MGOS_NET_EV_DISCONNECTED;
      send_ev = true;
      break;
    case SYSTEM_EVENT_STA_CONNECTED:
      mg_ev = MGOS_NET_EV_CONNECTED;
      send_ev = true;
      break;
    case SYSTEM_EVENT_STA_GOT_IP:
      mg_ev = MGOS_NET_EV_IP_ACQUIRED;
      send_ev = true;
      break;
    case SYSTEM_EVENT_AP_STACONNECTED: {
      const uint8_t *mac = ev->event_info.sta_connected.mac;
      LOG(LL_INFO, ("WiFi AP: station %02X%02X%02X%02X%02X%02X (aid %d) %s",
                    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
                    info->sta_connected.aid, "connected"));
      break;
    }
    case SYSTEM_EVENT_AP_STADISCONNECTED: {
      const uint8_t *mac = ev->event_info.sta_disconnected.mac;
      LOG(LL_INFO, ("WiFi AP: station %02X%02X%02X%02X%02X%02X (aid %d) %s",
                    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
                    info->sta_disconnected.aid, "disconnected"));
      break;
    }
    case SYSTEM_EVENT_SCAN_DONE: {
      int num_res = -1;
      struct mgos_wifi_scan_result *res = NULL;
      system_event_sta_scan_done_t *p = &ev->event_info.scan_done;
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
      break;
    }
    default: { LOG(LL_DEBUG, ("WiFi event: %d", ev->event_id)); }
  }

  if (send_ev) {
    mgos_wifi_dev_on_change_cb(mg_ev);
  }

  return ESP_OK;
}

static esp_err_t wifi_ensure_init_and_start(wifi_func_t func, void *arg) {
  esp_err_t r;
  if (!s_inited) {
    wifi_init_config_t icfg = WIFI_INIT_CONFIG_DEFAULT();
    r = esp_wifi_init(&icfg);
    if (r != ESP_OK) {
      LOG(LL_ERROR, ("Failed to init WiFi: %d", r));
      goto out;
    }
    esp_wifi_set_storage(WIFI_STORAGE_RAM);
    s_inited = true;
  }
  if (!s_started) {
    r = esp_wifi_start();
    if (r != ESP_OK) {
      LOG(LL_ERROR, ("Failed to start WiFi: %d", r));
      goto out;
    }
    /* Workaround for https://github.com/espressif/esp-idf/issues/1942 */
    r = esp_wifi_set_ps(WIFI_PS_NONE);
    if (r != ESP_OK) {
      LOG(LL_ERROR, ("Failed to set PS mode: %d", r));
      goto out;
    }
  }
  r = func(arg);
out:
  return r;
}

static esp_err_t esp32_wifi_set_mode(wifi_mode_t mode) {
  esp_err_t r;

  const char *mode_str = NULL;
  switch (mode) {
    case WIFI_MODE_NULL:
      mode_str = "disabled";
      break;
    case WIFI_MODE_AP:
      mode_str = "AP";
      break;
    case WIFI_MODE_STA:
      mode_str = "STA";
      break;
    case WIFI_MODE_APSTA:
      mode_str = "AP+STA";
      break;
    default:
      mode_str = "???";
  }
  LOG(LL_INFO, ("WiFi mode: %s", mode_str));

  if (mode == WIFI_MODE_NULL) {
    r = esp_wifi_stop();
    if (r == ESP_ERR_WIFI_NOT_INIT) r = ESP_OK; /* Nothing to stop. */
    if (r == ESP_OK) {
      s_cur_mode = WIFI_MODE_NULL;
      s_started = false;
    }
    goto out;
  }

  r = wifi_ensure_init_and_start((wifi_func_t) esp_wifi_set_mode,
                                 (void *) mode);
  if (r != ESP_OK) {
    LOG(LL_ERROR, ("Failed to set WiFi mode %d: %d", mode, r));
    goto out;
  }

  s_cur_mode = mode;

out:
  return r;
}

static esp_err_t mgos_wifi_add_mode(wifi_mode_t mode) {
  esp_err_t r = ESP_OK;

  if (s_cur_mode == mode || s_cur_mode == WIFI_MODE_APSTA) {
    goto out;
  }

  if ((s_cur_mode == WIFI_MODE_AP && mode == WIFI_MODE_STA) ||
      (s_cur_mode == WIFI_MODE_STA && mode == WIFI_MODE_AP)) {
    mode = WIFI_MODE_APSTA;
  }

  r = esp32_wifi_set_mode(mode);

out:
  return r;
}

static esp_err_t mgos_wifi_remove_mode(wifi_mode_t mode) {
  esp_err_t r = ESP_OK;

  if ((mode == WIFI_MODE_STA && s_cur_mode == WIFI_MODE_AP) ||
      (mode == WIFI_MODE_AP && s_cur_mode == WIFI_MODE_STA)) {
    /* Nothing to do. */
    goto out;
  }
  if (mode == WIFI_MODE_APSTA ||
      (mode == WIFI_MODE_STA && s_cur_mode == WIFI_MODE_STA) ||
      (mode == WIFI_MODE_AP && s_cur_mode == WIFI_MODE_AP)) {
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
    r = tcpip_adapter_set_hostname(TCPIP_ADAPTER_IF_STA, host_name);
  }
  return r;
}

bool mgos_wifi_dev_sta_setup(const struct mgos_config_wifi_sta *cfg) {
  bool result = false;
  esp_err_t r;
  wifi_config_t wcfg;
  memset(&wcfg, 0, sizeof(wcfg));
  wifi_sta_config_t *stacfg = &wcfg.sta;

  if (!cfg->enable) {
    result = (mgos_wifi_remove_mode(WIFI_MODE_STA) == ESP_OK);
    goto out;
  }

  r = mgos_wifi_add_mode(WIFI_MODE_STA);
  if (r != ESP_OK) goto out;

  strncpy((char *) stacfg->ssid, cfg->ssid, sizeof(stacfg->ssid));
  if (mgos_conf_str_empty(cfg->user) /* Not using EAP */ &&
      !mgos_conf_str_empty(cfg->pass)) {
    strncpy((char *) stacfg->password, cfg->pass, sizeof(stacfg->password));
  }

  if (!mgos_conf_str_empty(cfg->ip) && !mgos_conf_str_empty(cfg->netmask)) {
    tcpip_adapter_dhcpc_stop(TCPIP_ADAPTER_IF_STA);
    tcpip_adapter_ip_info_t info;
    memset(&info, 0, sizeof(info));
    info.ip.addr = ipaddr_addr(cfg->ip);
    info.netmask.addr = ipaddr_addr(cfg->netmask);
    if (!mgos_conf_str_empty(cfg->gw)) info.gw.addr = ipaddr_addr(cfg->gw);
    r = tcpip_adapter_set_ip_info(TCPIP_ADAPTER_IF_STA, &info);
    if (r != ESP_OK) {
      LOG(LL_ERROR, ("Failed to set WiFi STA IP config: %d", r));
      goto out;
    }
    LOG(LL_INFO, ("WiFi STA IP: %s/%s gw %s", cfg->ip, cfg->netmask,
                  (cfg->gw ? cfg->gw : "")));
  } else {
    tcpip_adapter_dhcpc_start(TCPIP_ADAPTER_IF_STA);
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
    esp_wpa2_config_t config = WPA2_CONFIG_INIT_DEFAULT();
    esp_wifi_sta_wpa2_ent_enable(&config);
  } else {
    esp_wifi_sta_wpa2_ent_disable();
  }

  esp_err_t host_r = wifi_sta_set_host_name(cfg);
  if (host_r != ESP_OK && host_r != ESP_ERR_TCPIP_ADAPTER_IF_NOT_READY) {
    LOG(LL_ERROR, ("WiFi STA: Failed to set host name"));
    goto out;
  }

  result = true;

out:
  return result;
}

bool mgos_wifi_dev_ap_setup(const struct mgos_config_wifi_ap *cfg) {
  bool result = false;
  esp_err_t r;
  wifi_config_t wcfg;
  memset(&wcfg, 0, sizeof(wcfg));
  wifi_ap_config_t *apcfg = &wcfg.ap;

  if (!cfg->enable) {
    result = (mgos_wifi_remove_mode(WIFI_MODE_AP) == ESP_OK);
    goto out;
  }

  r = mgos_wifi_add_mode(WIFI_MODE_AP);
  if (r != ESP_OK) goto out;

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

  r = esp_wifi_set_config(WIFI_IF_AP, &wcfg);
  if (r != ESP_OK) {
    LOG(LL_ERROR, ("WiFi AP: Failed to set config: %d", r));
    goto out;
  }

  tcpip_adapter_dhcps_stop(TCPIP_ADAPTER_IF_AP);
  {
    tcpip_adapter_ip_info_t info;
    memset(&info, 0, sizeof(info));
    info.ip.addr = ipaddr_addr(cfg->ip);
    info.netmask.addr = ipaddr_addr(cfg->netmask);
    if (!mgos_conf_str_empty(cfg->gw)) info.gw.addr = ipaddr_addr(cfg->gw);
    r = tcpip_adapter_set_ip_info(TCPIP_ADAPTER_IF_AP, &info);
    if (r != ESP_OK) {
      LOG(LL_ERROR, ("WiFi AP: Failed to set IP config: %d", r));
      goto out;
    }
  }
  {
    dhcps_lease_t opt;
    memset(&opt, 0, sizeof(opt));
    opt.enable = true;
    opt.start_ip.addr = ipaddr_addr(cfg->dhcp_start);
    opt.end_ip.addr = ipaddr_addr(cfg->dhcp_end);
    r = tcpip_adapter_dhcps_option(TCPIP_ADAPTER_OP_SET,
                                   TCPIP_ADAPTER_REQUESTED_IP_ADDRESS, &opt,
                                   sizeof(opt));
    if (r != ESP_OK) {
      LOG(LL_ERROR, ("WiFi AP: Failed to set DHCP config: %d", r));
      goto out;
    }
  }
  r = tcpip_adapter_dhcps_start(TCPIP_ADAPTER_IF_AP);
  if (r != ESP_OK) {
    LOG(LL_ERROR, ("WiFi AP: Failed to start DHCP server: %d", r));
    goto out;
  }
  LOG(LL_INFO,
      ("WiFi AP IP: %s/%s gw %s, DHCP range %s - %s", cfg->ip, cfg->netmask,
       (cfg->gw ? cfg->gw : "(none)"), cfg->dhcp_start, cfg->dhcp_end));

  /* There is no way to tell if AP is running already. */
  esp_wifi_start();

  LOG(LL_INFO, ("WiFi AP: SSID %s, channel %d", apcfg->ssid, apcfg->channel));

  result = true;

out:
  return result;
}

bool mgos_wifi_dev_sta_connect(void) {
  esp_err_t r =
      wifi_ensure_init_and_start((wifi_func_t) esp_wifi_connect, NULL);
  if (r != ESP_OK) {
    LOG(LL_ERROR, ("WiFi STA: Connect failed: %d", r));
  }
  return (r == ESP_OK);
}

bool mgos_wifi_dev_sta_disconnect(void) {
  esp_wifi_disconnect();
  /* If we are in station-only mode, stop WiFi task as well. */
  if (s_cur_mode == WIFI_MODE_STA) {
    esp_err_t r = esp_wifi_stop();
    if (r == ESP_ERR_WIFI_NOT_INIT) r = ESP_OK; /* Nothing to stop. */
    if (r == ESP_OK) {
      s_cur_mode = WIFI_MODE_NULL;
      s_started = false;
    }
  }
  return true;
}

char *mgos_wifi_get_connected_ssid(void) {
  wifi_ap_record_t ap_info;
  if (esp_wifi_sta_get_ap_info(&ap_info) != ESP_OK) {
    return NULL;
  }
  return strdup((char *) ap_info.ssid);
}

bool mgos_wifi_dev_get_ip_info(int if_instance,
                               struct mgos_net_ip_info *ip_info) {
  tcpip_adapter_ip_info_t info;
  if ((tcpip_adapter_get_ip_info(
           (if_instance == 0 ? TCPIP_ADAPTER_IF_STA : TCPIP_ADAPTER_IF_AP),
           &info) != ESP_OK) ||
      info.ip.addr == 0) {
    return false;
  }
  ip_info->ip.sin_addr.s_addr = info.ip.addr;
  ip_info->netmask.sin_addr.s_addr = info.netmask.addr;
  ip_info->gw.sin_addr.s_addr = info.gw.addr;
  return true;
}

void mgos_wifi_dev_init(void) {
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
  s_cur_mode = WIFI_MODE_NULL;
}

char *mgos_wifi_get_sta_default_dns() {
  char *dns;
  ip_addr_t dns_addr = dns_getserver(0);
  if (dns_addr.u_addr.ip4.addr == 0 || dns_addr.type != IPADDR_TYPE_V4) {
    return NULL;
  }
  if (asprintf(&dns, IPSTR, IP2STR(&dns_addr.u_addr.ip4)) < 0) {
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
  if (s_cur_mode != WIFI_MODE_STA && s_cur_mode != WIFI_MODE_APSTA) {
    r = mgos_wifi_add_mode(WIFI_MODE_STA);
    if (r == ESP_OK) r = esp_wifi_start();
  }
  if (r == ESP_OK) {
    wifi_scan_config_t scan_cfg = {.ssid = NULL,
                                   .bssid = NULL,
                                   .channel = 0,
                                   .show_hidden = false,
                                   .scan_type = WIFI_SCAN_TYPE_ACTIVE,
                                   .scan_time = {
                                       .active = {
                                           .min = 10, .max = 50,
                                       }, }};
    r = esp_wifi_scan_start(&scan_cfg, false /* block */);
  }
  return (r == ESP_OK);
}
