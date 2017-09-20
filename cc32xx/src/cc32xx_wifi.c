/*
 * Copyright (c) 2014-2016 Cesanta Software Limited
 * All rights reserved
 */

#include <stdio.h>
#include <stdlib.h>

#include <common/platform.h>

#include "common/cs_dbg.h"
#include "common/platform.h"
#include "mgos_hal.h"
#include "mgos_mongoose.h"
#include "mgos_net_hal.h"
#include "mgos_sys_config.h"
#include "mgos_wifi_hal.h"

#include "cc32xx_vfs_dev_slfs_container.h"

#ifndef WIFI_SCAN_INTERVAL_SECONDS
#define WIFI_SCAN_INTERVAL_SECONDS 15
#endif

/* Compatibility with older versions of SimpleLink */
#if SL_MAJOR_VERSION_NUM < 2
#define SL_NETAPP_DHCP_SERVER_ID SL_NET_APP_DHCP_SERVER_ID
#define SL_NETAPP_HTTP_SERVER_ID SL_NET_APP_HTTP_SERVER_ID

#define SL_NETAPP_EVENT_IPV4_ACQUIRED SL_NETAPP_IPV4_IPACQUIRED_EVENT
#define SL_NETAPP_EVENT_DHCPV4_LEASED SL_NETAPP_IP_LEASED_EVENT

#define SL_NETAPP_DHCP_SRV_BASIC_OPT NETAPP_SET_DHCP_SRV_BASIC_OPT

#define SL_NETCFG_IPV4_STA_ADDR_MODE SL_IPV4_STA_P2P_CL_GET_INFO
#define SL_NETCFG_IPV4_AP_ADDR_MODE SL_IPV4_AP_P2P_GO_GET_INFO

#define SL_WLAN_EVENT_CONNECT SL_WLAN_CONNECT_EVENT
#define SL_WLAN_EVENT_DISCONNECT SL_WLAN_DISCONNECT_EVENT

#define SL_WLAN_AP_OPT_SSID WLAN_AP_OPT_SSID
#define SL_WLAN_AP_OPT_CHANNEL WLAN_AP_OPT_CHANNEL
#define SL_WLAN_AP_OPT_HIDDEN_SSID WLAN_AP_OPT_HIDDEN_SSID
#define SL_WLAN_AP_OPT_SECURITY_TYPE WLAN_AP_OPT_SECURITY_TYPE
#define SL_WLAN_AP_OPT_PASSWORD WLAN_AP_OPT_PASSWORD
#define SL_WLAN_AP_OPT_MAX_STATIONS WLAN_AP_OPT_MAX_STATIONS

#define SL_WLAN_POLICY_SCAN SL_POLICY_SCAN

#define SL_WLAN_SEC_TYPE_OPEN SL_SEC_TYPE_OPEN
#define SL_WLAN_SEC_TYPE_WEP SL_SEC_TYPE_WEP
#define SL_WLAN_SEC_TYPE_WPA SL_SEC_TYPE_WPA
#define SL_WLAN_SEC_TYPE_WPA_WPA2 SL_SEC_TYPE_WPA_WPA2
#define SL_WLAN_SEC_TYPE_WPA_ENT SL_SEC_TYPE_WPA_ENT

#define SL_WLAN_SECURITY_TYPE_BITMAP_OPEN SL_SCAN_SEC_TYPE_OPEN
#define SL_WLAN_SECURITY_TYPE_BITMAP_WEP SL_SCAN_SEC_TYPE_WEP
#define SL_WLAN_SECURITY_TYPE_BITMAP_WPA SL_SCAN_SEC_TYPE_WPA
#define SL_WLAN_SECURITY_TYPE_BITMAP_WPA2 SL_SCAN_SEC_TYPE_WPA2

#define SlWlanNetworkEntry_t Sl_WlanNetworkEntry_t

#endif

struct cc3200_wifi_config {
  char *ssid;
  char *pass;
  char *user;
  char *anon_identity;
  SlNetCfgIpV4Args_t static_ip;
};

static struct cc3200_wifi_config s_wifi_sta_config;
static int s_current_role = -1;

static void free_wifi_config(void) {
  free(s_wifi_sta_config.ssid);
  free(s_wifi_sta_config.pass);
  free(s_wifi_sta_config.user);
  free(s_wifi_sta_config.anon_identity);
  memset(&s_wifi_sta_config, 0, sizeof(s_wifi_sta_config));
}

static bool restart_nwp(SlWlanMode_e role) {
  /*
   * Properly close FS container if it's open for writing.
   * Suspend FS I/O while NWP is being restarted.
   */
  mgos_lock();
  cc32xx_vfs_dev_slfs_container_flush_all();
  if (sl_WlanSetMode(role) != 0) return false;
  /* Without a delay in sl_Stop subsequent sl_Start gets stuck sometimes. */
  sl_Stop(10);
  s_current_role = sl_Start(NULL, NULL, NULL);
  mgos_unlock();
  /* We don't need TI's web server. */
  sl_NetAppStop(SL_NETAPP_HTTP_SERVER_ID);
  sl_restart_cb(mgos_get_mgr());
  return (s_current_role >= 0);
}

static bool ensure_role_sta(void) {
  if (s_current_role == ROLE_STA) return true;
  if (!restart_nwp(ROLE_STA)) return false;
  _u32 scan_interval = WIFI_SCAN_INTERVAL_SECONDS;
  sl_WlanPolicySet(SL_WLAN_POLICY_SCAN, 1 /* enable */, (_u8 *) &scan_interval,
                   sizeof(scan_interval));
  return true;
}

void SimpleLinkWlanEventHandler(SlWlanEvent_t *e) {
#if SL_MAJOR_VERSION_NUM >= 2
  _u32 eid = e->Id;
#else
  _u32 eid = e->Event;
#endif
  switch (eid) {
    case SL_WLAN_EVENT_CONNECT: {
      mgos_wifi_dev_on_change_cb(MGOS_NET_EV_CONNECTED);
      break;
    }
    case SL_WLAN_EVENT_DISCONNECT: {
      mgos_wifi_dev_on_change_cb(MGOS_NET_EV_DISCONNECTED);
      break;
    }
    default:
      return;
  }
}

void sl_net_app_eh(SlNetAppEvent_t *e) {
#if SL_MAJOR_VERSION_NUM >= 2
  _u32 eid = e->Id;
  SlNetAppEventData_u *edu = &e->Data;
#else
  _u32 eid = e->Event;
  SlNetAppEventData_u *edu = &e->EventData;
#endif
  if (eid == SL_NETAPP_EVENT_IPV4_ACQUIRED && s_current_role == ROLE_STA) {
    mgos_wifi_dev_on_change_cb(MGOS_NET_EV_IP_ACQUIRED);
  } else if (eid == SL_NETAPP_EVENT_DHCPV4_LEASED) {
#if SL_MAJOR_VERSION_NUM >= 2
    _u32 ip = edu->IpLeased.IpAddress;
    _u8 *mac = edu->IpLeased.Mac;
#else
    _u32 ip = edu->ipLeased.ip_address;
    _u8 *mac = edu->ipLeased.mac;
#endif
    LOG(LL_INFO,
        ("WiFi: leased %lu.%lu.%lu.%lu to %02x:%02x:%02x:%02x:%02x:%02x",
         SL_IPV4_BYTE(ip, 3), SL_IPV4_BYTE(ip, 2), SL_IPV4_BYTE(ip, 1),
         SL_IPV4_BYTE(ip, 0), mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]));
  }
}

void SimpleLinkNetAppEventHandler(SlNetAppEvent_t *e) {
  sl_net_app_eh(e);
}

bool mgos_wifi_dev_sta_setup(const struct sys_config_wifi_sta *cfg) {
  free_wifi_config();
  s_wifi_sta_config.ssid = strdup(cfg->ssid);
  if (!mgos_conf_str_empty(cfg->pass)) {
    s_wifi_sta_config.pass = strdup(cfg->pass);
  }
  if (!mgos_conf_str_empty(cfg->user)) {
    s_wifi_sta_config.user = strdup(cfg->user);
  }
  if (!mgos_conf_str_empty(cfg->anon_identity)) {
    s_wifi_sta_config.anon_identity = strdup(cfg->anon_identity);
  }

  memset(&s_wifi_sta_config.static_ip, 0, sizeof(s_wifi_sta_config.static_ip));
  if (!mgos_conf_str_empty(cfg->ip) && !mgos_conf_str_empty(cfg->netmask)) {
    SlNetCfgIpV4Args_t *ipcfg = &s_wifi_sta_config.static_ip;
#if SL_MAJOR_VERSION_NUM >= 2
    if (!inet_pton(AF_INET, cfg->ip, &ipcfg->Ip) ||
        !inet_pton(AF_INET, cfg->netmask, &ipcfg->IpMask) ||
        (!mgos_conf_str_empty(cfg->ip) &&
         !inet_pton(AF_INET, cfg->gw, &ipcfg->IpGateway))) {
      return false;
    }
#else
    if (!inet_pton(AF_INET, cfg->ip, &ipcfg->ipV4) ||
        !inet_pton(AF_INET, cfg->netmask, &ipcfg->ipV4Mask) ||
        (!mgos_conf_str_empty(cfg->ip) &&
         !inet_pton(AF_INET, cfg->gw, &ipcfg->ipV4Gateway))) {
      return false;
    }
#endif
  }

  return true;
}

bool mgos_wifi_dev_ap_setup(const struct sys_config_wifi_ap *cfg) {
  int ret;
  uint8_t v;
  SlNetCfgIpV4Args_t ipcfg;
  SlNetAppDhcpServerBasicOpt_t dhcpcfg;
  char ssid[64];

  if ((ret = sl_WlanSetMode(ROLE_AP)) != 0) {
    return false;
  }

  strncpy(ssid, cfg->ssid, sizeof(ssid));
  mgos_expand_mac_address_placeholders(ssid);
  if ((ret = sl_WlanSet(SL_WLAN_CFG_AP_ID, SL_WLAN_AP_OPT_SSID, strlen(ssid),
                        (const uint8_t *) ssid)) != 0) {
    return false;
  }

  v = mgos_conf_str_empty(cfg->pass) ? SL_WLAN_SEC_TYPE_OPEN
                                     : SL_WLAN_SEC_TYPE_WPA;
  if ((ret = sl_WlanSet(SL_WLAN_CFG_AP_ID, SL_WLAN_AP_OPT_SECURITY_TYPE, 1,
                        &v)) != 0) {
    return false;
  }
  if (v == SL_WLAN_SEC_TYPE_WPA &&
      (ret = sl_WlanSet(SL_WLAN_CFG_AP_ID, SL_WLAN_AP_OPT_PASSWORD,
                        strlen(cfg->pass), (const uint8_t *) cfg->pass)) != 0) {
    return false;
  }

  v = cfg->channel;
  if ((ret = sl_WlanSet(SL_WLAN_CFG_AP_ID, SL_WLAN_AP_OPT_CHANNEL, 1,
                        (uint8_t *) &v)) != 0) {
    return false;
  }

  v = cfg->hidden;
  if ((ret = sl_WlanSet(SL_WLAN_CFG_AP_ID, SL_WLAN_AP_OPT_HIDDEN_SSID, 1,
                        (uint8_t *) &v)) != 0) {
    return false;
  }

  sl_NetAppStop(SL_NETAPP_DHCP_SERVER_ID);

  memset(&ipcfg, 0, sizeof(ipcfg));
#if SL_MAJOR_VERSION_NUM >= 2
  if (!inet_pton(AF_INET, cfg->ip, &ipcfg.Ip) ||
      !inet_pton(AF_INET, cfg->netmask, &ipcfg.IpMask) ||
      !inet_pton(AF_INET, cfg->gw, &ipcfg.IpGateway) ||
      !inet_pton(AF_INET, cfg->gw, &ipcfg.IpDnsServer) ||
      (ret = sl_NetCfgSet(SL_NETCFG_IPV4_AP_ADDR_MODE, SL_NETCFG_ADDR_STATIC,
                          sizeof(ipcfg), (uint8_t *) &ipcfg)) != 0) {
    return false;
  }
#else
  if (!inet_pton(AF_INET, cfg->ip, &ipcfg.ipV4) ||
      !inet_pton(AF_INET, cfg->netmask, &ipcfg.ipV4Mask) ||
      !inet_pton(AF_INET, cfg->gw, &ipcfg.ipV4Gateway) ||
      !inet_pton(AF_INET, cfg->gw, &ipcfg.ipV4DnsServer) ||
      (ret = sl_NetCfgSet(SL_IPV4_AP_P2P_GO_STATIC_ENABLE,
                          IPCONFIG_MODE_ENABLE_IPV4, sizeof(ipcfg),
                          (uint8_t *) &ipcfg)) != 0) {
    return false;
  }
#endif

  memset(&dhcpcfg, 0, sizeof(dhcpcfg));
  dhcpcfg.lease_time = 900;
  if (!inet_pton(AF_INET, cfg->dhcp_start, &dhcpcfg.ipv4_addr_start) ||
      !inet_pton(AF_INET, cfg->dhcp_end, &dhcpcfg.ipv4_addr_last) ||
      (ret =
           sl_NetAppSet(SL_NETAPP_DHCP_SERVER_ID, SL_NETAPP_DHCP_SRV_BASIC_OPT,
                        sizeof(dhcpcfg), (uint8_t *) &dhcpcfg)) != 0) {
    return false;
  }

  /* Turning the device off and on for the change to take effect. */
  if (!restart_nwp(ROLE_AP)) return false;

  if ((ret = sl_NetAppStart(SL_NETAPP_DHCP_SERVER_ID)) != 0) {
    LOG(LL_ERROR, ("DHCP server failed to start: %d", ret));
  }

  sl_WlanRxStatStart();

  LOG(LL_INFO, ("AP %s configured", ssid));

  return true;
}

bool mgos_wifi_dev_sta_connect(void) {
  int ret;
#if SL_MAJOR_VERSION_NUM >= 2
  SlWlanSecParams_t sp;
  SlWlanSecParamsExt_t spext;
#else
  SlSecParams_t sp;
  SlSecParamsExt_t spext;
#endif

#if SL_MAJOR_VERSION_NUM >= 2
  if (s_wifi_sta_config.static_ip.Ip != 0) {
    ret = sl_NetCfgSet(SL_NETCFG_IPV4_STA_ADDR_MODE, SL_NETCFG_ADDR_STATIC,
                       sizeof(s_wifi_sta_config.static_ip),
                       (unsigned char *) &s_wifi_sta_config.static_ip);
#else
  if (s_wifi_sta_config.static_ip.ipV4 != 0) {
    ret = sl_NetCfgSet(SL_IPV4_STA_P2P_CL_STATIC_ENABLE,
                       IPCONFIG_MODE_ENABLE_IPV4,
                       sizeof(s_wifi_sta_config.static_ip),
                       (unsigned char *) &s_wifi_sta_config.static_ip);
#endif
  } else {
#if SL_MAJOR_VERSION_NUM >= 2
    ret = sl_NetCfgSet(SL_NETCFG_IPV4_STA_ADDR_MODE, SL_NETCFG_ADDR_DHCP, 0, 0);
#else
    _u8 val = 1;
    ret = sl_NetCfgSet(SL_IPV4_STA_P2P_CL_DHCP_ENABLE,
                       IPCONFIG_MODE_ENABLE_IPV4, sizeof(val), &val);
#endif
  }
  if (ret != 0) return false;

  if (!ensure_role_sta()) return false;

  memset(&sp, 0, sizeof(sp));
  memset(&spext, 0, sizeof(spext));

  if (s_wifi_sta_config.pass != NULL) {
    sp.Key = (_i8 *) s_wifi_sta_config.pass;
    sp.KeyLen = strlen(s_wifi_sta_config.pass);
  }
  if (s_wifi_sta_config.user != NULL && get_cfg()->wifi.sta.eap_method != 0) {
    /* WPA-enterprise mode */
    sp.Type = SL_WLAN_SEC_TYPE_WPA_ENT;
    spext.UserLen = strlen(s_wifi_sta_config.user);
    spext.User = (_i8 *) s_wifi_sta_config.user;
    if (s_wifi_sta_config.anon_identity != NULL) {
      spext.AnonUserLen = strlen(s_wifi_sta_config.anon_identity);
      spext.AnonUser = (_i8 *) s_wifi_sta_config.anon_identity;
    }
    spext.EapMethod = get_cfg()->wifi.sta.eap_method;
    unsigned char v = 0;
    sl_WlanSet(SL_WLAN_CFG_GENERAL_PARAM_ID, 19, 1, &v);
  } else {
    sp.Type = sp.KeyLen ? SL_WLAN_SEC_TYPE_WPA_WPA2 : SL_WLAN_SEC_TYPE_OPEN;
  }

  ret = sl_WlanConnect((const _i8 *) s_wifi_sta_config.ssid,
                       strlen(s_wifi_sta_config.ssid), 0, &sp,
                       (sp.Type == SL_WLAN_SEC_TYPE_WPA_ENT ? &spext : NULL));
  if (ret != 0) {
    LOG(LL_ERROR, ("sl_WlanConnect failed: %d", ret));
    return false;
  }

  sl_WlanRxStatStart();

  return true;
}

bool mgos_wifi_dev_disconnect(void) {
  free_wifi_config();
  return (sl_WlanDisconnect() == 0);
}

char *mgos_wifi_get_connected_ssid(void) {
  if (s_wifi_sta_config.ssid != NULL) return strdup(s_wifi_sta_config.ssid);
  return NULL;
}

bool mgos_wifi_dev_get_ip_info(int if_instance,
                               struct mgos_net_ip_info *ip_info) {
  int r = -1;
  SlNetCfgIpV4Args_t info = {0};
  SL_LEN_TYPE len = sizeof(info);
  SL_OPT_TYPE dhcp_is_on = 0;
  switch (if_instance) {
    case MGOS_NET_IF_WIFI_STA: {
      if (s_current_role != ROLE_STA) return false;
      r = sl_NetCfgGet(SL_NETCFG_IPV4_STA_ADDR_MODE, &dhcp_is_on, &len,
                       (_u8 *) &info);
      break;
    }
    case MGOS_NET_IF_WIFI_AP: {
      if (s_current_role != ROLE_AP) return false;
      r = sl_NetCfgGet(SL_NETCFG_IPV4_AP_ADDR_MODE, &dhcp_is_on, &len,
                       (_u8 *) &info);
      break;
    }
    default:
      return false;
  }
  if (r < 0) {
    LOG(LL_ERROR, ("sl_NetCfgGet failed: %d", r));
    return false;
  }
#if SL_MAJOR_VERSION_NUM >= 2
  ip_info->ip.sin_addr.s_addr = ntohl(info.Ip);
  ip_info->netmask.sin_addr.s_addr = ntohl(info.IpMask);
  ip_info->gw.sin_addr.s_addr = ntohl(info.IpGateway);
#else
  ip_info->ip.sin_addr.s_addr = ntohl(info.ipV4);
  ip_info->netmask.sin_addr.s_addr = ntohl(info.ipV4Mask);
  ip_info->gw.sin_addr.s_addr = ntohl(info.ipV4Gateway);
#endif
  return true;
}

static char *ip2str(uint32_t ip) {
  char *ipstr = NULL;
  mg_asprintf(&ipstr, 0, "%lu.%lu.%lu.%lu", SL_IPV4_BYTE(ip, 3),
              SL_IPV4_BYTE(ip, 2), SL_IPV4_BYTE(ip, 1), SL_IPV4_BYTE(ip, 0));
  return ipstr;
}

char *mgos_wifi_get_sta_default_dns(void) {
  SlNetCfgIpV4Args_t info = {0};
  SL_LEN_TYPE len = sizeof(info);
  SL_OPT_TYPE dhcp_is_on = 0;
  sl_NetCfgGet(SL_NETCFG_IPV4_STA_ADDR_MODE, &dhcp_is_on, &len, (_u8 *) &info);
#if SL_MAJOR_VERSION_NUM >= 2
  return (info.IpDnsServer != 0 ? ip2str(info.IpDnsServer) : NULL);
#else
  return (info.ipV4DnsServer != 0 ? ip2str(info.ipV4DnsServer) : NULL);
#endif
}

bool mgos_wifi_dev_start_scan(void) {
  bool ret = false;
  int n = -1, num_res = 0;
  struct mgos_wifi_scan_result *res = NULL;
  SlWlanNetworkEntry_t info[2];

  if (!ensure_role_sta()) goto out;

  while ((n = sl_WlanGetNetworkList(num_res, 2, info)) > 0) {
    int i, j;
    res = (struct mgos_wifi_scan_result *) realloc(
        res, (num_res + n) * sizeof(*res));
    if (res == NULL) {
      goto out;
    }
    for (i = 0, j = num_res; i < n; i++) {
      SlWlanNetworkEntry_t *e = &info[i];
      struct mgos_wifi_scan_result *r = &res[j];
      _u8 sec_type = 0;
#if SL_MAJOR_VERSION_NUM >= 2
      strncpy(r->ssid, (const char *) e->Ssid, sizeof(r->ssid));
      memcpy(r->bssid, e->Bssid, sizeof(r->bssid));
      r->rssi = e->Rssi;
      sec_type = SL_WLAN_SCAN_RESULT_SEC_TYPE_BITMAP(e->SecurityInfo);
#else
      strncpy(r->ssid, (const char *) e->ssid, sizeof(r->ssid));
      memcpy(r->bssid, e->bssid, sizeof(r->bssid));
      r->rssi = e->rssi;
      sec_type = e->sec_type;
#endif
      r->ssid[sizeof(r->ssid) - 1] = '\0';
      r->channel = 0; /* n/a */
      switch (sec_type) {
        case SL_WLAN_SECURITY_TYPE_BITMAP_OPEN:
          r->auth_mode = MGOS_WIFI_AUTH_MODE_OPEN;
          break;
        case SL_WLAN_SECURITY_TYPE_BITMAP_WEP:
          r->auth_mode = MGOS_WIFI_AUTH_MODE_WEP;
          break;
        case SL_WLAN_SECURITY_TYPE_BITMAP_WPA:
          r->auth_mode = MGOS_WIFI_AUTH_MODE_WPA_PSK;
          break;
        case SL_WLAN_SECURITY_TYPE_BITMAP_WPA2:
          r->auth_mode = MGOS_WIFI_AUTH_MODE_WPA2_PSK;
          break;
        default:

          continue;
      }
      num_res++;
      j++;
    }
  }
  ret = (n == 0); /* Reached the end of the list */

out:
  if (ret) {
    mgos_wifi_dev_scan_cb(num_res, res);
  } else {
    free(res);
  }
  return ret;
}

void mgos_wifi_dev_init(void) {
}
