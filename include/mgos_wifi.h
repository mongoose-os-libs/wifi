/*
 * Copyright (c) 2014-2016 Cesanta Software Limited
 * All rights reserved
 */

#ifndef CS_MOS_LIBS_WIFI_SRC_MGOS_WIFI_H_
#define CS_MOS_LIBS_WIFI_SRC_MGOS_WIFI_H_

#include <stdbool.h>
#include "mgos_sys_config.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * Setup wifi station; `struct mgos_config_wifi_sta` looks as follows:
 *
 * ```c
 * struct mgos_config_wifi_sta {
 *   int enable;
 *   char *ssid;
 *   char *pass;
 *   char *user;
 *   char *anon_identity;
 *   char *cert;
 *   char *key;
 *   char *ca_cert;
 *   char *ip;
 *   char *netmask;
 *   char *gw;
 *   char *nameserver;
 *   char *dhcp_hostname;
 * };
 * ```
 *
 * If `cfg->enable` is true, also calls `mgos_wifi_connect()`.
 */
bool mgos_wifi_setup_sta(const struct mgos_config_wifi_sta *cfg);

/*
 * Setup wifi access point; `struct mgos_config_wifi_ap` looks as follows:
 *
 * ```c
 * struct mgos_config_wifi_ap {
 *   int enable;
 *   char *ssid;
 *   char *pass;
 *   int hidden;
 *   int channel;
 *   int max_connections;
 *   char *ip;
 *   char *netmask;
 *   char *gw;
 *   char *dhcp_start;
 *   char *dhcp_end;
 *   int trigger_on_gpio;
 *   int disable_after;
 *   int keep_enabled;
 * };
 * ```
 */
bool mgos_wifi_setup_ap(const struct mgos_config_wifi_ap *cfg);

/*
 * Setup both wifi station and access point at once; `struct mgos_config_wifi`
 * looks as follows:
 *
 * ```c
 * struct mgos_config_wifi {
 *   struct mgos_config_wifi_sta sta; // See definition above
 *   struct mgos_config_wifi_ap ap;   // See definition above
 * };
 * ```
 */
bool mgos_wifi_setup(const struct mgos_config_wifi *cfg);

/*
 * Connect to the previously setup wifi station (with `mgos_wifi_setup_sta()`).
 */
bool mgos_wifi_connect(void);

/*
 * Disconnect from wifi station.
 */
bool mgos_wifi_disconnect(void);

#define MGOS_NET_IF_WIFI_STA 0
#define MGOS_NET_IF_WIFI_AP 1

/*
 * DEPRECATED: use `mgos_net_*` API instead.
 * Check for events with if_type == MGOS_NET_IF_TYPE_WIFI
 * and if_instance == MGOS_NET_IF_WIFI_STA or MGOS_NET_IF_WIFI_AP
 */
enum mgos_wifi_status {
  MGOS_WIFI_DISCONNECTED = 0,
  MGOS_WIFI_CONNECTING = 1,
  MGOS_WIFI_CONNECTED = 2,
  MGOS_WIFI_IP_ACQUIRED = 3,
  MGOS_WIFI_AP_DISCONNECTED = 4,
  MGOS_WIFI_AP_CONNECTED = 5
};

/*
 * DEPRECATED: use `mgos_net_*` API instead.
 *
 * Callback signature for `mgos_wifi_add_on_change_cb()`.
 */
typedef void (*mgos_wifi_changed_t)(enum mgos_wifi_status event, void *arg);

/*
 * DEPRECATED: use `mgos_net_*` API instead.
 *
 * Add a callback to be invoked when WiFi state changes.
 */
void mgos_wifi_add_on_change_cb(mgos_wifi_changed_t fn, void *arg);

/*
 * DEPRECATED: use `mgos_net_*` API instead.
 *
 * Remove a previously added callback, fn and arg have to match exactly.
 */
void mgos_wifi_remove_on_change_cb(mgos_wifi_changed_t fn, void *arg);

/*
 * Check whether the wifi access point config `cfg` is valid; if it is, `true`
 * is returned; otherwise `false` is returned and error message is written
 * to `*msg`. The caller should free `*msg`.
 */
bool mgos_wifi_validate_ap_cfg(const struct mgos_config_wifi_ap *cfg,
                               char **msg);

/*
 * Check whether the wifi station config `cfg` is valid; if it is, `true` is
 * returned; otherwise `false` is returned and error message is written to
 * `*msg`. The caller should free `*msg`.
 */
bool mgos_wifi_validate_sta_cfg(const struct mgos_config_wifi_sta *cfg,
                                char **msg);

/*
 * Get wifi status, see `enum mgos_wifi_status`.
 */
enum mgos_wifi_status mgos_wifi_get_status(void);

/*
 * Return wifi status string; the caller should free it.
 */
char *mgos_wifi_get_status_str(void);

/*
 * Return wifi ssid the device is currently connected to (if any); the caller
 * should free it. If the device is not connected to any wifi network, `NULL`
 * is returned.
 */
char *mgos_wifi_get_connected_ssid(void);

/*
 * Return default DNS server IP address. The caller should free it.
 */
char *mgos_wifi_get_sta_default_dns(void);

/*
 * Returns RSSI of the station if connected to an AP, otherwise 0.
 * Note: RSSI is a negative number.
 */
int mgos_wifi_sta_get_rssi(void);

/*
 * Auth mode for networks obtained with `mgos_wifi_scan()`.
 */
enum mgos_wifi_auth_mode {
  MGOS_WIFI_AUTH_MODE_OPEN = 0,
  MGOS_WIFI_AUTH_MODE_WEP = 1,
  MGOS_WIFI_AUTH_MODE_WPA_PSK = 2,
  MGOS_WIFI_AUTH_MODE_WPA2_PSK = 3,
  MGOS_WIFI_AUTH_MODE_WPA_WPA2_PSK = 4,
  MGOS_WIFI_AUTH_MODE_WPA2_ENTERPRISE = 5,
};

/*
 * One particular wifi network in the scan results, see `mgos_wifi_scan()`.
 */
struct mgos_wifi_scan_result {
  char ssid[33];
  uint8_t bssid[6];
  enum mgos_wifi_auth_mode auth_mode;
  int channel;
  int rssi;
};

/*
 * Callback prototype for `mgos_wifi_scan()`, called when wifi scan is done.
 * `num_res` is a number of networks found, `res` is a pointer to the first
 * one. `arg` is an arbitrary pointer given to `mgos_wifi_scan()`.
 *
 * See `mgos_wifi_scan()` for more details.
 */
typedef void (*mgos_wifi_scan_cb_t)(int num_res,
                                    struct mgos_wifi_scan_result *res,
                                    void *arg);

/*
 * Scan available wifi networks; when the scan is done, the provided callback
 * `cb` will be called with list of SSIDs or NULL on error.
 *
 * Each particular scan result isn't guaranteed to be exhaustive; a few scans
 * might be necessary to get all networks around.
 *
 * Caller owns SSIDS, they are not freed by the callee.
 *
 * A note for implementations: invoking inline is ok.
 */
void mgos_wifi_scan(mgos_wifi_scan_cb_t cb, void *arg);

/*
 * Deinitialize wifi.
 */
void mgos_wifi_deinit(void);

#ifdef MGOS_HAVE_MJS
struct mjs;
/*
 * Internal: implementation of mJS `Wifi.scan()`; available if only
 * `MGOS_HAVE_MJS` is 1.
 */
void mgos_wifi_scan_js(struct mjs *mjs);
#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* CS_MOS_LIBS_WIFI_SRC_MGOS_WIFI_H_ */
