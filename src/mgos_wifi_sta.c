/*
 * Copyright (c) Mongoose OS Contributors
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

#include "mgos_wifi_sta.h"

#include "mgos.h"
#include "mgos_wifi.h"
#include "mgos_wifi_hal.h"

#ifndef MGOS_WIFI_STA_AP_ATTEMPTS
#define MGOS_WIFI_STA_AP_ATTEMPTS 3
#endif

#ifndef MGOS_WIFI_STA_FAILING_AP_RETRY_SECONDS
#define MGOS_WIFI_STA_FAILING_AP_RETRY_SECONDS (60 * 60)  // 1 hour
#endif

#ifndef MGOS_WIFI_STA_AP_HISTORY_SIZE
#define MGOS_WIFI_STA_AP_HISTORY_SIZE 20
#endif

#ifndef MGOS_WIFI_STA_ROAM_RSSI_HYST
#define MGOS_WIFI_STA_ROAM_RSSI_HYST 5
#endif

#ifndef MGOS_WIFI_STA_MAX_AP_QUEUE_LEN
#define MGOS_WIFI_STA_MAX_AP_QUEUE_LEN 2
#endif

void wifi_lock(void);
void wifi_unlock(void);

enum wifi_sta_state {
  WIFI_STA_IDLE = 0,
  WIFI_STA_INIT = 1,
  WIFI_STA_SCAN = 2,
  WIFI_STA_SCANNING = 3,
  WIFI_STA_WAIT_CONNECT = 4,
  WIFI_STA_CONNECT = 5,
  WIFI_STA_CONNECTING = 6,
  WIFI_STA_CONNECTED = 7,
  WIFI_STA_IP_ACQUIRED = 8,
  WIFI_STA_SHUTDOWN = 9,  // Shutting down, do not reconnect.
};

int8_t s_num_cfgs = 0;
struct mgos_config_wifi_sta **s_cfgs = NULL;
const struct mgos_config_wifi_sta *s_cur_cfg = NULL;

struct wifi_ap_entry {
  const struct mgos_config_wifi_sta *cfg;
  uint8_t bssid[6];
  int8_t rssi;
  uint8_t num_attempts;
  int64_t last_attempt;
  SLIST_ENTRY(wifi_ap_entry) next;
};

const struct wifi_ap_entry *s_cur_entry = NULL;
static enum wifi_sta_state s_state = WIFI_STA_IDLE;
static mgos_timer_id s_connect_timer_id = MGOS_INVALID_TIMER_ID;
// AP is either on the queue or on the history list, not both.
static SLIST_HEAD(s_ap_queue, wifi_ap_entry) s_ap_queue;
static SLIST_HEAD(s_ap_history, wifi_ap_entry) s_ap_history;
static int64_t s_last_roam_attempt = 0;
static bool s_roaming = false;

static void mgos_wifi_sta_run(int wifi_ev, void *ev_data, bool timeout);

static bool is_sys_cfg(const struct mgos_config_wifi_sta *cfg) {
  return (cfg == mgos_sys_config_get_wifi_sta() ||
          cfg == mgos_sys_config_get_wifi_sta1() ||
          cfg == mgos_sys_config_get_wifi_sta2());
}

static void mgos_wifi_sta_free_cfg(struct mgos_config_wifi_sta *cfg) {
  if (is_sys_cfg(cfg)) return;
  mgos_config_wifi_sta_free(cfg);
}

static struct wifi_ap_entry *mgos_wifi_sta_find_history_entry(
    const uint8_t *bssid) {
  struct wifi_ap_entry *ape = NULL;
  SLIST_FOREACH(ape, &s_ap_history, next) {
    if (memcmp(ape->bssid, bssid, sizeof(ape->bssid)) == 0) return ape;
  }
  return NULL;
}

static void mgos_wifi_sta_remove_history_entry(struct wifi_ap_entry *ape) {
  SLIST_REMOVE(&s_ap_history, ape, wifi_ap_entry, next);
}

static void mgos_wifi_sta_add_history_entry(struct wifi_ap_entry *ape) {
  SLIST_INSERT_HEAD(&s_ap_history, ape, next);
  int num = 0;
  struct wifi_ap_entry *oldest = SLIST_FIRST(&s_ap_history);
  SLIST_FOREACH(ape, &s_ap_history, next) {
    num++;
    if (ape->last_attempt < oldest->last_attempt) oldest = ape;
  }
  if (num > MGOS_WIFI_STA_AP_HISTORY_SIZE) {
    mgos_wifi_sta_remove_history_entry(oldest);
    free(oldest);
  }
}

static const char *mgos_wifi_sta_bssid_to_str(const uint8_t *bssid,
                                              char *bssid_s) {
  snprintf(bssid_s, 20, "%02x:%02x:%02x:%02x:%02x:%02x", bssid[0], bssid[1],
           bssid[2], bssid[3], bssid[4], bssid[5]);
  return bssid_s;
}

static bool check_ap(const struct mgos_wifi_scan_result *e,
                     const struct mgos_config_wifi_sta **sta_cfg,
                     const struct wifi_ap_entry *hape, const char **reason) {
  *sta_cfg = NULL;
  for (int i = 0; i < s_num_cfgs; i++) {
    const struct mgos_config_wifi_sta *cfg = s_cfgs[i];
    if (!cfg->enable) continue;
    if (strcmp(cfg->ssid, e->ssid) != 0) continue;
    // Check if auth mode matches.
    bool have_pass = !mgos_conf_str_empty(cfg->pass);
    bool is_eap =
        (!mgos_conf_str_empty(cfg->cert) || !mgos_conf_str_empty(cfg->user));
    switch (e->auth_mode) {
      case MGOS_WIFI_AUTH_MODE_OPEN:
        if (have_pass || is_eap) continue;
        break;
      case MGOS_WIFI_AUTH_MODE_WPA2_ENTERPRISE:
        if (!is_eap) continue;
        break;
      case MGOS_WIFI_AUTH_MODE_WEP:
      case MGOS_WIFI_AUTH_MODE_WPA_PSK:
      case MGOS_WIFI_AUTH_MODE_WPA2_PSK:
      case MGOS_WIFI_AUTH_MODE_WPA_WPA2_PSK:
        if (!have_pass) continue;
        break;
    }
    // If the config specifies a particular BSSID, check it.
    if (!mgos_conf_str_empty(cfg->bssid)) {
      char bssid_s[20];
      mgos_wifi_sta_bssid_to_str(e->bssid, bssid_s);
      if (strcasecmp(cfg->bssid, bssid_s) != 0) {
        continue;
      }
    }
    *sta_cfg = cfg;
    break;
  }
  if (*sta_cfg == NULL) {
    *reason = "no matching config";
    return false;
  }
  if (e->rssi < mgos_sys_config_get_wifi_sta_rssi_thr()) {
    *reason = "too weak";
    return false;
  }
  if (hape != NULL && hape->num_attempts >= MGOS_WIFI_STA_AP_ATTEMPTS &&
      (mgos_uptime_micros() - hape->last_attempt <
       (MGOS_WIFI_STA_FAILING_AP_RETRY_SECONDS * 1000000LL))) {
    *reason = "bad history";
    return false;
  }
  *reason = "ok";
  return true;
}

static void mgos_wifi_sta_connect_timeout_timer_cb(void *arg) {
  wifi_lock();
  mgos_wifi_sta_run(-1 /* wifi_ev */, NULL /* evd */, true /* timeout */);
  wifi_unlock();
  (void) arg;
}

static void set_timeout_n(int timeout, bool run_now) {
  mgos_clear_timer(s_connect_timer_id);
  s_connect_timer_id = mgos_set_timer(
      timeout, MGOS_TIMER_REPEAT, mgos_wifi_sta_connect_timeout_timer_cb, NULL);
  if (run_now) {
    mgos_wifi_sta_run(-1 /* wifi_ev */, NULL /* evd */, false /* timeout */);
  }
}

static void set_timeout(bool run_now) {
  set_timeout_n(mgos_sys_config_get_wifi_sta_connect_timeout() * 1000, run_now);
}

static void mgos_wifi_sta_build_queue(int num_res,
                                      struct mgos_wifi_scan_result *res,
                                      bool check_history) {
  for (int i = 0; i < num_res; i++) {
    const struct mgos_wifi_scan_result *e = &res[i];
    const struct mgos_config_wifi_sta *cfg = NULL;
    const char *reason = NULL;
    struct wifi_ap_entry *eape = mgos_wifi_sta_find_history_entry(e->bssid);
    bool ok = check_ap(e, &cfg, (check_history ? eape : NULL), &reason);
    /* Check if we already have this queued. */
    int len = 0;
    struct wifi_ap_entry *pape = NULL;
    if (ok) {
      struct wifi_ap_entry *ape = NULL;
      SLIST_FOREACH(ape, &s_ap_queue, next) {
        if (memcmp(ape->bssid, e->bssid, sizeof(e->bssid)) == 0) {
          ok = false;
          reason = "dup";
          break;
        }
        len++;
        /* Among bad ones, prefer those with fewer attempts.
         * This will have the effect of cycling through all available ones
         * even when there are more than the queue can hold. */
        if (ape->num_attempts >= MGOS_WIFI_STA_AP_ATTEMPTS && eape != NULL &&
            eape->num_attempts >= MGOS_WIFI_STA_AP_ATTEMPTS &&
            eape->num_attempts != ape->num_attempts) {
          if (eape->num_attempts > ape->num_attempts) {
            pape = ape;
          }
          continue;
        }
        /* Stronger signal APs stay at the front of the queue. */
        if (ape->rssi >= e->rssi) {
          pape = ape;
        }
      }
    }
    if (ok) {
      if (eape == NULL) {
        eape = calloc(1, sizeof(*eape));
        memcpy(eape->bssid, e->bssid, sizeof(eape->bssid));
      } else {
        mgos_wifi_sta_remove_history_entry(eape);
      }
      if (eape == NULL) return;
      eape->cfg = cfg;
      eape->rssi = e->rssi;
      if (pape != NULL) {
        SLIST_INSERT_AFTER(pape, eape, next);
      } else {
        SLIST_INSERT_HEAD(&s_ap_queue, eape, next);
      }
      len++;
      while (len > MGOS_WIFI_STA_MAX_AP_QUEUE_LEN) {
        len = 0;
        pape = NULL;
        struct wifi_ap_entry *ape = NULL;
        SLIST_FOREACH(ape, &s_ap_queue, next) {
          if (SLIST_NEXT(ape, next) == NULL) {
            if (pape != NULL) {
              SLIST_REMOVE_AFTER(pape, next);
            } else {
              SLIST_REMOVE_HEAD(&s_ap_queue, next);
            }
            // If evicted entry has been tried before, put it back on the
            // history list. If it's a completely new AP that didn't make it,
            // just drop it on the floor, we'll find it again next time.
            if (ape->num_attempts > 0) {
              mgos_wifi_sta_add_history_entry(ape);
            } else {
              free(ape);
              if (eape == ape) eape = NULL;
            }
            break;
          }
          pape = ape;
          len++;
        }
      }
    }
    LOG(LL_DEBUG,
        ("  %d: SSID: %-32s, BSSID: %02x:%02x:%02x:%02x:%02x:%02x "
         "auth: %d, ch: %3d, RSSI: %2d att %d - %d %s %p",
         i, e->ssid, e->bssid[0], e->bssid[1], e->bssid[2], e->bssid[3],
         e->bssid[4], e->bssid[5], e->auth_mode, e->channel, e->rssi,
         (eape ? eape->num_attempts : -1), ok, reason, eape));
    (void) reason;
  }
}

void mgos_wifi_sta_scan_cb(int num_res, struct mgos_wifi_scan_result *res,
                           void *arg) {
  if (s_state != WIFI_STA_SCANNING) return;
  LOG(LL_DEBUG, ("WiFi scan result: %d entries", num_res));
  if (num_res < 0) {
    s_state = WIFI_STA_SCAN;
    return;
  }
  mgos_wifi_sta_build_queue(num_res, res, true /* check_history */);
  if (SLIST_EMPTY(&s_ap_queue)) {
    /* No good quality APs left to try, keep trying bad ones. */
    LOG(LL_DEBUG, ("Second pass"));
    mgos_wifi_sta_build_queue(num_res, res, false /* check_history */);
  }
  if (!SLIST_EMPTY(&s_ap_queue)) {
    int i = 0;
    struct wifi_ap_entry *ape = NULL;
    LOG(LL_DEBUG, ("AP queue:"));
    SLIST_FOREACH(ape, &s_ap_queue, next) {
      const uint8_t *bssid = &ape->bssid[0];
      LOG(LL_DEBUG, ("  %d: %02x:%02x:%02x:%02x:%02x:%02x %d %d", i, bssid[0],
                     bssid[1], bssid[2], bssid[3], bssid[4], bssid[5],
                     ape->rssi, ape->num_attempts));
      i++;
    }
  }
  s_state = WIFI_STA_CONNECT;
  set_timeout(true /* run_now */);
  (void) arg;
}

static void mgos_wifi_sta_empty_queue(void) {
  while (!SLIST_EMPTY(&s_ap_queue)) {
    struct wifi_ap_entry *ape = SLIST_FIRST(&s_ap_queue);
    SLIST_REMOVE_HEAD(&s_ap_queue, next);
    mgos_wifi_sta_add_history_entry(ape);
  }
}

static void mgos_wifi_sta_run(int wifi_ev, void *ev_data, bool timeout) {
  LOG(LL_DEBUG, ("State %d ev %d timeout %d", s_state, wifi_ev, timeout));
  if (wifi_ev == MGOS_WIFI_EV_STA_DISCONNECTED) {
    s_roaming = false;
    s_cur_entry = NULL;
  }
  switch (s_state) {
    case WIFI_STA_IDLE:
      break;
    case WIFI_STA_INIT:
      mgos_wifi_dev_sta_disconnect();
      s_state = WIFI_STA_SCAN;
      set_timeout(true /* run_now */);
      s_roaming = false;
      s_cur_entry = NULL;
      break;
    case WIFI_STA_SCAN:
      LOG(LL_DEBUG, ("Starting scan"));
      mgos_wifi_sta_empty_queue();
      s_state = WIFI_STA_SCANNING;
      mgos_wifi_scan(mgos_wifi_sta_scan_cb, NULL);
      break;
    case WIFI_STA_SCANNING:
      if (timeout) {
        s_state = WIFI_STA_SCAN;
        set_timeout(true /* run_now */);
      }
      break;
    case WIFI_STA_WAIT_CONNECT:
      if (!timeout) {
        set_timeout_n(1000, false /* run_now */);
        break;
      }
      s_state = WIFI_STA_CONNECT;
      set_timeout_n(1000, true /* run_now */);
      break;
    case WIFI_STA_CONNECT: {
      struct wifi_ap_entry *ape = SLIST_FIRST(&s_ap_queue);
      if (s_roaming) {
        s_roaming = false;
        // If we are roaming and have no good candidate, go back.
        int cur_rssi = mgos_wifi_sta_get_rssi();
        bool ok = false;
        if (ape == NULL) {
          LOG(LL_DEBUG, ("No alternative APs found"));
        } else if (s_cur_entry != NULL && memcmp(s_cur_entry->bssid, ape->bssid,
                                                 sizeof(ape->bssid)) == 0) {
          LOG(LL_DEBUG, ("Best AP is the same"));
        } else if (ape->rssi <= mgos_sys_config_get_wifi_sta_roam_rssi_thr() ||
                   (ape->rssi - MGOS_WIFI_STA_ROAM_RSSI_HYST) < cur_rssi) {
          LOG(LL_DEBUG, ("Best AP is not good enough (RSSI %d vs %d)",
                         ape->rssi, cur_rssi));
        } else {
          ok = true;
        }
        if (!ok) {
          s_state = WIFI_STA_IP_ACQUIRED;
          set_timeout(true /* run_now */);
          break;
        }
        // We have a better AP candidate, disconnect and try to roam.
        char bssid_s[20];
        LOG(LL_INFO, ("Trying to switch to %s (RSSI %d -> %d)",
                      mgos_wifi_sta_bssid_to_str(ape->bssid, bssid_s), cur_rssi,
                      ape->rssi));
        mgos_wifi_dev_sta_disconnect();
        // We need to allow some time for connection to terminate.
        s_cur_entry = NULL;
        s_state = WIFI_STA_WAIT_CONNECT;
        set_timeout_n(1000, false /* run_now */);
        break;
      }
      if (ape == NULL) {
        LOG(LL_DEBUG, ("No more candidate APs"));
        s_state = WIFI_STA_SCAN;
        set_timeout(true /* run_now */);
        break;
      }
      ape->num_attempts++;
      uint8_t *bssid = &ape->bssid[0];
      LOG(LL_INFO,
          ("Trying %s AP %02x:%02x:%02x:%02x:%02x:%02x RSSI %d attempt %d",
           ape->cfg->ssid, bssid[0], bssid[1], bssid[2], bssid[3], bssid[4],
           bssid[5], ape->rssi, ape->num_attempts));
      ape->last_attempt = mgos_uptime_micros();
      char bssid_s[20];
      mgos_wifi_sta_bssid_to_str(bssid, bssid_s);
      struct mgos_config_wifi_sta sta_cfg = *ape->cfg;
      sta_cfg.bssid = bssid_s;
      mgos_wifi_dev_sta_setup(&sta_cfg);
      mgos_wifi_dev_sta_connect();
      s_state = WIFI_STA_CONNECTING;
      set_timeout(true /* run_now */);
      break;
    }
    case WIFI_STA_CONNECTING: {
      if (wifi_ev == MGOS_WIFI_EV_STA_DISCONNECTED || timeout) {
        LOG(LL_INFO, ("Connect failed"));
        // Remove the queue entry that failed.
        struct wifi_ap_entry *ape = SLIST_FIRST(&s_ap_queue);
        SLIST_REMOVE_HEAD(&s_ap_queue, next);
        mgos_wifi_sta_add_history_entry(ape);
        // Stop connection attempts and let things settle before moving on.
        mgos_wifi_dev_sta_disconnect();
        s_cur_entry = NULL;
        s_state = WIFI_STA_WAIT_CONNECT;
        set_timeout_n(1000, false /* run_now */);
        break;
      }
      if (wifi_ev == MGOS_WIFI_EV_STA_CONNECTED) {
        s_cur_entry = SLIST_FIRST(&s_ap_queue);
        s_state = WIFI_STA_CONNECTED;
      }
      break;
    }
    case WIFI_STA_CONNECTED: {
      if (wifi_ev == MGOS_WIFI_EV_STA_IP_ACQUIRED) {
        struct wifi_ap_entry *ape = SLIST_FIRST(&s_ap_queue);
        ape->num_attempts = 0;
        mgos_wifi_sta_empty_queue();
        s_last_roam_attempt = mgos_uptime_micros();
        s_state = WIFI_STA_IP_ACQUIRED;
        break;
      }
      int cur_rssi = mgos_wifi_sta_get_rssi();
      if (timeout || wifi_ev == MGOS_WIFI_EV_STA_DISCONNECTED ||
          cur_rssi == 0) {
        s_state = WIFI_STA_INIT;
        set_timeout_n(1000, false /* run_now */);
        break;
      }
      break;
    }
    case WIFI_STA_IP_ACQUIRED: {
      int cur_rssi = mgos_wifi_sta_get_rssi();
      if (wifi_ev == MGOS_WIFI_EV_STA_DISCONNECTED || cur_rssi == 0) {
        s_state = WIFI_STA_INIT;
        set_timeout_n(1000, false /* run_now */);
        break;
      }
      if (cur_rssi < mgos_sys_config_get_wifi_sta_roam_rssi_thr()) {
        if (mgos_uptime_micros() - s_last_roam_attempt >
            mgos_sys_config_get_wifi_sta_roam_interval() * 1000000) {
          LOG(LL_INFO,
              ("Current RSSI %d, will scan for a better AP", cur_rssi));
          s_roaming = true;
          s_state = WIFI_STA_SCAN;
          set_timeout(true /* run_now */);
          s_last_roam_attempt = mgos_uptime_micros();
          break;
        }
      }
      break;
    }
    case WIFI_STA_SHUTDOWN:
      break;
  }
}

static void mgos_wifi_ev_handler(int ev, void *evd, void *cb_arg) {
  wifi_lock();
  mgos_wifi_sta_run(ev, evd, false /* timeout */);
  wifi_unlock();
  (void) cb_arg;
}

bool mgos_wifi_connect(void) {
  int ret = true;
  wifi_lock();
  switch (s_state) {
    case WIFI_STA_SHUTDOWN:
      ret = false;
      break;
    case WIFI_STA_IDLE:
      s_state = WIFI_STA_INIT;
      set_timeout(true /* run_now */);
      break;
    case WIFI_STA_INIT:
    case WIFI_STA_SCAN:
    case WIFI_STA_SCANNING:
    case WIFI_STA_WAIT_CONNECT:
    case WIFI_STA_CONNECT:
    case WIFI_STA_CONNECTING:
    case WIFI_STA_CONNECTED:
    case WIFI_STA_IP_ACQUIRED:
      break;
  }
  wifi_unlock();
  return ret;
}

bool mgos_wifi_disconnect(void) {
  wifi_lock();
  bool ret = true;
  if (s_state == WIFI_STA_SHUTDOWN) {
    wifi_unlock();
    return true;
  }
  bool disconnect = (s_state != WIFI_STA_IDLE);
  mgos_clear_timer(s_connect_timer_id);
  s_connect_timer_id = MGOS_INVALID_TIMER_ID;
  s_state = WIFI_STA_IDLE;
  if (disconnect) {
    ret = mgos_wifi_dev_sta_disconnect();
    s_cur_entry = NULL;
  }
  wifi_unlock();
  return ret;
}

enum mgos_wifi_status mgos_wifi_get_status(void) {
  switch (s_state) {
    case WIFI_STA_IDLE:
    case WIFI_STA_SHUTDOWN:
      return MGOS_WIFI_DISCONNECTED;
    case WIFI_STA_SCAN:
    case WIFI_STA_SCANNING:
      if (s_roaming) {
        return MGOS_WIFI_IP_ACQUIRED;
      } else {
        return MGOS_WIFI_CONNECTING;
      }
    case WIFI_STA_INIT:
    case WIFI_STA_WAIT_CONNECT:
    case WIFI_STA_CONNECT:
    case WIFI_STA_CONNECTING:
      return MGOS_WIFI_CONNECTING;
    case WIFI_STA_CONNECTED:
      return MGOS_WIFI_CONNECTED;
    case WIFI_STA_IP_ACQUIRED:
      return MGOS_WIFI_IP_ACQUIRED;
  }
  return MGOS_WIFI_DISCONNECTED;
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

static void mgos_wifi_shutdown_cb(void *arg) {
  mgos_wifi_disconnect();
  wifi_lock();
  s_state = WIFI_STA_SHUTDOWN;
  wifi_unlock();
  (void) arg;
}

static void mgos_wifi_reboot_after_ev_handler(int ev, void *evd, void *cb_arg) {
  const struct mgos_event_reboot_after_arg *arg =
      (struct mgos_event_reboot_after_arg *) evd;
  int64_t time_to_reboot_ms =
      (arg->reboot_at_uptime_micros - mgos_uptime_micros()) / 1000;
  if (time_to_reboot_ms > 50) {
    mgos_set_timer(time_to_reboot_ms - 50, 0, mgos_wifi_shutdown_cb, NULL);
  } else {
    mgos_wifi_shutdown_cb(NULL);
  }
  (void) ev;
  (void) cb_arg;
}

bool mgos_wifi_sta_add_cfg(const struct mgos_config_wifi_sta *cfg) {
  if (!cfg->enable) return false;
  if (!mgos_wifi_validate_sta_cfg(cfg, NULL)) return false;
  struct mgos_config_wifi_sta *cfg2;
  if (is_sys_cfg(cfg)) {
    cfg2 = (struct mgos_config_wifi_sta *) cfg;
  } else {
    cfg2 = calloc(1, sizeof(*cfg));
    if (cfg2 == NULL) return false;
    if (!mgos_config_wifi_sta_copy(cfg, cfg2)) return false;
  }
  struct mgos_config_wifi_sta **cfgs =
      realloc(s_cfgs, (s_num_cfgs + 1) * sizeof(*s_cfgs));
  if (cfgs == NULL) return false;
  cfgs[s_num_cfgs] = cfg2;
  s_cfgs = cfgs;
  s_num_cfgs++;
  return true;
}

void mgos_wifi_sta_clear_cfgs(void) {
  s_cur_entry = NULL;
  while (!SLIST_EMPTY(&s_ap_queue)) {
    struct wifi_ap_entry *ape = SLIST_FIRST(&s_ap_queue);
    SLIST_REMOVE_HEAD(&s_ap_queue, next);
    free(ape);
  }
  while (!SLIST_EMPTY(&s_ap_history)) {
    struct wifi_ap_entry *ape = SLIST_FIRST(&s_ap_history);
    SLIST_REMOVE_HEAD(&s_ap_history, next);
    free(ape);
  }
  for (int i = 0; i < s_num_cfgs; i++) {
    mgos_wifi_sta_free_cfg(s_cfgs[i]);
  }
  s_num_cfgs = 0;
  free(s_cfgs);
  s_cfgs = NULL;
}

char *mgos_wifi_get_connected_ssid(void) {
  if (s_cur_entry == NULL) return NULL;
  return strdup(s_cur_entry->cfg->ssid);
}

void mgos_wifi_sta_init(void) {
  mgos_event_add_group_handler(MGOS_WIFI_EV_BASE, mgos_wifi_ev_handler, NULL);
  mgos_event_add_handler(MGOS_EVENT_REBOOT_AFTER,
                         mgos_wifi_reboot_after_ev_handler, NULL);
}
