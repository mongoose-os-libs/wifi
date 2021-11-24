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

#include <strings.h>

#include "mgos.h"
#include "mgos_wifi.h"
#include "mgos_wifi_hal.h"

#ifndef MGOS_WIFI_STA_AP_ATTEMPTS
#define MGOS_WIFI_STA_AP_ATTEMPTS 5
#endif

#ifndef MGOS_WIFI_STA_FAILING_AP_RETRY_SECONDS
#define MGOS_WIFI_STA_FAILING_AP_RETRY_SECONDS (60 * 60)  // 1 hour
#endif

#ifndef MGOS_WIFI_STA_MAX_AP_HISTORY_LEN
#define MGOS_WIFI_STA_MAX_AP_HISTORY_LEN 25
#endif

#ifndef MGOS_WIFI_STA_ROAM_RSSI_HYST
#define MGOS_WIFI_STA_ROAM_RSSI_HYST 5
#endif

#ifndef MGOS_WIFI_STA_MAX_AP_QUEUE_LEN
#define MGOS_WIFI_STA_MAX_AP_QUEUE_LEN 10
#endif

// OUI cannot be 0, so checking first 3 bytes is sufficient.
#define BSSID_EMPTY(bssid) \
  ((bssid)[0] == 0 && (bssid)[1] == 0 && (bssid)[2] == 0)

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

struct wifi_ap_entry {
  struct mgos_config_wifi_sta *cfg;
  SLIST_ENTRY(wifi_ap_entry) next;
  uint64_t last_attempt : 56;
  uint64_t is_wildcard : 1;
  uint8_t bssid[6];
  int8_t channel;
  int8_t rssi;
  uint8_t num_attempts;
};

struct wifi_ap_entry *s_cur_entry = NULL;
static enum wifi_sta_state s_state = WIFI_STA_IDLE;
static mgos_timer_id s_connect_timer_id = MGOS_INVALID_TIMER_ID;
// AP is either on the queue or on the history list, not both.
SLIST_HEAD(wifi_ap_list, wifi_ap_entry);
static struct wifi_ap_list s_ap_queue, s_ap_history;
static int64_t s_last_roam_attempt = 0;
static bool s_roaming = false;
static union {
  int8_t samples[4];
  uint32_t val;
} s_rssi_info;

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

static void mgos_wifi_sta_free_ap_entry(struct wifi_ap_entry *ape) {
  memset(ape, 0, sizeof(*ape));
  free(ape);
}

static struct wifi_ap_entry *mgos_wifi_sta_find_history_entry(
    const uint8_t *bssid, const struct mgos_config_wifi_sta *cfg) {
  struct wifi_ap_entry *ape = NULL;
  bool is_wildcard = BSSID_EMPTY(bssid);
  SLIST_FOREACH(ape, &s_ap_history, next) {
    if (ape->cfg != cfg) continue;
    if (ape->is_wildcard != is_wildcard) continue;
    if (is_wildcard || memcmp(ape->bssid, bssid, sizeof(ape->bssid)) == 0) {
      return ape;
    }
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
  if (num > MGOS_WIFI_STA_MAX_AP_HISTORY_LEN) {
    mgos_wifi_sta_remove_history_entry(oldest);
    mgos_wifi_sta_free_ap_entry(oldest);
  }
}

static const char *mgos_wifi_sta_bssid_to_str(const uint8_t *bssid,
                                              char *bssid_s) {
  snprintf(bssid_s, 20, "%02x:%02x:%02x:%02x:%02x:%02x", bssid[0], bssid[1],
           bssid[2], bssid[3], bssid[4], bssid[5]);
  return bssid_s;
}

static bool mgos_wifi_sta_bssid_from_str(const char *bssid_s, uint8_t *bssid) {
  if (bssid_s == NULL) return false;
  unsigned int bi[6] = {0};
  if (sscanf(bssid_s, "%02x:%02x:%02x:%02x:%02x:%02x", &bi[0], &bi[1], &bi[2],
             &bi[3], &bi[4], &bi[5]) != 6) {
    return false;
  }
  for (int i = 0; i < 6; i++) {
    bssid[i] = bi[i];
  }
  return true;
}

static void mgos_wifi_sta_run_cb(void *arg) {
  wifi_lock();
  bool is_timeout = (arg != NULL);
  mgos_wifi_sta_run(-1 /* wifi_ev */, NULL /* evd */, is_timeout);
  wifi_unlock();
}

static void mgos_wifi_sta_set_timeout_n(int timeout, bool run_now) {
  mgos_clear_timer(s_connect_timer_id);
  s_connect_timer_id = mgos_set_timer(timeout, MGOS_TIMER_REPEAT,
                                      mgos_wifi_sta_run_cb, (void *) 1);
  if (run_now) {
    mgos_invoke_cb(mgos_wifi_sta_run_cb, NULL, false /* from_isr */);
  }
}

static void mgos_wifi_sta_set_timeout(bool run_now) {
  mgos_wifi_sta_set_timeout_n(
      mgos_sys_config_get_wifi_sta_connect_timeout() * 1000, run_now);
}

static bool check_ap(const struct mgos_wifi_scan_result *e,
                     struct mgos_config_wifi_sta **sta_cfg, int *cfg_index,
                     bool check_history, struct wifi_ap_entry **hape,
                     const char **reason) {
  for (int i = 0; i < s_num_cfgs; i++) {
    struct mgos_config_wifi_sta *cfg = s_cfgs[i];
    if (*sta_cfg != NULL) {  // Continue iterating from last config.
      if (cfg == *sta_cfg) {
        // Start checking for real from the next entry.
        *sta_cfg = NULL;
      }
      continue;
    }
    // When roaming we only consider current config.
    if (s_roaming && cfg != s_cur_entry->cfg) {
      continue;
    }
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
    // If the config specifies a particular BSSID and/or channel, check them.
    if (!mgos_conf_str_empty(cfg->bssid)) {
      char bssid_s[20];
      mgos_wifi_sta_bssid_to_str(e->bssid, bssid_s);
      if (strcasecmp(cfg->bssid, bssid_s) != 0) {
        continue;
      }
    }
    if (cfg->channel > 0 && cfg->channel != e->channel) {
      continue;
    }
    *sta_cfg = cfg;
    *cfg_index = i;
    *hape = mgos_wifi_sta_find_history_entry(e->bssid, cfg);
    break;
  }
  if (*sta_cfg == NULL) {
    *reason = "no cfg";
    return false;
  }
  if (e->rssi < mgos_sys_config_get_wifi_sta_rssi_thr()) {
    *reason = "too weak";
    return false;
  }
  if (check_history && *hape != NULL) {
    if ((*hape)->num_attempts >= MGOS_WIFI_STA_AP_ATTEMPTS &&
        (mgos_uptime_micros() - (*hape)->last_attempt <
         (MGOS_WIFI_STA_FAILING_AP_RETRY_SECONDS * 1000000LL))) {
      *reason = "bad";
      return false;
    }
  }
  *reason = "ok";
  return true;
}

static int get_cfg_index(const struct mgos_config_wifi_sta *cfg) {
  for (int i = 0; i < s_num_cfgs; i++) {
    if (s_cfgs[i] == cfg) return i;
  }
  return -1;
}

static void mgos_wifi_sta_build_queue(int num_res,
                                      struct mgos_wifi_scan_result *res,
                                      bool check_history, uint32_t *seen_cfg) {
  for (int i = 0; i < num_res; i++) {
    const struct mgos_wifi_scan_result *e = &res[i];
    struct mgos_config_wifi_sta *cfg = NULL;
    int cfg_index = -1;
    bool first = true;
    while (true) {
      const char *reason = NULL;
      struct wifi_ap_entry *eape = NULL;
      bool ok = check_ap(e, &cfg, &cfg_index, check_history, &eape, &reason);
      if (ok || first) {
        LOG(LL_DEBUG,
            ("  %d: SSID %-32s BSSID %02x:%02x:%02x:%02x:%02x:%02x "
             "auth %d, ch %2d, RSSI %2d - %s cfg %d att %d",
             i, e->ssid, e->bssid[0], e->bssid[1], e->bssid[2], e->bssid[3],
             e->bssid[4], e->bssid[5], e->auth_mode, e->channel, e->rssi,
             reason, cfg_index, (eape ? eape->num_attempts : -1)));
      }
      if (cfg_index != -1) {
        *seen_cfg |= (1 << cfg_index);
      }
      if (!ok) break;
      first = false;
      int len = 0;
      struct wifi_ap_entry *pape = NULL;
      // Find a position in the queue for this AP.
      struct wifi_ap_entry *ape = NULL;
      SLIST_FOREACH(ape, &s_ap_queue, next) {
        if (memcmp(ape->bssid, e->bssid, sizeof(e->bssid)) == 0 &&
            ape->cfg == cfg) {
          ok = false;
          reason = "dup";
          break;
        }
        // Config index indicates preference: lower index = higher preference.
        int ape_cfg_index = get_cfg_index(ape->cfg);
        if (cfg_index != ape_cfg_index) {
          if (cfg_index > ape_cfg_index) {
            pape = ape;
          }
          continue;
        }
        // Among bad ones, prefer those with fewer attempts.
        // This will have the effect of cycling through all available ones
        // even when there are more than the queue can hold.
        if (ape->num_attempts >= MGOS_WIFI_STA_AP_ATTEMPTS && eape != NULL &&
            eape->num_attempts >= MGOS_WIFI_STA_AP_ATTEMPTS &&
            eape->num_attempts != ape->num_attempts) {
          if (eape->num_attempts > ape->num_attempts) {
            pape = ape;
          }
          continue;
        }
        /* Stronger signal APs stay at the front of the queue. */
        if (ape->rssi > e->rssi) {
          pape = ape;
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
        eape->channel = e->channel;
        if (pape != NULL) {
          SLIST_INSERT_AFTER(pape, eape, next);
        } else {
          SLIST_INSERT_HEAD(&s_ap_queue, eape, next);
        }
        len++;
        while (len > MGOS_WIFI_STA_MAX_AP_QUEUE_LEN) {
          len = 0;
          pape = NULL;
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
                mgos_wifi_sta_free_ap_entry(ape);
                if (eape == ape) eape = NULL;
              }
              break;
            }
            pape = ape;
            len++;
          }
        }
      }
      (void) reason;
    }
  }
}

static void mgos_wifi_sta_dump_list(const struct wifi_ap_list *list,
                                    const char *name) {
  if (SLIST_EMPTY(list)) return;
  int i = 0;
  struct wifi_ap_entry *ape = NULL;
  LOG(LL_DEBUG, ("AP %s:", name));
  int64_t now = mgos_uptime_micros();
  SLIST_FOREACH(ape, list, next) {
    const uint8_t *bssid = &ape->bssid[0];
    int age = -1;
    if (ape->last_attempt > 0) {
      age = (now - ape->last_attempt) / 1000000;
    }
    LOG(LL_DEBUG,
        ("  %d: SSID %-32s, BSSID %02x:%02x:%02x:%02x:%02x:%02x "
         "ch %2d RSSI %2d cfg %d att %u wc %d age %d",
         i, ape->cfg->ssid, bssid[0], bssid[1], bssid[2], bssid[3], bssid[4],
         bssid[5], ape->channel, ape->rssi, get_cfg_index(ape->cfg),
         ape->num_attempts, ape->is_wildcard, age));
    (void) bssid;
    (void) age;
    i++;
  }
  (void) name;
}

void mgos_wifi_sta_scan_cb(int num_res, struct mgos_wifi_scan_result *res,
                           void *arg) {
  if (s_state != WIFI_STA_SCANNING) return;
  LOG(LL_DEBUG, ("WiFi scan result: %d entries", num_res));
  if (num_res < 0) {
    s_state = WIFI_STA_SCAN;  // Retry.
    return;
  }
  uint32_t seen_cfg = 0;
  mgos_wifi_sta_build_queue(num_res, res, true /* check_history */, &seen_cfg);
  if (SLIST_EMPTY(&s_ap_queue)) {
    // No good quality APs left to try, keep trying bad ones.
    LOG(LL_DEBUG, ("Second pass"));
    mgos_wifi_sta_build_queue(num_res, res, false /* check_history */,
                              &seen_cfg);
  }
  // If we found absolutely no APs for a config that is enabled,
  // insert a non-specific/wildcard entry in case it's a hidden network.
  for (int cfg_index = 0; cfg_index < s_num_cfgs; cfg_index++) {
    struct mgos_config_wifi_sta *cfg = s_cfgs[cfg_index];
    if (!cfg->enable) continue;
    if (seen_cfg & (1 << cfg_index)) continue;
    bool found = false;
    struct wifi_ap_entry *ape = NULL, *pape = NULL;
    SLIST_FOREACH(ape, &s_ap_queue, next) {
      if (ape->cfg == cfg) {
        found = true;
        break;
      }
      int ape_cfg_index = get_cfg_index(ape->cfg);
      if (ape_cfg_index < cfg_index) {
        pape = ape;
      } else {
        break;
      }
    }
    if (found) continue;
    uint8_t bssid[6];
    if (!mgos_wifi_sta_bssid_from_str(cfg->bssid, bssid)) {
      memset(bssid, 0, sizeof(bssid));  // Wildcard.
    }
    struct wifi_ap_entry *eape = mgos_wifi_sta_find_history_entry(bssid, cfg);
    if (eape == NULL) {
      eape = calloc(1, sizeof(*eape));
      if (eape == NULL) return;
      eape->cfg = cfg;
      eape->is_wildcard = BSSID_EMPTY(bssid);
      eape->channel = cfg->channel;
    } else {
      mgos_wifi_sta_remove_history_entry(eape);
    }
    if (pape != NULL) {
      SLIST_INSERT_AFTER(pape, eape, next);
    } else {
      SLIST_INSERT_HEAD(&s_ap_queue, eape, next);
    }
  }
  mgos_wifi_sta_dump_list(&s_ap_queue, "queue");
  mgos_wifi_sta_dump_list(&s_ap_history, "history");
  s_state = WIFI_STA_CONNECT;
  mgos_wifi_sta_set_timeout(true /* run_now */);
  (void) arg;
}

static void mgos_wifi_sta_empty_queue(void) {
  while (!SLIST_EMPTY(&s_ap_queue)) {
    struct wifi_ap_entry *ape = SLIST_FIRST(&s_ap_queue);
    SLIST_REMOVE_HEAD(&s_ap_queue, next);
    if (ape->last_attempt != 0) {
      mgos_wifi_sta_add_history_entry(ape);
    } else {
      mgos_wifi_sta_free_ap_entry(ape);
    }
  }
}

static void mgos_wifi_sta_run(int wifi_ev, void *ev_data, bool timeout) {
  LOG(LL_DEBUG, ("State %d ev %d timeout %d", s_state, wifi_ev, timeout));
  if (wifi_ev == MGOS_WIFI_EV_STA_DISCONNECTED) {
    s_roaming = false;
  }
  switch (s_state) {
    case WIFI_STA_IDLE:
      break;
    case WIFI_STA_INIT:
      mgos_wifi_dev_sta_disconnect();
      s_roaming = false;
      s_cur_entry = NULL;
      mgos_wifi_sta_empty_queue();
      // See if we can pre-populate the queue with saved entries.
      // We iterate backwards to ensure correct priority of the queue.
      // Note that with the code as it is now, we can get stuck on a lower
      // priority config as long as quick connect entry works.
      // Is this bad? Is it more important to quickly connect to a secondary
      // network or hop back on primary when it becomes available? Not sure.
      // Let's wait and see if users complain about this behavior.
      for (int i = s_num_cfgs - 1; i >= 0; i--) {
        struct mgos_config_wifi_sta *cfg = s_cfgs[i];
        if (!cfg->enable) continue;
        if (mgos_conf_str_empty(cfg->last_bssid) || cfg->last_channel == 0) {
          continue;
        }
        uint8_t bssid[6];
        if (!mgos_wifi_sta_bssid_from_str(cfg->last_bssid, bssid)) {
          continue;
        }
        bool found = true;
        struct wifi_ap_entry *ape =
            mgos_wifi_sta_find_history_entry(bssid, cfg);
        if (ape == NULL) {
          found = false;
          ape = calloc(1, sizeof(*ape));
          if (ape == NULL) break;
          ape->cfg = cfg;
          memcpy(ape->bssid, bssid, sizeof(ape->bssid));
        }
        ape->channel = cfg->last_channel;
        if (found) mgos_wifi_sta_remove_history_entry(ape);
        SLIST_INSERT_HEAD(&s_ap_queue, ape, next);
      }
      if (!SLIST_EMPTY(&s_ap_queue)) {
        mgos_wifi_sta_dump_list(&s_ap_queue, "queue");
        mgos_wifi_sta_dump_list(&s_ap_history, "history");
        s_state = WIFI_STA_CONNECT;
      } else {
        s_state = WIFI_STA_SCAN;
      }
      mgos_wifi_sta_set_timeout(true /* run_now */);
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
        mgos_wifi_sta_set_timeout(true /* run_now */);
      }
      break;
    case WIFI_STA_WAIT_CONNECT:
      if (!timeout) {
        mgos_wifi_sta_set_timeout_n(2000, false /* run_now */);
        break;
      }
      s_state = WIFI_STA_CONNECT;
      mgos_wifi_sta_set_timeout_n(1000, false /* run_now */);
      break;
    case WIFI_STA_CONNECT: {
      struct wifi_ap_entry *ape = SLIST_FIRST(&s_ap_queue);
      if (s_roaming) {
        s_roaming = false;
        /* If we are roaming and have no good candidate, go back. */
        int cur_rssi = mgos_wifi_sta_get_rssi();
        bool ok = false;
        if (ape == NULL || ape->rssi == 0) {
          LOG(LL_INFO, ("No candidate APs"));
        } else if (s_cur_entry != NULL && memcmp(s_cur_entry->bssid, ape->bssid,
                                                 sizeof(ape->bssid)) == 0) {
          LOG(LL_INFO, ("Current AP is best AP"));
        } else if (ape->rssi <= mgos_sys_config_get_wifi_sta_roam_rssi_thr() ||
                   (ape->rssi - MGOS_WIFI_STA_ROAM_RSSI_HYST) < cur_rssi) {
          LOG(LL_INFO, ("Best AP is not much better (RSSI %d vs %d)", ape->rssi,
                        cur_rssi));
        } else {
          ok = true;
        }
        if (!ok) {
          mgos_wifi_sta_empty_queue();
          s_state = WIFI_STA_IP_ACQUIRED;
          mgos_wifi_sta_set_timeout(true /* run_now */);
          break;
        }
        /* We have a better AP candidate, disconnect and try to roam. */
        char bssid_s[20];
        LOG(LL_INFO, ("Trying to switch to %s (RSSI %d -> %d)",
                      mgos_wifi_sta_bssid_to_str(ape->bssid, bssid_s), cur_rssi,
                      ape->rssi));
        mgos_wifi_dev_sta_disconnect();
        /* We need to allow some time for connection to terminate. */
        s_cur_entry = NULL;
        s_state = WIFI_STA_WAIT_CONNECT;
        mgos_wifi_sta_set_timeout_n(1000, false /* run_now */);
        (void) bssid_s;
        break;
      }
      if (ape == NULL) {
        LOG(LL_INFO, ("No candidate APs"));
        s_state = WIFI_STA_SCAN;
        mgos_wifi_sta_set_timeout_n(2000, false /* run_now */);
        break;
      }
      ape->num_attempts++;
      if (ape->num_attempts >= 200) {
        /* Prevent overflow by scaling down the numbers. */
        struct wifi_ap_entry *ape2 = NULL;
        SLIST_FOREACH(ape2, &s_ap_queue, next) {
          ape2->num_attempts /= 2;
        }
        SLIST_FOREACH(ape2, &s_ap_history, next) {
          ape2->num_attempts /= 2;
        }
      }
      struct mgos_config_wifi_sta sta_cfg = *ape->cfg;
      if (!ape->is_wildcard) {
        char bssid_s[20];
        const uint8_t *bssid = &ape->bssid[0];
        mgos_wifi_sta_bssid_to_str(bssid, bssid_s);
        sta_cfg.bssid = bssid_s;
        sta_cfg.channel = ape->channel;
        LOG(LL_INFO,
            ("Trying %s AP %02x:%02x:%02x:%02x:%02x:%02x ch %d RSSI %2d "
             "cfg %d att %d",
             ape->cfg->ssid, bssid[0], bssid[1], bssid[2], bssid[3], bssid[4],
             bssid[5], ape->channel, ape->rssi, get_cfg_index(ape->cfg),
             ape->num_attempts));
      } else {
        sta_cfg.bssid = NULL;
        sta_cfg.channel = 0;
        LOG(LL_INFO, ("Trying %s cfg %d AP (auto) att %d", ape->cfg->ssid,
                      get_cfg_index(ape->cfg), ape->num_attempts));
      }
      ape->last_attempt = mgos_uptime_micros();
      mgos_wifi_dev_sta_setup(&sta_cfg);
      mgos_wifi_dev_sta_connect();
      s_state = WIFI_STA_CONNECTING;
      struct mgos_wifi_dev_event_info dei = {
          .ev = MGOS_WIFI_EV_STA_CONNECTING,
      };
      mgos_wifi_dev_event_cb(&dei);
      mgos_wifi_sta_set_timeout(true /* run_now */);
      break;
    }
    case WIFI_STA_CONNECTING: {
      struct wifi_ap_entry *ape = SLIST_FIRST(&s_ap_queue);
      struct mgos_config_wifi_sta *cfg = ape->cfg;
      if (wifi_ev == MGOS_WIFI_EV_STA_DISCONNECTED || timeout) {
        LOG(LL_INFO, ("Connect failed"));
        // Remove the queue entry that failed.
        SLIST_REMOVE_HEAD(&s_ap_queue, next);
        mgos_wifi_sta_add_history_entry(ape);
        // Stop connection attempts and let things settle before moving on.
        mgos_wifi_dev_sta_disconnect();
        s_cur_entry = NULL;
        // Reset quick connect settings for this config.
        {
          mgos_conf_set_str(&cfg->last_bssid, NULL);
          ape->cfg->last_channel = 0;
          // We do not save config at this point, it will be saved when we
          // eventually connect.
        }
        s_state = WIFI_STA_WAIT_CONNECT;
        mgos_wifi_sta_set_timeout_n(1000, false /* run_now */);
        break;
      }
      if (wifi_ev == MGOS_WIFI_EV_STA_CONNECTED) {
        const struct mgos_wifi_sta_connected_arg *ea = ev_data;
        // Whatever we thought we were connecting to,
        // this is what we ended up with.
        ape->channel = ea->channel;
        memcpy(ape->bssid, ea->bssid, sizeof(s_cur_entry->bssid));
        ape->rssi = ea->rssi;
        s_cur_entry = ape;
        s_state = WIFI_STA_CONNECTED;
      }
      break;
    }
    case WIFI_STA_CONNECTED: {
      if (wifi_ev == MGOS_WIFI_EV_STA_IP_ACQUIRED) {
        struct wifi_ap_entry *ape = (struct wifi_ap_entry *) s_cur_entry;
        struct mgos_config_wifi_sta *cfg = ape->cfg;
        ape->num_attempts = 0;
        mgos_wifi_sta_empty_queue();
        s_state = WIFI_STA_IP_ACQUIRED;
        int8_t cur_rssi = (int8_t) mgos_wifi_sta_get_rssi();
        for (int i = 0; i < (int) ARRAY_SIZE(s_rssi_info.samples); i++) {
          s_rssi_info.samples[i] = cur_rssi;
        }
        // Save the AP that we connected to, for quick reconnect.
        if (ape->channel != 0 && !BSSID_EMPTY(ape->bssid)) {
          char bssid_s[20] = {0};
          mgos_wifi_sta_bssid_to_str(ape->bssid, bssid_s);
          bool changed = (ape->channel != cfg->last_channel ||
                          mgos_conf_str_empty(cfg->last_bssid));
          if (!changed) changed = strcasecmp(cfg->last_bssid, bssid_s);
          if (changed) {
            mgos_conf_set_str(&cfg->last_bssid, bssid_s);
            cfg->last_channel = ape->channel;
            // Early version of this code was using bssid prefixed with '*' and
            // negative channel to store quick connect values.
            // This was a bad idea that broke backward compatibility,
            // we no longer do this and clean up such values when possible.
            if (cfg->channel < 0) cfg->channel = 0;
            if (!mgos_conf_str_empty(cfg->bssid) && cfg->bssid[0] == '*') {
              mgos_conf_set_str(&cfg->bssid, NULL);
            }
            if (is_sys_cfg(cfg)) {
              LOG(LL_INFO,
                  ("Saving AP %s %s ch %d", cfg->ssid, bssid_s, ape->channel));
              mgos_sys_config_save(&mgos_sys_config, false /* try_once */,
                                   NULL /* msg */);
            }
          }
        }
        mgos_wifi_sta_dump_list(&s_ap_history, "history");
        break;
      }
      int cur_rssi = mgos_wifi_sta_get_rssi();
      if (timeout || wifi_ev == MGOS_WIFI_EV_STA_DISCONNECTED ||
          cur_rssi == 0) {
        s_state = WIFI_STA_INIT;
        mgos_wifi_sta_set_timeout_n(1000, false /* run_now */);
        break;
      }
      break;
    }
    case WIFI_STA_IP_ACQUIRED: {
      int cur_rssi = mgos_wifi_sta_get_rssi();
      s_cur_entry->rssi = cur_rssi;
      if (wifi_ev == MGOS_WIFI_EV_STA_DISCONNECTED || cur_rssi == 0) {
        s_state = WIFI_STA_INIT;
        s_cur_entry = NULL;
        mgos_wifi_sta_set_timeout_n(1000, false /* run_now */);
        break;
      }
      int roam_rssi_thr = mgos_sys_config_get_wifi_sta_roam_rssi_thr();
      int roam_intvl = mgos_sys_config_get_wifi_sta_roam_interval();
      if (roam_rssi_thr < 0 && roam_intvl > 0) {
        s_rssi_info.val <<= 8;
        s_rssi_info.samples[0] = cur_rssi;
        int sum = 0;
        for (int i = 0; i < (int) ARRAY_SIZE(s_rssi_info.samples); i++) {
          sum += s_rssi_info.samples[i];
        }
        int avg_rssi = sum / (int) ARRAY_SIZE(s_rssi_info.samples);
        if (avg_rssi < roam_rssi_thr &&
            mgos_uptime_micros() - s_last_roam_attempt > roam_intvl * 1000000) {
          LOG(LL_INFO, ("Avg RSSI %d, will scan for a better AP", avg_rssi));
          s_roaming = true;
          s_state = WIFI_STA_SCAN;
          s_last_roam_attempt = mgos_uptime_micros();
          mgos_wifi_sta_set_timeout(true /* run_now */);
        }
      }
    }
    case WIFI_STA_SHUTDOWN:
      break;
  }
}

void mgos_wifi_sta_ev_handler(int ev, void *evd, void *cb_arg) {
  wifi_lock();
  mgos_wifi_sta_run(ev, evd, false /* timeout */);
  wifi_unlock();
  (void) cb_arg;
}

bool mgos_wifi_connect(void) {
  int ret = true;
  wifi_lock();
  if (s_num_cfgs > 0) {
    switch (s_state) {
      case WIFI_STA_SHUTDOWN:
        ret = false;
        break;
      case WIFI_STA_IDLE:
        s_state = WIFI_STA_INIT;
        mgos_wifi_sta_set_timeout(true /* run_now */);
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
  } else {
    ret = false;
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
  char *err_msg = NULL;
  if (!cfg->enable) return false;
  if (!mgos_wifi_validate_sta_cfg(cfg, &err_msg)) {
    LOG(LL_ERROR, ("WiFi STA: %s", err_msg));
    free(err_msg);
    return false;
  }
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
  mgos_wifi_disconnect();
  s_cur_entry = NULL;
  while (!SLIST_EMPTY(&s_ap_queue)) {
    struct wifi_ap_entry *ape = SLIST_FIRST(&s_ap_queue);
    SLIST_REMOVE_HEAD(&s_ap_queue, next);
    mgos_wifi_sta_free_ap_entry(ape);
  }
  while (!SLIST_EMPTY(&s_ap_history)) {
    struct wifi_ap_entry *ape = SLIST_FIRST(&s_ap_history);
    SLIST_REMOVE_HEAD(&s_ap_history, next);
    mgos_wifi_sta_free_ap_entry(ape);
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

const struct mgos_config_wifi_sta *mgos_wifi_get_connected_sta_cfg(void) {
  if (s_cur_entry == NULL) return NULL;
  return s_cur_entry->cfg;
}

void mgos_wifi_sta_init(void) {
  mgos_event_add_handler(MGOS_EVENT_REBOOT_AFTER,
                         mgos_wifi_reboot_after_ev_handler, NULL);
}
