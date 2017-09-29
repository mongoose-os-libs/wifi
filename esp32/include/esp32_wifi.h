/*
 * Copyright (c) 2014-2017 Cesanta Software Limited
 * All rights reserved
 */

#ifndef CS_MOS_LIBS_WIFI_ESP32_SRC_ESP32_WIFI_H_
#define CS_MOS_LIBS_WIFI_ESP32_SRC_ESP32_WIFI_H_

#include "esp_event.h"

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t esp32_wifi_ev(system_event_t *event);

#ifdef __cplusplus
}
#endif

#endif /* CS_MOS_LIBS_WIFI_ESP32_SRC_ESP32_WIFI_H_ */
