//
// Wifi global object is created during C initialization.
//

//
// `Wifi.scan(cb)`; `cb` is a function taking a single argument, `results` is
// either `undefined` in case of error, or an array of object conataining:
// {
//   "ssid": "NetworkName",
//   "bssid": "12:34:56:78:90:ab",
//   "authMode": 2, // Auth mode, one of AUTH constants.
//   "channel": 11,
//   "rssi": -70
// }
//
// Wifi.scan = function(cb) { ... } /* defined in C */

// Must be kept in sync with enum mgos_wifi_auth_mode
Wifi.AUTH_MODE_OPEN = 0;
Wifi.AUTH_MODE_WEP = 1;
Wifi.AUTH_MODE_WPA_PSK = 2;
Wifi.AUTH_MODE_WPA2_PSK = 3;
Wifi.AUTH_MODE_WPA_WPA2_PSK = 4;
Wifi.AUTH_MODE_WPA2_ENTERPRISE = 5;
