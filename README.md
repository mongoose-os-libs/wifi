# WiFi support

This library provides common WiFi API.

## Configuration

A library adds a `wifi` configuration entry with two sub-entries: `wifi.ap`
which contains configuration settings for the Access Point mode, and
`wifi.sta` for the Station mode.

```javascript
"wifi": {
  "sta": {
    "enable": true,         // Enable Station mode
    "ssid": "",             // WiFi network name
    "pass": "",             // Password
    "user": "",             // Username for WPA-PEAP mode
    "anon_identity": "",    // Anonymous identity for WPA mode
    "cert": "",             // Client certificate for WPA-TTLS mode
    "key": "",              // Client key for WPA-TTLS mode
    "ca_cert": "",          // CA certificate for WPA-enterprise mode
    "ip": "",               // Static IP Address
    "netmask": "",          // Static Netmask
    "gw": "",               // Static Default Gateway
    "nameserver": "",       // DNS Server
    "dhcp_hostname": ""     // Host name to include in DHCP requests
  },
  "ap": {
    "enable": true,               // Enable Access Point mode
    "ssid": "Mongoose_??????",    // SSID to use. ?? symbols are substituted by MAC address
    "pass": "Mongoose",           // Password
    "hidden": false,              // Hide WiFi network
    "channel": 6,                 // WiFi channel
    "max_connections": 10,        // Maximum number of connections
    "ip": "192.168.4.1",          // Static IP Address
    "netmask": "255.255.255.0",   // Static Netmask
    "gw": "192.168.4.1",          // Static Default Gateway
    "dhcp_start": "192.168.4.2",  // DHCP Start Address
    "dhcp_end": "192.168.4.100",  // DHCP End Address
    "trigger_on_gpio": -1         // Trigger AP on low GPIO
  },
}
```
