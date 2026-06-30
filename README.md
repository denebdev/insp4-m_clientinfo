# m_clientinfo

Advanced WebIRC intelligence and client metadata module for InspIRCd4.

## Features

- IRCop WHOIS client information
- Browser and OS detection
- Device detection
- Headless browser detection
- Bot detection
- WebIRC metadata support
- Client risk scoring
- IRCop SNOTICE alerts
- Client statistics
- Logging support
- Generic metadata support
- InspIRCd4 native module

## Planned Detection

- HeadlessChrome
- Selenium
- Puppeteer
- Playwright
- curl
- wget
- python requests
- suspicious User-Agents
- datacenter detection
- proxy detection

## Example WHOIS

320 Browser: Chrome 136
320 OS: Windows 11
320 Device: Desktop
320 Bot: No
320 Risk: LOW

## Example SNOTICE

*** CLIENTINFO: Deneb using Chrome on Windows 11
*** CLIENTINFO ALERT: Possible headless browser detected

## Status

Early development.

## Build

This module must be built against an InspIRCd 4 source tree.

Requirements:

- InspIRCd 4 source tree
- CMake
- C++ compiler supported by InspIRCd

Build:

```sh
./build-inspircd.sh /path/to/inspircd
```

The script copies the module into `modules/clientinfo` inside the InspIRCd
source tree, configures CMake if needed, and builds the `m_clientinfo` module
target.

Install the resulting module into your InspIRCd module directory:

```sh
install -m 0755 /path/to/inspircd/build/modules/m_clientinfo.so /path/to/inspircd/modules/
```

Load it from your InspIRCd config:

```xml
<module name="clientinfo">
```

## License

GPLv2
