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
- InspIRCd4 native module

## Implemented Detection

- HeadlessChrome
- Selenium
- Puppeteer
- Playwright
- curl
- wget
- python requests
- suspicious User-Agents
- Tor/VPN/proxy User-Agent hints
- datacenter/cloud User-Agent hints

## Planned Detection

- Client statistics
- Connection logging
- Additional metadata fields
- IP-based datacenter detection
- IP-based proxy/VPN detection
- Configurable detection toggles

## Example WHOIS

999 CLIENTINFO Browser: Chrome
999 CLIENTINFO OS: Windows 10/11
999 CLIENTINFO Device: Desktop
999 CLIENTINFO RiskScore: 0
999 CLIENTINFO RiskLevel: LOW

## Example SNOTICE

*** CLIENTINFO: Deneb [198.51.100.23] using Chrome on Windows 10/11
*** CLIENTINFO ALERT: Possible bot detected from Deneb [198.51.100.23]
*** CLIENTINFO CRITICAL: High risk client detected from Deneb [198.51.100.23]

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
<clientinfo whoisnumeric="999">
```

The `whoisnumeric` setting controls the raw numeric used for CLIENTINFO WHOIS
lines. If unset, it defaults to `999`.

The module currently reads User-Agent data from `METADATA` with the
`useragent` key. WHOIS client information is only shown to IRC operators.

## License

GPLv2
