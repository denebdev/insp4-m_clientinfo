# m_clientinfo

Advanced WebIRC intelligence and client metadata module for InspIRCd4.

## Features

- IRCop `/CLIENTINFO <nick>` command
- Browser and OS detection
- Device detection
- Headless browser detection
- Bot detection
- WebIRC metadata support
- Client risk scoring
- IRCop SNOTICE alerts
- Client statistics
- Connection logging
- Additional metadata fields
- IP-based datacenter detection
- IP-based proxy/VPN detection
- Configurable detection toggles
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
- IP-based proxy/VPN CIDR matches
- IP-based datacenter/cloud CIDR matches

## Example CLIENTINFO

```irc
/CLIENTINFO Deneb
999 Deneb :CLIENTINFO Nick: Deneb Browser: Chrome
999 Deneb :CLIENTINFO Nick: Deneb OS: Windows 10/11
999 Deneb :CLIENTINFO Nick: Deneb Device: Desktop
999 Deneb :CLIENTINFO Nick: Deneb IP: 198.51.100.23
999 Deneb :CLIENTINFO Nick: Deneb Host: user.example.net
999 Deneb :CLIENTINFO Nick: Deneb RiskScore: 0
999 Deneb :CLIENTINFO Nick: Deneb RiskLevel: LOW
999 Deneb :CLIENTINFO Nick: Deneb Stats: total=1 bots=0 proxies=0 datacenters=0 malicious=0
```

The command returns raw `999` lines with the target nick in every response, so
mIRC scripts can parse and act on the nick. Normal WHOIS output is not changed.

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
<clientinfo
 clientinfonumeric="999"
 operonly="yes"
 showbrowser="yes"
 showos="yes"
 showdevice="yes"
 showip="yes"
 showhost="yes"
 showsnotice="yes"
 snoticebots="yes"
 detectbots="yes"
 detectheadless="yes"
 detectproxy="yes"
 detectdatacenter="yes"
 riskscoring="yes"
 logconnections="no"
 logfile="logs/clientinfo.log"
 proxyips="203.0.113.0/24,198.51.100.44"
 datacenterips="192.0.2.0/24">
```

The `clientinfonumeric` setting controls the raw numeric used for
`/CLIENTINFO` response lines. If unset, it defaults to `999`.

The module reads client metadata from `METADATA`. The supported keys are
`useragent`, `platform`, `language`, `timezone`, and `screen`. The
`/CLIENTINFO <nick>` command is only available to IRC operators by default.

`proxyips` and `datacenterips` accept comma-separated IPv4 addresses or CIDR
ranges. These lists are local and deterministic; no external network lookup is
required at runtime.

## License

GPLv2
