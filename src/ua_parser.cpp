#include "clientinfo.h"

#include <algorithm>
#include <cctype>

void DetectClientInfo(const std::string& ua, ClientInfo& ci)
{
	ci.useragent = ua;

	std::string lowerua = ua;

	std::transform(
		lowerua.begin(),
		lowerua.end(),
		lowerua.begin(),
		[](unsigned char c)
		{
			return std::tolower(c);
		}
	);

	/* Browser detection */

	if (lowerua.find("firefox") != std::string::npos)
		ci.browser = "Firefox";

	else if (lowerua.find("edg") != std::string::npos)
		ci.browser = "Edge";

	else if (lowerua.find("chrome") != std::string::npos)
		ci.browser = "Chrome";

	else if (lowerua.find("safari") != std::string::npos)
		ci.browser = "Safari";

	else
	{
		ci.browser = "Unknown";
		ci.riskscore += 15;
		ci.riskreason += "UnknownBrowser ";
	}

	/* OS detection */

	if (lowerua.find("windows nt 10") != std::string::npos)
		ci.os = "Windows 10/11";

	else if (lowerua.find("android") != std::string::npos)
		ci.os = "Android";

	else if (lowerua.find("iphone") != std::string::npos)
		ci.os = "iPhone";

	else if (lowerua.find("linux") != std::string::npos)
		ci.os = "Linux";

	else if (lowerua.find("mac os") != std::string::npos)
		ci.os = "macOS";

	else
	{
		ci.os = "Unknown";
		ci.riskscore += 10;
		ci.riskreason += "UnknownOS ";
	}

	/* Device */

	if (lowerua.find("mobile") != std::string::npos)
	{
		ci.mobile = true;
		ci.device = "Mobile";
	}
	else
	{
		ci.device = "Desktop";
	}

	/* Engine */

	if (lowerua.find("applewebkit") != std::string::npos)
		ci.engine = "WebKit/Blink";

	/* Bot detection */

	if (lowerua.find("headless") != std::string::npos)
	{
		ci.bot = true;
		ci.headless = true;
		ci.riskscore += 40;
		ci.riskreason += "Headless ";
	}

	if (lowerua.find("selenium") != std::string::npos)
	{
		ci.bot = true;
		ci.riskscore += 50;
		ci.riskreason += "Selenium ";
	}

	if (lowerua.find("puppeteer") != std::string::npos)
	{
		ci.bot = true;
		ci.riskscore += 50;
		ci.riskreason += "Puppeteer ";
	}

	if (lowerua.find("playwright") != std::string::npos)
	{
		ci.bot = true;
		ci.riskscore += 50;
		ci.riskreason += "Playwright ";
	}

	if (lowerua.find("phantomjs") != std::string::npos)
	{
		ci.bot = true;
		ci.riskscore += 60;
		ci.riskreason += "PhantomJS ";
	}

	if (lowerua.find("scrapy") != std::string::npos)
	{
		ci.bot = true;
		ci.riskscore += 80;
		ci.riskreason += "Scrapy ";
	}

	if (lowerua.find("aiohttp") != std::string::npos)
	{
		ci.bot = true;
		ci.riskscore += 70;
		ci.riskreason += "aiohttp ";
	}

	if (lowerua.find("libwww") != std::string::npos)
	{
		ci.bot = true;
		ci.riskscore += 80;
		ci.riskreason += "libwww ";
	}

	if (lowerua.find("curl") != std::string::npos)
	{
		ci.bot = true;
		ci.riskscore += 90;
		ci.riskreason += "curl ";
	}

	if (lowerua.find("wget") != std::string::npos)
	{
		ci.bot = true;
		ci.riskscore += 90;
		ci.riskreason += "wget ";
	}

	if (lowerua.find("python-requests") != std::string::npos)
	{
		ci.bot = true;
		ci.riskscore += 80;
		ci.riskreason += "python ";
	}

	if (lowerua.find("java") != std::string::npos)
	{
		ci.bot = true;
		ci.riskscore += 40;
		ci.riskreason += "Java ";
	}

	if (lowerua.find("electron") != std::string::npos)
	{
		ci.bot = true;
		ci.riskscore += 35;
		ci.riskreason += "Electron ";
	}

	if (lowerua.find("node.js") != std::string::npos)
	{
		ci.bot = true;
		ci.riskscore += 40;
		ci.riskreason += "NodeJS ";
	}

	if (lowerua.find("axios") != std::string::npos)
	{
		ci.bot = true;
		ci.riskscore += 60;
		ci.riskreason += "axios ";
	}

	if (lowerua.find("undici") != std::string::npos)
	{
		ci.bot = true;
		ci.riskscore += 60;
		ci.riskreason += "undici ";
	}

	if (lowerua.find("discordbot") != std::string::npos)
	{
		ci.bot = true;
		ci.riskscore += 70;
		ci.riskreason += "DiscordBot ";
	}

	if (lowerua.find("tor browser") != std::string::npos)
	{
		ci.proxy = true;
		ci.riskscore += 40;
		ci.riskreason += "TorBrowser ";
	}

	if (lowerua.find("torsocks") != std::string::npos)
	{
		ci.proxy = true;
		ci.riskscore += 50;
		ci.riskreason += "TorSocks ";
	}

	if (lowerua.find("tor-exit") != std::string::npos)
	{
		ci.proxy = true;
		ci.riskscore += 60;
		ci.riskreason += "TorExit ";
	}

	if (lowerua.find("gptbot") != std::string::npos)
	{
		ci.bot = true;
		ci.riskscore += 50;
		ci.riskreason += "GPTBot ";
	}

	if (lowerua.find("claudebot") != std::string::npos)
	{
		ci.bot = true;
		ci.riskscore += 50;
		ci.riskreason += "ClaudeBot ";
	}

	if (lowerua.find("ccbot") != std::string::npos)
	{
		ci.bot = true;
		ci.riskscore += 50;
		ci.riskreason += "CCBot ";
	}

	if (lowerua.find("bytespider") != std::string::npos)
	{
		ci.bot = true;
		ci.riskscore += 60;
		ci.riskreason += "ByteSpider ";
	}

	if (lowerua.find("amazonbot") != std::string::npos)
	{
		ci.bot = true;
		ci.riskscore += 50;
		ci.riskreason += "AmazonBot ";
	}

	if (lowerua.empty() ||
		lowerua == "-" ||
		lowerua == "." ||
		lowerua == "test" ||
		lowerua == "bot")
	{
		ci.bot = true;
		ci.riskscore += 40;
		ci.riskreason += "EmptyUA ";
	}

	if (lowerua.find("ovh") != std::string::npos)
	{
		ci.proxy = true;
		ci.riskscore += 20;
		ci.riskreason += "OVH ";
	}

	if (lowerua.find("digitalocean") != std::string::npos)
	{
		ci.proxy = true;
		ci.riskscore += 20;
		ci.riskreason += "DigitalOcean ";
	}

	if (lowerua.find("amazon") != std::string::npos)
	{
		ci.proxy = true;
		ci.riskscore += 20;
		ci.riskreason += "AWS ";
	}

	if (lowerua.find("azure") != std::string::npos)
	{
		ci.proxy = true;
		ci.riskscore += 20;
		ci.riskreason += "Azure ";
	}

	if (lowerua.find("googlecloud") != std::string::npos)
	{
		ci.proxy = true;
		ci.riskscore += 20;
		ci.riskreason += "GoogleCloud ";
	}

	if (lowerua.find("protonvpn") != std::string::npos)
	{
		ci.proxy = true;
		ci.riskscore += 35;
		ci.riskreason += "ProtonVPN ";
	}

	if (lowerua.find("mullvad") != std::string::npos)
	{
		ci.proxy = true;
		ci.riskscore += 35;
		ci.riskreason += "Mullvad ";
	}

	if (lowerua.find("nordvpn") != std::string::npos)
	{
		ci.proxy = true;
		ci.riskscore += 35;
		ci.riskreason += "NordVPN ";
	}

	if (lowerua.find("openvpn") != std::string::npos)
	{
		ci.proxy = true;
		ci.riskscore += 25;
		ci.riskreason += "OpenVPN ";
	}

	if (lowerua.find("wireguard") != std::string::npos)
	{
		ci.proxy = true;
		ci.riskscore += 25;
		ci.riskreason += "WireGuard ";
	}

	int browsercount = 0;

	if (lowerua.find("chrome") != std::string::npos)
		browsercount++;

	if (lowerua.find("firefox") != std::string::npos)
		browsercount++;

	if (lowerua.find("safari") != std::string::npos)
		browsercount++;

	if (lowerua.find("edge") != std::string::npos)
		browsercount++;

	if (browsercount >= 3)
	{
		ci.riskscore += 30;
		ci.riskreason += "FakeUA ";
	}

	if (lowerua.length() < 20)
	{
		ci.riskscore += 25;
		ci.riskreason += "ShortUA ";
	}

	if (lowerua.find("mozilla") != std::string::npos &&
		lowerua.find("gecko") == std::string::npos &&
		lowerua.find("webkit") == std::string::npos)
	{
		ci.riskscore += 35;
		ci.riskreason += "FakeMozilla ";
	}

	if (ci.riskscore >= 120)
	{
		ci.malicious = true;
		ci.riskreason += "Malicious ";
	}
}
