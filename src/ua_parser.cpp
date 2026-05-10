#include "../include/clientinfo.h"

void DetectClientInfo(const std::string& ua, ClientInfo& ci)
{
	/* Browser detection */

	if (ua.find("Firefox") != std::string::npos)
		ci.browser = "Firefox";

	else if (ua.find("Edg") != std::string::npos)
		ci.browser = "Edge";

	else if (ua.find("Chrome") != std::string::npos)
		ci.browser = "Chrome";

	else if (ua.find("Safari") != std::string::npos)
		ci.browser = "Safari";

	else
		ci.browser = "Unknown";

	/* OS detection */

	if (ua.find("Windows NT 10") != std::string::npos)
		ci.os = "Windows 10/11";

	else if (ua.find("Android") != std::string::npos)
		ci.os = "Android";

	else if (ua.find("iPhone") != std::string::npos)
		ci.os = "iPhone";

	else if (ua.find("Linux") != std::string::npos)
		ci.os = "Linux";

	else if (ua.find("Mac OS") != std::string::npos)
		ci.os = "macOS";

	else
		ci.os = "Unknown";

	/* Device */

	if (ua.find("Mobile") != std::string::npos)
	{
		ci.mobile = true;
		ci.device = "Mobile";
	}
	else
	{
		ci.device = "Desktop";
	}

	/* Engine */

	if (ua.find("AppleWebKit") != std::string::npos)
		ci.engine = "WebKit/Blink";

	/* Bot detection */

	if (ua.find("Headless") != std::string::npos)
	{
		ci.bot = true;
		ci.headless = true;
		ci.riskscore += 40;
		ci.riskreason += "Headless ";
	}

	if (ua.find("selenium") != std::string::npos)
	{
		ci.bot = true;
		ci.riskscore += 50;
		ci.riskreason += "Selenium ";
	}

	if (ua.find("puppeteer") != std::string::npos)
	{
		ci.bot = true;
		ci.riskscore += 50;
		ci.riskreason += "Puppeteer ";
	}

	if (ua.find("playwright") != std::string::npos)
	{
		ci.bot = true;
		ci.riskscore += 50;
		ci.riskreason += "Playwright ";
	}

	if (ua.find("PhantomJS") != std::string::npos)
	{
		ci.bot = true;
		ci.riskscore += 60;
		ci.riskreason += "PhantomJS ";
	}

	if (ua.find("Scrapy") != std::string::npos)
	{
		ci.bot = true;
		ci.riskscore += 80;
		ci.riskreason += "Scrapy ";
	}

	if (ua.find("aiohttp") != std::string::npos)
	{
		ci.bot = true;
		ci.riskscore += 70;
		ci.riskreason += "aiohttp ";
	}

	if (ua.find("libwww") != std::string::npos)
	{
		ci.bot = true;
		ci.riskscore += 80;
		ci.riskreason += "libwww ";
	}

	if (ua.find("curl") != std::string::npos)
	{
		ci.bot = true;
		ci.riskscore += 90;
		ci.riskreason += "curl ";
	}

	if (ua.find("wget") != std::string::npos)
	{
		ci.bot = true;
		ci.riskscore += 90;
		ci.riskreason += "wget ";
	}

	if (ua.find("python-requests") != std::string::npos)
	{
		ci.bot = true;
		ci.riskscore += 80;
		ci.riskreason += "python ";
	}

	if (ua.find("Java") != std::string::npos)
	{
		ci.bot = true;
		ci.riskscore += 40;
		ci.riskreason += "Java ";
	}

	if (ua.empty())
	{
		ci.riskscore += 20;
		ci.riskreason += "empty-ua ";
	}
}
