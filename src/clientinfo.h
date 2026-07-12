#pragma once

#include "inspircd.h"

struct ClientInfo
{
	std::string browser;
	std::string os;
	std::string device;
	std::string engine;
	std::string useragent;
	std::string riskreason;
	std::string platform;
	std::string language;
	std::string timezone;
	std::string screen;
	std::string sourceip;

	int riskscore = 0;

	bool bot = false;
	bool proxy = false;
	bool datacenter = false;
	bool mobile = false;
	bool headless = false;
	bool malicious = false;
};
