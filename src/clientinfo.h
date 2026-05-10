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

	int riskscore = 0;

	bool bot = false;
	bool proxy = false;
	bool mobile = false;
	bool headless = false;
	bool malicious = false;
};
