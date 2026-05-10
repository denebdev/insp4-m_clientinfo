#pragma once

#include "inspircd.h"

struct ClientInfo
{
	std::string browser;
	std::string os;
	std::string device;
	std::string engine;
	std::string useragent;

	bool mobile = false;
	bool bot = false;
	bool headless = false;
	bool proxy = false;
	bool secure = false;

	int riskscore = 0;

	std::string riskreason;
};
