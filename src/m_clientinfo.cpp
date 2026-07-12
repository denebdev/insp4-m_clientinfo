/*
 * m_clientinfo.cpp
 *
 * Advanced WebIRC intelligence and client metadata module
 * for InspIRCd4.
 *
 * GPLv2
 */

#include "inspircd.h"
#include "extension.h"
#include "modules/whois.h"
#include "clientinfo.h"

#include <cstdint>
#include <fstream>
#include <sstream>
#include <vector>

void DetectClientInfo(const std::string& ua, ClientInfo& ci);

static constexpr unsigned int DEFAULT_WHOIS_NUMERIC = 999;
static constexpr size_t MAX_METADATA_LENGTH = 512;

static bool ParseIPv4(const std::string& address, uint32_t& out)
{
	unsigned int a = 0;
	unsigned int b = 0;
	unsigned int c = 0;
	unsigned int d = 0;
	char dot1 = 0;
	char dot2 = 0;
	char dot3 = 0;
	std::istringstream parser(address);

	if (!(parser >> a >> dot1 >> b >> dot2 >> c >> dot3 >> d))
		return false;

	if (dot1 != '.' || dot2 != '.' || dot3 != '.')
		return false;

	if (a > 255 || b > 255 || c > 255 || d > 255)
		return false;

	out = (a << 24) | (b << 16) | (c << 8) | d;
	return true;
}

static bool MatchCIDR(const std::string& address, const std::string& cidr)
{
	if (cidr.empty())
		return false;

	std::string range = cidr;
	unsigned int bits = 32;
	const std::string::size_type slash = range.find('/');

	if (slash != std::string::npos)
	{
		std::istringstream bitparser(range.substr(slash + 1));

		if (!(bitparser >> bits))
			return false;

		range.erase(slash);
	}

	if (bits > 32)
		return false;

	uint32_t addressnum = 0;
	uint32_t rangenum = 0;

	if (!ParseIPv4(address, addressnum) || !ParseIPv4(range, rangenum))
		return false;

	const uint32_t mask = (bits == 0) ? 0 : (0xFFFFFFFFu << (32 - bits));
	return (addressnum & mask) == (rangenum & mask);
}

static std::vector<std::string> SplitList(const std::string& list)
{
	std::vector<std::string> items;
	std::string item;
	std::istringstream stream(list);

	while (std::getline(stream, item, ','))
	{
		const std::string::size_type first = item.find_first_not_of(" \t\r\n");

		if (first == std::string::npos)
			continue;

		const std::string::size_type last = item.find_last_not_of(" \t\r\n");
		items.push_back(item.substr(first, last - first + 1));
	}

	return items;
}

static bool MatchAnyCIDR(const std::string& address, const std::vector<std::string>& ranges)
{
	for (const auto& range : ranges)
	{
		if (MatchCIDR(address, range))
			return true;
	}

	return false;
}

class ModuleClientInfo : public Module
	, public Whois::EventListener
{
 private:

	class ClientInfoExt
		: public SimpleExtItem<ClientInfo>
	{
	 public:

		ClientInfoExt(const WeakModulePtr& parent)
			: SimpleExtItem<ClientInfo>(parent, "clientinfo", ExtensionType::USER)
		{
		}
	};

	ClientInfoExt ext;
	unsigned int whoisnumeric = DEFAULT_WHOIS_NUMERIC;
	std::vector<std::string> proxyips;
	std::vector<std::string> datacenterips;
	std::string logfile;
	unsigned long totalchecks = 0;
	unsigned long botchecks = 0;
	unsigned long proxychecks = 0;
	unsigned long datacenterchecks = 0;
	unsigned long maliciouschecks = 0;
	bool operonly = true;
	bool showbrowser = true;
	bool showos = true;
	bool showdevice = true;
	bool showip = true;
	bool showhost = true;
	bool showsnotice = true;
	bool snoticebots = true;
	bool detectbots = true;
	bool detectheadless = true;
	bool detectproxy = true;
	bool detectdatacenter = true;
	bool riskscoring = true;
	bool logconnections = false;

 public:

	ModuleClientInfo()
		: Module(VF_VENDOR, "Advanced WebIRC intelligence and client metadata module.")
		, Whois::EventListener(weak_from_this())
		, ext(weak_from_this())
	{
	}

	void ReadConfig(ConfigStatus& status) override
	{
		const auto& tag = ServerInstance->Config->ConfValue("clientinfo");
		whoisnumeric = tag->getNum<unsigned int>("whoisnumeric", DEFAULT_WHOIS_NUMERIC, 1, 999);
		operonly = tag->getBool("operonly", true);
		showbrowser = tag->getBool("showbrowser", true);
		showos = tag->getBool("showos", true);
		showdevice = tag->getBool("showdevice", true);
		showip = tag->getBool("showip", true);
		showhost = tag->getBool("showhost", true);
		showsnotice = tag->getBool("showsnotice", true);
		snoticebots = tag->getBool("snoticebots", true);
		detectbots = tag->getBool("detectbots", true);
		detectheadless = tag->getBool("detectheadless", true);
		detectproxy = tag->getBool("detectproxy", true);
		detectdatacenter = tag->getBool("detectdatacenter", true);
		riskscoring = tag->getBool("riskscoring", true);
		logconnections = tag->getBool("logconnections", false);
		logfile = tag->getString("logfile");
		proxyips = SplitList(tag->getString("proxyips"));
		datacenterips = SplitList(tag->getString("datacenterips"));
	}

	void LogClientInfo(LocalUser* user, const ClientInfo& ci)
	{
		if (!logconnections || logfile.empty())
			return;

		std::ofstream log(logfile, std::ios::app);

		if (!log.is_open())
			return;

		log << "CLIENTINFO nick=" << user->nick
			<< " ip=" << user->GetAddress()
			<< " browser=" << ci.browser
			<< " os=" << ci.os
			<< " device=" << ci.device
			<< " bot=" << (ci.bot ? "yes" : "no")
			<< " proxy=" << (ci.proxy ? "yes" : "no")
			<< " datacenter=" << (ci.datacenter ? "yes" : "no")
			<< " malicious=" << (ci.malicious ? "yes" : "no")
			<< " riskscore=" << ci.riskscore
			<< " reason=\"" << ci.riskreason << "\""
			<< std::endl;
	}

	void ApplyConfigToggles(ClientInfo& ci)
	{
		if (!detectheadless)
			ci.headless = false;

		if (!detectbots)
		{
			ci.bot = false;
			ci.headless = false;
		}

		if (!detectproxy)
			ci.proxy = false;

		if (!detectdatacenter)
			ci.datacenter = false;

		if (!riskscoring)
		{
			ci.riskscore = 0;
			ci.riskreason.clear();
			ci.malicious = false;
		}
	}

	void ApplyIPDetection(LocalUser* user, ClientInfo& ci)
	{
		ci.sourceip = user->GetAddress();

		if (detectproxy && MatchAnyCIDR(ci.sourceip, proxyips))
		{
			ci.proxy = true;

			if (riskscoring)
			{
				ci.riskscore += 35;
				ci.riskreason += "IPProxy ";
			}
		}

		if (detectdatacenter && MatchAnyCIDR(ci.sourceip, datacenterips))
		{
			ci.datacenter = true;

			if (riskscoring)
			{
				ci.riskscore += 25;
				ci.riskreason += "IPDatacenter ";
			}
		}

		if (riskscoring && ci.riskscore >= 120)
		{
			ci.malicious = true;

			if (ci.riskreason.find("Malicious ") == std::string::npos)
				ci.riskreason += "Malicious ";
		}
	}

	void UpdateStats(const ClientInfo& ci)
	{
		++totalchecks;

		if (ci.bot)
			++botchecks;

		if (ci.proxy)
			++proxychecks;

		if (ci.datacenter)
			++datacenterchecks;

		if (ci.malicious)
			++maliciouschecks;
	}

	void SetMetadataField(ClientInfo& ci, const std::string& key, const std::string& value)
	{
		if (key == "platform")
			ci.platform = value;

		else if (key == "language")
			ci.language = value;

		else if (key == "timezone")
			ci.timezone = value;

		else if (key == "screen")
			ci.screen = value;
	}

	ModResult OnPreCommand(std::string& command,
		CommandBase::Params& parameters,
		LocalUser* user,
		bool validated) override
	{
		(void)validated;

		if (command != "METADATA")
			return MOD_RES_PASSTHRU;

		if (parameters.size() < 3)
			return MOD_RES_PASSTHRU;

		const std::string& metakey = parameters[1];

		if (metakey != "useragent" &&
			metakey != "platform" &&
			metakey != "language" &&
			metakey != "timezone" &&
			metakey != "screen")
			return MOD_RES_PASSTHRU;

		if (parameters[2].length() > MAX_METADATA_LENGTH)
		{
			if (showsnotice)
			{
				ServerInstance->SNO.WriteGlobalSno(
					'a',
					"CLIENTINFO ALERT: Oversized metadata from " +
					user->nick +
					" [" + user->GetAddress() + "]"
				);
			}

			return MOD_RES_DENY;
		}

		ClientInfo ci;
		ClientInfo* existing = ext.Get(user);

		if (existing)
			ci = *existing;

		if (metakey == "useragent")
		{
			const std::string platform = ci.platform;
			const std::string language = ci.language;
			const std::string timezone = ci.timezone;
			const std::string screen = ci.screen;

			DetectClientInfo(parameters[2], ci);

			ci.platform = platform;
			ci.language = language;
			ci.timezone = timezone;
			ci.screen = screen;
			ApplyIPDetection(user, ci);
			ApplyConfigToggles(ci);
			UpdateStats(ci);
			LogClientInfo(user, ci);

			if (showsnotice)
			{
				ServerInstance->SNO.WriteGlobalSno(
					'a',
					"CLIENTINFO: " + user->nick +
					" [" + user->GetAddress() + "] " +
					"using " + ci.browser +
					" on " + ci.os
				);
			}

			if (showsnotice && snoticebots && ci.bot)
			{
				ServerInstance->SNO.WriteGlobalSno(
					'a',
					"CLIENTINFO ALERT: Possible bot detected from " +
					user->nick +
					" [" + user->GetAddress() + "]"
				);
			}

			if (showsnotice && ci.riskscore >= 80)
			{
				ServerInstance->SNO.WriteGlobalSno(
					'a',
					"CLIENTINFO CRITICAL: High risk client detected from " +
					user->nick +
					" [" + user->GetAddress() + "]"
				);
			}

			if (showsnotice && ci.malicious)
			{
				ServerInstance->SNO.WriteGlobalSno(
					'a',
					"CLIENTINFO MALICIOUS: Dangerous client detected from " +
					user->nick +
					" [" + user->GetAddress() + "]"
				);
			}
		}
		else
		{
			SetMetadataField(ci, metakey, parameters[2]);
		}

		ext.Set(user, ci, false);

		return MOD_RES_PASSTHRU;
	}

	void OnWhois(Whois::Context& ctx) override
	{
		LocalUser* source = ctx.GetSource();
		User* target = ctx.GetTarget();

		if (operonly && !source->IsOper())
			return;

		ClientInfo* ci = ext.Get(target);

		if (!ci)
			return;

		const std::string nickprefix = "CLIENTINFO Nick: " + target->nick + " ";

		auto SendClientInfo = [&](const std::string& line)
		{
			ctx.SendLine(whoisnumeric, nickprefix + line);
		};

		if (showbrowser)
		{
			SendClientInfo("Browser: " + ci->browser);
		}

		if (showos)
		{
			SendClientInfo("OS: " + ci->os);
		}

		if (showdevice)
		{
			SendClientInfo("Device: " + ci->device);
		}

		SendClientInfo("Engine: " + ci->engine);

		SendClientInfo("UserAgent: " + ci->useragent);

		SendClientInfo("UALength: " + ConvToStr(ci->useragent.length()));

		if (showip)
		{
			SendClientInfo("IP: " + target->GetAddress());
		}

		if (showhost)
		{
			SendClientInfo("Host: " + target->GetRealHost());
		}

		if (!ci->platform.empty())
		{
			SendClientInfo("Platform: " + ci->platform);
		}

		if (!ci->language.empty())
		{
			SendClientInfo("Language: " + ci->language);
		}

		if (!ci->timezone.empty())
		{
			SendClientInfo("Timezone: " + ci->timezone);
		}

		if (!ci->screen.empty())
		{
			SendClientInfo("Screen: " + ci->screen);
		}

		SendClientInfo("RiskScore: " + ConvToStr(ci->riskscore));

		std::string scorevisual;

		int bars = ci->riskscore / 10;

		for (int i = 0; i < bars; ++i)
			scorevisual += "#";

		if (scorevisual.empty())
			scorevisual = "-";

		SendClientInfo("ScoreVisual: " + scorevisual);

		std::string risklevel = "LOW";

		if (ci->riskscore >= 80)
			risklevel = "CRITICAL";

		else if (ci->riskscore >= 50)
			risklevel = "HIGH";

		else if (ci->riskscore >= 20)
			risklevel = "MEDIUM";

		SendClientInfo("RiskLevel: " + risklevel);

		std::string clienttype = "HUMAN";

		if (ci->bot || ci->headless || ci->malicious)
			clienttype = "AUTOMATED";

		SendClientInfo("Type: " + clienttype);

		if (ci->bot)
		{
			SendClientInfo("Bot: YES");
		}

		if (ci->proxy)
		{
			SendClientInfo("Proxy: YES");
		}

		if (ci->datacenter)
		{
			SendClientInfo("Datacenter: YES");
		}

		if (ci->mobile)
		{
			SendClientInfo("Mobile: YES");
		}

		if (ci->headless)
		{
			SendClientInfo("Headless: YES");
		}

		if (ci->malicious)
		{
			SendClientInfo("Malicious: YES");
		}

		if (!ci->riskreason.empty())
		{
			SendClientInfo("RiskReason: " + ci->riskreason);
		}

		SendClientInfo(
			"Stats: total=" + ConvToStr(totalchecks) +
			" bots=" + ConvToStr(botchecks) +
			" proxies=" + ConvToStr(proxychecks) +
			" datacenters=" + ConvToStr(datacenterchecks) +
			" malicious=" + ConvToStr(maliciouschecks)
		);
	}
};

MODULE_INIT(ModuleClientInfo)
