/*
 * m_clientinfo.cpp
 *
 * Advanced WebIRC intelligence and client metadata module
 * for InspIRCd4.
 *
 * GPLv2
 */

#include "inspircd.h"
#include "modules/whois.h"
#include "clientinfo.h"

void DetectClientInfo(const std::string& ua, ClientInfo& ci);

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

 public:

	ModuleClientInfo()
		: Module(VF_VENDOR, "Advanced WebIRC intelligence and client metadata module.")
		, Whois::EventListener(weak_from_this())
		, ext(weak_from_this())
	{
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

		if (parameters[1] != "useragent")
			return MOD_RES_PASSTHRU;

		if (parameters[2].length() > 512)
		{
			ServerInstance->SNO.WriteGlobalSno(
				'a',
				"CLIENTINFO ALERT: Oversized User-Agent from " +
				user->nick +
				" [" + user->GetAddress() + "]"
			);

			return MOD_RES_DENY;
		}

		ext.Unset(user);

		ClientInfo ci;
		DetectClientInfo(parameters[2], ci);
		ext.Set(user, ci, false);

		ServerInstance->SNO.WriteGlobalSno(
			'a',
			"CLIENTINFO: " + user->nick +
			" [" + user->GetAddress() + "] " +
			"using " + ci.browser +
			" on " + ci.os
		);

		if (ci.bot)
		{
			ServerInstance->SNO.WriteGlobalSno(
				'a',
				"CLIENTINFO ALERT: Possible bot detected from " +
				user->nick +
				" [" + user->GetAddress() + "]"
			);
		}

		if (ci.riskscore >= 80)
		{
			ServerInstance->SNO.WriteGlobalSno(
				'a',
				"CLIENTINFO CRITICAL: High risk client detected from " +
				user->nick +
				" [" + user->GetAddress() + "]"
			);
		}

		if (ci.malicious)
		{
			ServerInstance->SNO.WriteGlobalSno(
				'a',
				"CLIENTINFO MALICIOUS: Dangerous client detected from " +
				user->nick +
				" [" + user->GetAddress() + "]"
			);
		}

		return MOD_RES_PASSTHRU;
	}

	void OnWhois(Whois::Context& ctx) override
	{
		LocalUser* source = ctx.GetSource();
		User* target = ctx.GetTarget();

		if (!source->IsOper())
			return;

		ClientInfo* ci = ext.Get(target);

		if (!ci)
			return;

		ctx.SendLine(
			RPL_WHOISSPECIAL,
			"CLIENTINFO Browser: " + ci->browser
		);

		ctx.SendLine(
			RPL_WHOISSPECIAL,
			"CLIENTINFO OS: " + ci->os
		);

		ctx.SendLine(
			RPL_WHOISSPECIAL,
			"CLIENTINFO Device: " + ci->device
		);

		ctx.SendLine(
			RPL_WHOISSPECIAL,
			"CLIENTINFO Engine: " + ci->engine
		);

		ctx.SendLine(
			RPL_WHOISSPECIAL,
			"CLIENTINFO UserAgent: " +
			ci->useragent
		);

		ctx.SendLine(
			RPL_WHOISSPECIAL,
			"CLIENTINFO UALength: " +
			ConvToStr(ci->useragent.length())
		);

		ctx.SendLine(
			RPL_WHOISSPECIAL,
			"CLIENTINFO IP: " +
			target->GetAddress()
		);

		ctx.SendLine(
			RPL_WHOISSPECIAL,
			"CLIENTINFO RiskScore: " +
			ConvToStr(ci->riskscore)
		);

		std::string scorevisual;

		int bars = ci->riskscore / 10;

		for (int i = 0; i < bars; ++i)
			scorevisual += "#";

		if (scorevisual.empty())
			scorevisual = "-";

		ctx.SendLine(
			RPL_WHOISSPECIAL,
			"CLIENTINFO ScoreVisual: " +
			scorevisual
		);

		std::string risklevel = "LOW";

		if (ci->riskscore >= 80)
			risklevel = "CRITICAL";

		else if (ci->riskscore >= 50)
			risklevel = "HIGH";

		else if (ci->riskscore >= 20)
			risklevel = "MEDIUM";

		ctx.SendLine(
			RPL_WHOISSPECIAL,
			"CLIENTINFO RiskLevel: " +
			risklevel
		);

		std::string clienttype = "HUMAN";

		if (ci->bot || ci->headless || ci->malicious)
			clienttype = "AUTOMATED";

		ctx.SendLine(
			RPL_WHOISSPECIAL,
			"CLIENTINFO Type: " +
			clienttype
		);

		if (ci->bot)
		{
			ctx.SendLine(
				RPL_WHOISSPECIAL,
				"CLIENTINFO Bot: YES"
			);
		}

		if (ci->proxy)
		{
			ctx.SendLine(
				RPL_WHOISSPECIAL,
				"CLIENTINFO Proxy: YES"
			);
		}

		if (ci->mobile)
		{
			ctx.SendLine(
				RPL_WHOISSPECIAL,
				"CLIENTINFO Mobile: YES"
			);
		}

		if (ci->headless)
		{
			ctx.SendLine(
				RPL_WHOISSPECIAL,
				"CLIENTINFO Headless: YES"
			);
		}

		if (ci->malicious)
		{
			ctx.SendLine(
				RPL_WHOISSPECIAL,
				"CLIENTINFO Malicious: YES"
			);
		}

		if (!ci->riskreason.empty())
		{
			ctx.SendLine(
				RPL_WHOISSPECIAL,
				"CLIENTINFO RiskReason: " +
				ci->riskreason
			);
		}
	}
};

MODULE_INIT(ModuleClientInfo)
