/*
 * m_clientinfo.cpp
 *
 * Advanced WebIRC intelligence and client metadata module
 * for InspIRCd4.
 *
 * GPLv2
 */

#include "inspircd.h"
#include "../include/clientinfo.h"

void DetectClientInfo(const std::string& ua, ClientInfo& ci);

class ModuleClientInfo : public Module
{
 private:

	SimpleExtItem<ClientInfo> ext;

 public:

	ModuleClientInfo()
		: ext(this, "clientinfo")
	{
	}

	ModResult OnPreCommand(std::string& command,
		CommandBase::Params& parameters,
		LocalUser* user,
		bool validated) override
	{
		if (command != "METADATA")
			return MOD_RES_PASSTHRU;

		if (parameters.size() < 3)
			return MOD_RES_PASSTHRU;

		if (parameters[1] != "useragent")
			return MOD_RES_PASSTHRU;

		ClientInfo ci;

		DetectClientInfo(parameters[2], ci);

		ext.Set(user, ci);

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

		return MOD_RES_PASSTHRU;
	}

	void OnWhois(Whois::Context& ctx) override
	{
		if (!ctx.source->IsOper())
			return;

		ClientInfo* ci = ext.Get(ctx.target);

		if (!ci)
			return;

		ctx.source->WriteNumeric(
			320,
			ctx.target->nick,
			"CLIENTINFO Browser: " + ci->browser
		);

		ctx.source->WriteNumeric(
			320,
			ctx.target->nick,
			"CLIENTINFO OS: " + ci->os
		);

		ctx.source->WriteNumeric(
			320,
			ctx.target->nick,
			"CLIENTINFO Device: " + ci->device
		);

		ctx.source->WriteNumeric(
			320,
			ctx.target->nick,
			"CLIENTINFO RiskScore: " +
			ConvToStr(ci->riskscore)
		);

		if (ci->bot)
		{
			ctx.source->WriteNumeric(
				320,
				ctx.target->nick,
				"CLIENTINFO Bot: YES"
			);
		}
	}

	Version GetVersion() override
	{
		return Version("Advanced WebIRC intelligence module", VF_VENDOR);
	}
};

MODULE_INIT(ModuleClientInfo)
