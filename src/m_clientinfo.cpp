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

		return MOD_RES_PASSTHRU;
	}

	Version GetVersion() override
	{
		return Version("Advanced WebIRC intelligence module", VF_VENDOR);
	}
};

MODULE_INIT(ModuleClientInfo)
