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
 public:
	Version GetVersion() override
	{
		return Version("Advanced WebIRC intelligence module", VF_VENDOR);
	}
};

MODULE_INIT(ModuleClientInfo)
