#ifndef BESS_MODULES_DYIDS_H_
#define BESS_MODULES_DYIDS_H_

#include "../module.h"
#include "../pb/module_msg.pb.h"

#include "../utils/ip.h"
#include "../utils/tcp.h"

#include "dyssectnf.h"

#define ENTRIES	100

using bess::utils::Tcp;
using bess::utils::Ipv4;

struct dyIDSState {
	uint32_t found;
	uint32_t not_found;
	uint32_t *matched;
	uint32_t *unmatched;
};

class dyIDS : public DyssectNF {
	private:
		size_t offset_;
		int lex(const uint8_t *);

	public:
		void UpdateState(bess::Packet *, dyIDSState *);
		CommandResponse Init(const bess::pb::dyIDSArg&);
		void ProcessBatch(Context *, bess::PacketBatch *) override;
};

#endif // BESS_MODULES_DYIDS_H_
