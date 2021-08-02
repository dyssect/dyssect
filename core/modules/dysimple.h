#ifndef BESS_MODULES_DYSIMPLE_H_
#define BESS_MODULES_DYSIMPLE_H_

#include "../module.h"
#include "../pb/module_msg.pb.h"

#include "dyssectnf.h"

class dySimpleState
{
	/* NF state struture */
};

class dySimple : public DyssectNF {
	private:
		bool timeout(bess::Packet*);
		void nf_logic(bess::Packet*, dySimpleState*);
        public:
		CommandResponse Init(const bess::pb::dySimpleArg& arg);
                void ProcessBatch(Context *, bess::PacketBatch *) override;
};

#endif // BESS_MODULES_DYSIMPLE_H_
