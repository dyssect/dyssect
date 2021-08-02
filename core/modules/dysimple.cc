#include "dysimple.h"

CommandResponse dySimple::Init(const bess::pb::dySimpleArg& arg) 
{
	handle = arg.handle();

	return CommandSuccess();
}

bool dySimple::timeout(bess::Packet *)
{
	return true; /* Example condition to delete the NF state */
}

void dySimple::nf_logic(bess::Packet *pkt, dySimpleState *) 
{
	/* NF logic here */

	if(timeout(pkt))
	{
		_delete<dySimpleState>(handle, pkt);
	}
}

void dySimple::ProcessBatch(Context *ctx, bess::PacketBatch *batch) 
{
	int cnt = batch->cnt();

        for(int i = 0; i < cnt; i++) 
	{
                bess::Packet *pkt = batch->pkts()[i];

		dySimpleState *state = _lookup<dySimpleState>(handle, pkt);
		if(!state) 
		{
			state = nullptr; /* Allocation the NF state */
			_insert<dySimpleState>(handle, pkt, state);
		}

		nf_logic(pkt, state);
        }

	RunNextModule(ctx, batch);
}

ADD_MODULE(dySimple, "dysimple", "Simple NF with Dyssect")
