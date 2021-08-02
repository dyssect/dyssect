#include "dyids.h"

int dyIDS::lex(const uint8_t *YYCURSOR)
{
	const uint8_t *YYMARKER;

first_group:
    
{
	uint8_t yych;
	unsigned int yyaccept = 0;
	yych = *YYCURSOR;
	switch (yych) {
	case 0x00:	goto yy2;
	case 0x01:	goto yy4;
	default:	goto yy6;
	}
yy2:
	++YYCURSOR;
	{ return 0; }
yy4:
	yyaccept = 0;
	yych = *(YYMARKER = ++YYCURSOR);
	switch (yych) {
	case 0x00:	goto yy5;
	case 0x01:	goto yy7;
	case 0x03:	goto yy10;
	default:	goto yy9;
	}
yy5:
	{ goto first_group; }
yy6:
	yyaccept = 0;
	yych = *(YYMARKER = ++YYCURSOR);
	switch (yych) {
	case 0x00:	goto yy5;
	case 0x01:	goto yy7;
	default:	goto yy9;
	}
yy7:
	yych = *++YYCURSOR;
	switch (yych) {
	case 0x01:	goto yy12;
	case 0x03:	goto yy10;
	default:	goto yy8;
	}
yy8:
	YYCURSOR = YYMARKER;
	if (yyaccept == 0) {
		goto yy5;
	} else {
		goto yy15;
	}
yy9:
	yych = *++YYCURSOR;
	switch (yych) {
	case 0x01:	goto yy12;
	default:	goto yy8;
	}
yy10:
	yych = *++YYCURSOR;
	switch (yych) {
	case 0x00:	goto yy8;
	case 0x0b:	goto yy13;
	default:	goto yy10;
	}
yy12:
	yych = *++YYCURSOR;
	switch (yych) {
	case 0x03:	goto yy10;
	default:	goto yy8;
	}
yy13:
	yyaccept = 1;
	yych = *(YYMARKER = ++YYCURSOR);
	switch (yych) {
	case 0x00:	goto yy15;
	case 0x0b:	goto yy13;
	default:	goto yy10;
	}
yy15:
	{ return 1; }
}

}

CommandResponse dyIDS::Init(const bess::pb::dyIDSArg& arg) 
{
        handle = arg.handle();

        offset_ = 0;

        if(arg.offset())
	{
                offset_ = arg.offset();
	}

        return CommandSuccess();
}

inline
void dyIDS::UpdateState(bess::Packet *pkt, dyIDSState *state) 
{
        Ipv4* ip = _get_attr_with_offset<Ipv4*>(L3_OFFSET, pkt);
        Tcp* tcp = _get_attr_with_offset<Tcp*>(L4_OFFSET, pkt);

        size_t payload_len = ip->length.value() - ip->header_length*4 - tcp->offset*4;

        if(payload_len) 
	{
                uint8_t *payload = _get_attr_with_offset<uint8_t*>(PAYLOAD_OFFSET, pkt);

                payload += offset_;

                int ret = lex(payload);

		if(ret != 0) 
		{
                        state->matched[state->found++ % ENTRIES] = tcp->seq_num.raw_value();
                } else {
                        state->unmatched[state->not_found++ % ENTRIES] = tcp->seq_num.raw_value();
                }
        } else 
	{
                state->unmatched[state->not_found++ % ENTRIES] = tcp->seq_num.raw_value();
        }
}

void dyIDS::ProcessBatch(Context *ctx, bess::PacketBatch *batch) 
{
        int cnt = batch->cnt();

        for(int32_t i = 0; i < cnt; i++) 
	{
                bess::Packet *pkt = batch->pkts()[i];

                dyIDSState *state = _lookup<dyIDSState>(handle, pkt);

                if(!state) 
		{
                        state = (dyIDSState*) rte_zmalloc(NULL, sizeof(dyIDSState), 0);
                        state->matched = (uint32_t*) rte_malloc(NULL, ENTRIES * sizeof(uint32_t), 0);
                        state->unmatched = (uint32_t*) rte_malloc(NULL, ENTRIES * sizeof(uint32_t), 0);
                        _insert<dyIDSState>(handle, pkt, state);
                }

                UpdateState(pkt, state);
        }

        RunNextModule(ctx, batch);
}

ADD_MODULE(dyIDS, "dyids", "SSL NF with Dyssect")
