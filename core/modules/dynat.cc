#include "dynat.h"

CommandResponse dyNAT::Init(const bess::pb::dyNATArg& arg) 
{
	handle = arg.handle();

	next = 0;
	if(arg.seed())
	{
		rng_.SetSeed(arg.seed());
	} else
	{
		rng_.SetSeed(0x0F07ul);
	}

        for(const auto &e : arg.ext_addrs()) 
	{
                be32_t addr;
                bool ret = bess::utils::ParseIpv4Address(e.ext_addr(), &addr);

                if(!ret)
		{
                        return CommandFailure(EINVAL, "invalid IP address %s", e.ext_addr().c_str());
		}

                dst_addrs_.push_back(addr);
                std::vector<bool> ports;

                for(uint32_t j = 0; j < kPortRange; j++)
		{
                        ports.push_back(true);
		}

                port_lists_.push_back(ports);
        }

        return CommandSuccess();
}

inline 
dyNATFlow dyNAT::ExtractFlow(bess::Packet *pkt) 
{
	Ipv4* ip = _get_attr_with_offset<Ipv4*>(L3_OFFSET, pkt);
	Tcp* tcp = _get_attr_with_offset<Tcp*>(L4_OFFSET, pkt);

        dyNATFlow ret = { 	.src_port = tcp->src_port, .dst_port = tcp->dst_port,
                		.src_addr = ip->src, .dst_addr = ip->dst,
        };

        return ret;
}

inline 
void dyNAT::UpdateFlow(bess::Packet *pkt, dyNATFlow *after) 
{
	Ipv4* ip = _get_attr_with_offset<Ipv4*>(L3_OFFSET, pkt);
	Tcp* tcp = _get_attr_with_offset<Tcp*>(L4_OFFSET, pkt);

	uint32_t l3_increment, l4_increment;
	l3_increment = ChecksumIncrement32(ip->src.raw_value(), after->src_addr.raw_value());
	l4_increment = l3_increment + ChecksumIncrement16(tcp->src_port.raw_value(), after->src_port.raw_value());

	ip->src = after->src_addr;
	tcp->src_port = after->src_port;

	ip->checksum = UpdateChecksumWithIncrement(ip->checksum, l3_increment);
	tcp->checksum = UpdateChecksumWithIncrement(tcp->checksum, l4_increment);
}

inline
std::tuple<bool, be32_t, be16_t> dyNAT::GetEndpoint(uint32_t idx) 
{
        uint16_t start_port = 1 + rng_.GetRange(kPortRange);

	uint16_t port;
        for(uint32_t i = 0; i < kPortRange; i++) 
	{
		port = (start_port + i) % kPortRange;

                if(port_lists_[idx][port]) 
		{
                        port_lists_[idx][port] = false;

                        return std::make_tuple(true, dst_addrs_[idx], be16_t(port));
                }
        }

        return std::make_tuple(false, be32_t(0), be16_t(0));
}

inline
dyNATFlow *dyNAT::CreateNewEntry(const dyNATFlow& before) 
{
	bool valid;
        be32_t addr;
        be16_t port;
        uint32_t idx;

        for(uint32_t trials = 0; trials < dst_addrs_.size(); trials++) 
	{
                idx = (next++ % dst_addrs_.size());

                std::tie(valid, addr, port) = GetEndpoint(idx);

                if(valid)
		{
                        break;
		}
        }

        if(!valid)
	{
                return nullptr;
	}

	dyNATFlow *after = (dyNATFlow*) rte_malloc(NULL, sizeof(dyNATFlow), 0);
	after->src_port = port;
	after->dst_port = before.dst_port;
	after->src_addr = addr;
	after->dst_addr = before.dst_addr;

        return after;
}

void dyNAT::ProcessBatch(Context *ctx, bess::PacketBatch *batch) 
{
	int cnt = batch->cnt();

        for(int i = 0; i < cnt; i++) 
	{
                bess::Packet *pkt = batch->pkts()[i];

		dyNATFlow *state = _lookup<dyNATFlow>(handle, pkt);
		if(!state) 
		{
			dyNATFlow flow = ExtractFlow(pkt);
			state = CreateNewEntry(flow);
			_insert<dyNATFlow>(handle, pkt, state);
		}

		UpdateFlow(pkt, state);
        }

	RunNextModule(ctx, batch);
}

ADD_MODULE(dyNAT, "dynat", "NAT NF with Dyssect")
