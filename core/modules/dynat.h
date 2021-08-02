#ifndef BESS_MODULES_DYNAT_H_
#define BESS_MODULES_DYNAT_H_

#include "../module.h"
#include "../pb/module_msg.pb.h"

#include <tuple>
#include <rte_hash_crc.h>

#include "../utils/ip.h"
#include "../utils/tcp.h"
#include "../utils/udp.h"
#include "../utils/ether.h"
#include "../utils/format.h"
#include "../utils/endian.h"
#include "../utils/random.h"
#include "../utils/checksum.h"
#include "../utils/cuckoo_map.h"

#include "dyssectnf.h"

using bess::utils::Tcp;
using bess::utils::Ipv4;
using bess::utils::be16_t;
using bess::utils::be32_t;
using bess::utils::Ethernet;
using bess::utils::UpdateChecksum16;
using bess::utils::ChecksumIncrement16;
using bess::utils::ChecksumIncrement32;
using bess::utils::UpdateChecksumWithIncrement;

struct dyNATFlow {
        be16_t src_port;
        be16_t dst_port;
        be32_t src_addr;
        be32_t dst_addr;
};

class dyNAT : public DyssectNF {
        private:
                static const uint16_t kPortRange = (1 << 16) - 1;

                Random rng_;
                uint32_t next;
                std::vector<be32_t> dst_addrs_;
                std::vector<std::vector<bool>> port_lists_;

		dyNATFlow ExtractFlow(bess::Packet *);
		void UpdateFlow(bess::Packet *, dyNATFlow *);
                dyNATFlow *CreateNewEntry(const dyNATFlow &);
                std::tuple<bool, be32_t, be16_t> GetEndpoint(uint32_t);

        public:
                CommandResponse Init(const bess::pb::dyNATArg &);
                void ProcessBatch(Context *, bess::PacketBatch *) override;
};

#endif // BESS_MODULES_DYNAT_H_
