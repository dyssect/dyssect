#include <click/config.h>
#include "dyssectworkingcore.hh"
#include <click/args.hh>
#include <click/router.hh>
#include <click/standard/scheduleinfo.hh>

#include <clicknet/ip.h>
#include <clicknet/tcp.h>
#include <clicknet/ether.h>

CLICK_DECLS

inline bool is_priority(const click_ip *ip)
{
    return ip->ip_id == htons(1);
}

inline bool is_less_than(double a, double b)
{
    return (b - a) > ( (fabs(a) < fabs(b) ? fabs(b) : fabs(a)) * EPSILON );
}

DyssectWorkingCore::DyssectWorkingCore()
    : _task(this)
{
    in_batch_mode = BATCH_MODE_YES;
}

DyssectWorkingCore::~DyssectWorkingCore()
{
}

int DyssectWorkingCore::configure(Vector<String> &conf, ErrorHandler *errh)
{
    if(Args(conf, this, errh)
        .read("PORT", portid)
        .read("QUEUE", queueid)
        .read_or_set("BURST", _burst, 32)
        .complete() < 0)
        return -1;
    
    off_idx = 0;
    qsize = 256;
    myown = false;
    q = DyssectController::queues[queueid];
    myring = DyssectController::rings[queueid];
    offloading_idx = rte_atomic32_read(DyssectController::offloading_from_working[queueid]);
    
    return 0;
}

int DyssectWorkingCore::initialize(ErrorHandler *errh)
{
    ScheduleInfo::initialize_task(this, &_task, true, errh);
    return 0;
}

inline DyssectState* DyssectWorkingCore::extract_state(Packet *p) 
{
    const click_ip *ip = reinterpret_cast<const click_ip *>(p->data() + sizeof(click_ether));
    const click_tcp *tcp = reinterpret_cast<const click_tcp *>(p->data() + sizeof(click_ether) + ip->ip_hl*4);

    DyssectFlow f = {
        .src_port = tcp->th_sport,
        .dst_port = tcp->th_dport,
        .src_addr = IPAddress(ip->ip_src),
        .dst_addr = IPAddress(ip->ip_dst),
        .hash_value = AGGREGATE_ANNO(p)
    };

    if(unlikely(DyssectController::iqueues == 1)) {
        f.hash_value = rte_hash_crc(&f, FLOW_SIZE, 0);
    }

    DyssectState *state = 0;
    bool priority = is_priority(ip);
    uint32_t s = f.hash_value % DyssectController::total_shards;

    auto item = DyssectController::shards[s].table->find(f);
    if(item != DyssectController::shards[s].table->end()) 
    {
        state = item->second;

        if(!priority)
        {
            uint32_t local_epoch = rte_atomic32_read(DyssectController::epoch);

            if(state->epoch != local_epoch)
            {
                state->prob = 0;
                if(DyssectController::shards[s].old_bytes && state->epoch == local_epoch-1)
                {
                    state->prob = ((double) state->bytes)/DyssectController::shards[s].old_bytes;
                }
                state->bytes = 0;
                state->epoch = local_epoch;
            }

            if(DyssectController::shards[s].use_2)
            {
                rte_atomic32_inc(&DyssectController::shards[s].ref_count_2);
                DyssectController::shards[s].flows3_2->operator[](state->flow) = state;
                rte_atomic32_dec(&DyssectController::shards[s].ref_count_2);
            } else
            {
                rte_atomic32_inc(&DyssectController::shards[s].ref_count_1);
                DyssectController::shards[s].flows3->operator[](state->flow) = state;
                rte_atomic32_dec(&DyssectController::shards[s].ref_count_1);
            }
        }

    } else {
        state = (DyssectState*) rte_zmalloc(NULL, sizeof(DyssectState), 64);
        void **global_state = (void**) rte_zmalloc(NULL, DyssectController::sfc_length * sizeof(void*), 64);

        state->global_state = global_state;
        DyssectController::shards[s].table->operator[](f) = state;
        state->prob = 0;
        state->shard = s;
        state->priority = priority;
        state->epoch = rte_atomic32_read(DyssectController::epoch);

        rte_memcpy(&(state->flow), &f, sizeof(DyssectFlow));
    }

    uint32_t iplen = ntohs(ip->ip_len);

    state->bytes += iplen;
    rte_atomic32_add(&DyssectController::shards[s].bytes, iplen);
    rte_atomic32_inc(&DyssectController::shards[s].packets);

    p->set_network_header((const unsigned char*) ip);
    p->set_transport_header((const unsigned char*) tcp);
    SET_PERFCTR_ANNO(p, (uint64_t)(state->global_state));

    return state;
}

inline int DyssectWorkingCore::run(Packet *p)
{
    DyssectState *state = extract_state(p);
    if(state->priority)
    {
        return 0;
    }

    uint32_t s = state->shard;
    if(is_less_than(state->cdf, DyssectController::shards[s].r))
    {
        off_pkts[off_idx++] = p->mb();
        return -1;
    }
    
    return 0;
}

inline PacketBatch *DyssectWorkingCore::process()
{
    struct rte_mbuf *pkts[_burst];

    if(unlikely(rte_atomic32_read(DyssectController::had_changes[queueid]) == 1))
    {
        for(uint32_t s = 0; s < DyssectController::total_shards; s++)
        {
            if(DyssectController::shards[s].owner_new == queueid) 
            {
                if(rte_atomic32_read(&DyssectController::shards[s].pause) == 0)
                {
                    myown = false;
                    while(rte_ring_count(&DyssectController::shards[s].local_queue) != 0) 
                    {
                        uint32_t cnt = rte_ring_dequeue_burst(&DyssectController::shards[s].local_queue, (void**) pkts, _burst, 0);

                        rte_ring_enqueue_burst(myring, (void**) pkts, cnt, 0);
                    }
                }
            }
        }

        rte_atomic32_clear(DyssectController::had_changes[queueid]);
    }
    if(unlikely(myown))
    {
        return 0;
    }

    int cnt = rte_eth_rx_burst(portid, queueid, pkts, _burst);
    if(cnt == 0)
    {
        return 0;
    }

    PacketBatch *head = 0;
    WritablePacket *last;
    for(int i = 0; i < cnt; i++)
    {
        WritablePacket *p = static_cast<WritablePacket *>(Packet::make(pkts[i], false));
        p->set_packet_type_anno(Packet::HOST);
        SET_AGGREGATE_ANNO(p, pkts[i]->hash.rss);
        SET_FLOW_ID_ANNO(p, queueid);

        if (head == NULL)
            head = PacketBatch::start_head(p);
        else
            last->set_next(p);
        last = p;
    }

    head->make_tail(last, cnt);

    return head;
}

void DyssectWorkingCore::transfer_r()
{
    if(rte_ring_count(q) != 0)
    {
        rte_ring_enqueue(DyssectController::toRemoveQueue[offloading_idx], q);

        myown = true;
        rte_ring *aux = q;
        q = myring;
        DyssectController::queues[queueid] = myring;
        myring = aux;
        DyssectController::rings[queueid] = aux;

        rte_ring_enqueue(DyssectController::toAddQueue[offloading_idx], q);
    }

    for(uint32_t s = 0; s < DyssectController::total_shards; s++)
    {
        if(DyssectController::shards[s].owner == queueid)
        {
            DyssectController::shards[s].r = DyssectController::shards[s].r_new;
        }
    }
    
    rte_atomic32_clear(DyssectController::transfer_r[queueid]);
}

void DyssectWorkingCore::transfer_shard()
{
    struct rte_mbuf *pkts[_burst];

    if(offloading_idx != UINT32_MAX)
        rte_ring_enqueue(DyssectController::toRemoveQueue[offloading_idx], q);

    uint32_t count = MIN(rte_eth_rx_queue_count(portid, queueid), qsize);

    while(count > 0)
    {
        myown = true;

        int cnt = rte_eth_rx_burst(portid, queueid, pkts, _burst);
        if(cnt == 0)
        {
            break;
        }

        rte_ring_enqueue_burst(myring, (void**) pkts, cnt, 0);

        count -= cnt;
    }

    while(rte_ring_count(q) != 0)
    {
        myown = true;

        int cnt = rte_ring_dequeue_burst(q, (void**) pkts, _burst, NULL);
        rte_ring_enqueue_burst(myring, (void**) pkts, cnt, NULL);
    }

    if(offloading_idx != UINT32_MAX)
        rte_ring_enqueue(DyssectController::toAddQueue[offloading_idx], q);

    if(!myown)
    {
        for(uint32_t s = 0; s < DyssectController::total_shards; s++)
        {
            if(DyssectController::shards[s].owner == queueid && DyssectController::shards[s].owner_new != UINT32_MAX)
            {
                rte_atomic32_clear(&DyssectController::shards[s].pause);
                uint32_t owner_new = DyssectController::shards[s].owner_new;
                rte_atomic32_set(DyssectController::had_changes[owner_new], 1);
            }
        }
    }

    rte_atomic32_clear(DyssectController::transfer_shard[queueid]);
}

void DyssectWorkingCore::transfer_offloading()
{
    struct rte_mbuf *pkts[_burst];

    if(offloading_idx != UINT32_MAX)
        rte_ring_enqueue(DyssectController::toRemoveQueue[offloading_idx], q);

    while(rte_ring_count(q) != 0)
    {
        myown = true;

        int cnt = rte_ring_dequeue_burst(q, (void**) pkts, _burst, NULL);
        rte_ring_enqueue_burst(myring, (void**) pkts, cnt, NULL);
    }

    uint32_t new_offloading_idx = rte_atomic32_read(DyssectController::new_offloading_from_working[queueid]);
    if(new_offloading_idx != UINT32_MAX)
    {
        rte_ring_enqueue(DyssectController::toAddQueue[new_offloading_idx], q);
        offloading_idx = new_offloading_idx;
        rte_atomic32_set(DyssectController::new_offloading_from_working[queueid], UINT32_MAX);
    }

    rte_atomic32_clear(DyssectController::transfer_offloading[queueid]);
}

bool DyssectWorkingCore::run_task(Task *) {
    struct rte_mbuf *pkts[_burst];

    PacketBatch *head = 0;
    WritablePacket *last;

    if(unlikely(myown))
    {
        if(rte_ring_empty(myring))
        {
            myown = false;

            for(uint32_t s = 0; s < DyssectController::total_shards; s++)
            {
                if(rte_atomic32_read(&DyssectController::shards[s].pause) == 1 && DyssectController::shards[s].owner == queueid && DyssectController::shards[s].owner_new != UINT32_MAX)
                {
                    rte_atomic32_clear(&DyssectController::shards[s].pause);
                    uint32_t onwer_new = DyssectController::shards[s].owner_new;
                    rte_atomic32_set(DyssectController::had_changes[onwer_new], 1);
                }

                if(rte_atomic32_read(&DyssectController::shards[s].pause) == 0 && DyssectController::shards[s].owner_new == queueid)
                {
                    DyssectController::shards[s].owner_new = UINT32_MAX;
                    DyssectController::shards[s].owner = queueid;
                }
            }

            _task.fast_reschedule();
            return true;
        }

        uint32_t cnt = MIN(rte_ring_count(myring), _burst);
        if(cnt == 0)
        {
            _task.fast_reschedule();
            return true;
        }

        rte_ring_dequeue_burst(myring, (void**) pkts, cnt, NULL);

        for(uint32_t i = 0; i < cnt; i++) {
            WritablePacket *p = static_cast<WritablePacket *>(Packet::make(pkts[i], false));
            p->set_packet_type_anno(Packet::HOST);
            SET_AGGREGATE_ANNO(p, pkts[i]->hash.rss);
            SET_FLOW_ID_ANNO(p, queueid);

            extract_state(p);

            if (head == NULL)
                head = PacketBatch::start_head(p);
            else
                last->set_next(p);
            last = p;
        }

        if(head) 
        {
            head->make_tail(last, cnt);
            output_push_batch(0, head);
        }
        
        _task.fast_reschedule();
        return true;
    }

    if(unlikely(rte_atomic32_read(DyssectController::controller_signal[queueid]) == 1))
    {
        if(rte_atomic32_read(DyssectController::transfer_r[queueid]) == 1)
        {
            transfer_r();
        }
        if(rte_atomic32_read(DyssectController::transfer_offloading[queueid]) == 1)
        {
            transfer_offloading();   
        }
        if(rte_atomic32_read(DyssectController::transfer_shard[queueid]) == 1)
        {
            transfer_shard();
        }
        rte_atomic32_clear(DyssectController::controller_signal[queueid]);
    }

    PacketBatch *batch = process();
    if(batch) 
    {
        CLASSIFY_EACH_PACKET_IGNORE(1, run, batch, output_push_batch);
        if(off_idx)
        {
            rte_ring_enqueue_burst(q, (void**) off_pkts, off_idx, NULL);
            off_idx = 0;
        }
    } 

    _task.fast_reschedule();
    return true;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(DyssectWorkingCore)
