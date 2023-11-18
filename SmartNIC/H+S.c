#include <stdint.h>
#include <nfp.h>
#include <nfp/me.h>
#include <nfp/mem_atomic.h>
#include <pif_common.h>
#include <std/hash.h>
#include "pif_plugin.h"

#define VFS 				1
#define BUCKET_SIZE 			16
#define TABLE_SIZE			262144
#define MAX_PORTS			65536
#define RSS_SIZE			16
#define MAX_NUM_PUBLIC_IPS 		32
#define IP_ADDR(a, b, c, d) 	((a << 24) | (b << 16) | (c << 8) | d)

typedef struct bucket_entry_info {
	uint32_t state;
	uint32_t ip;
	uint32_t port;
} bucket_entry_info;

typedef struct bucket_key {
	uint32_t key0;
	uint32_t key1;
	uint32_t key2;
} bucket_key;

typedef struct bucket_entry {
	bucket_key key;
	bucket_entry_info bucket_entry_info_value;
} bucket_entry;

typedef struct bucket_list {
	struct bucket_entry entry[BUCKET_SIZE];
} bucket_list;

__declspec(emem export aligned(64)) int global_semaphores[TABLE_SIZE];
__shared __export __addr40 __emem bucket_list hashtable[TABLE_SIZE];
__shared __export __addr40 __emem bucket_entry pendingtable[TABLE_SIZE];
__shared __export __addr40 __emem uint32_t rss_buckets[RSS_SIZE];
__shared __export __imem uint32_t public_ips[MAX_NUM_PUBLIC_IPS] = {
	IP_ADDR(10,0,0,1), IP_ADDR(10,0,0,10), IP_ADDR(10,0,0,100), IP_ADDR(10,0,0,200), 
	IP_ADDR(10,0,1,1), IP_ADDR(10,0,1,10), IP_ADDR(10,0,1,100), IP_ADDR(10,0,1,200), 
	IP_ADDR(10,1,1,1), IP_ADDR(10,1,1,10), IP_ADDR(10,1,1,100), IP_ADDR(10,1,1,200), 
	IP_ADDR(172,16,0,1), IP_ADDR(172,16,0,10), IP_ADDR(172,16,0,100), IP_ADDR(172,16,0,200), 
	IP_ADDR(172,16,1,1), IP_ADDR(172,16,1,10), IP_ADDR(172,16,1,100), IP_ADDR(172,16,1,200),
	IP_ADDR(192,168,0,1), IP_ADDR(192,168,0,10), IP_ADDR(192,168,0,100), IP_ADDR(192,168,0,200),
	IP_ADDR(192,168,1,1), IP_ADDR(192,168,1,10), IP_ADDR(192,168,1,100), IP_ADDR(192,168,1,200),
	IP_ADDR(192,168,2,1), IP_ADDR(192,168,2,10), IP_ADDR(192,168,2,100), IP_ADDR(192,168,2,200)};

void semaphore_down(volatile __declspec(mem addr40) void * addr) 
{
	unsigned int addr_hi, addr_lo;
	__declspec(read_write_reg) int xfer;
	SIGNAL_PAIR my_signal_pair;
	addr_hi = ((unsigned long long int)addr >> 8) & 0xff000000;
	addr_lo = (unsigned long long int)addr & 0xffffffff;

	do 
	{
		xfer = 1;
		__asm 
		{
			mem[test_subsat, xfer, addr_hi, <<8, addr_lo, 1],\
			sig_done[my_signal_pair];
			ctx_arb[my_signal_pair]
		}
	} while (xfer == 0);
}

void semaphore_up(volatile __declspec(mem addr40) void * addr) 
{
	unsigned int addr_hi, addr_lo;
	__declspec(read_write_reg) int xfer;

	addr_hi = ((unsigned long long int)addr >> 8) & 0xff000000;
	addr_lo = (unsigned long long int)addr & 0xffffffff;

	__asm 
	{
		mem[incr, --, addr_hi, <<8, addr_lo, 1];
	}
}

uint16_t fold_checksum(uint32_t cksum) 
{
	uint32_t sum = (cksum >> 16) + (cksum & 0xFFFF);
	sum += (sum >> 16);
	return ~sum;
}

uint32_t checksum_increment32(uint32_t old, uint32_t new) 
{
	uint32_t sum = (~old >> 16) + (~old & 0xFFFF);
	sum += (new >> 16) + (new & 0xFFFF);
	return sum;
}

uint32_t checksum_increment16(uint16_t old, uint16_t new) 
{
	return (~old & 0xFFFF) + new;
}

uint16_t checksum(uint8_t* data, uint16_t len)
{
	uint64_t sum = 0;
	uint32_t* p = (uint32_t*) data;
	uint16_t i = 0;

	while(len >= 4) 
	{
		sum = sum + p[i++];
		len -= 4;
	}
	
	if(len >= 2) 
	{ 
		sum = sum + ((uint16_t*) data)[i * 4];
		len -= 2;
	}
	
	if(len == 1) 
	{
		sum += data[len-1];
	}
	
	while(sum >> 16) 
	{
		sum = (sum & 0xffff) + (sum>>16);
	}
	
	return ((uint16_t)~sum);
}

void pif_plugin_init() 
{
}

void pif_plugin_init_master() 
{
	uint32_t i;
	uint32_t j;

	for(i = 0; i < RSS_SIZE; i++) 
	{
		rss_buckets[i] = 768 + (i & (VFS-1));
	}

	for(i = 0; i < TABLE_SIZE; i++) 
	{
		semaphore_up(&global_semaphores[i]);
		for(j = 0; j < RSS_SIZE; j++) {
			hashtable[i].entry[j].key.key0 = 0;
			hashtable[i].entry[j].key.key1 = 0;
			hashtable[i].entry[j].key.key2 = 0;
		}
	}
}

int pif_plugin_scan_payload(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data)
{
        __xread uint8_t xdata8;
        __xread uint32_t xdata32;
        __mem __addr40 uint8_t *payload;

        int count;
        uint32_t mu_len;
        uint32_t sum = 0;

        if(pif_pkt_info_global.p_is_split) {
                mu_len = pif_pkt_info_global.p_len - ((256 << pif_pkt_info_global.p_ctm_size) - pkt.p_offset);
        } else {
                mu_len = 0;
        }

        count = pif_pkt_info_global.p_len - pif_pkt_info_spec.pkt_pl_off - mu_len;
        payload = pkt_ctm_ptr40(pkt.p_isl, pkt.p_pnum, pkt.p_offset);
        payload += pif_pkt_info_spec.pkt_pl_off;

        while(count > 0) {
                mem_read8(&xdata32, payload, 1);

                sum += xdata32 & 0xFF;

                count--;
                payload++;
        }

        if(mu_len) {
                payload = (__mem __addr40 void *)((uint64_t)pif_pkt_info_global.p_muptr << 11);
                payload += 256 << pif_pkt_info_global.p_ctm_size;

                count = mu_len;

                while(count > 0) {
                        mem_read8(&xdata32, payload, 1);

                        sum += xdata32 & 0xFF;

                        count--;
                        payload++;
                }
        }

        return sum;
}

int pif_plugin_processing(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data) 
{
	int i;
	volatile uint32_t hit;
	uint32_t csum;
	uint32_t newIP;
	uint16_t newPort;
	uint32_t oldIP;
	uint16_t oldPort;
	uint32_t randval;
	uint32_t pending;
	uint32_t rss_value;
	uint16_t hash_core[6];
	PIF_PLUGIN_tcp_T *tcp;
	PIF_PLUGIN_ipv4_T *ipv4;
	volatile uint32_t rss_entry;
	volatile uint32_t hash_key[3];
	volatile uint32_t hash_entry;
	volatile uint32_t hash_value;
	__xread uint32_t hash_key_r[3];
	__addr40 bucket_key *key_addr;
	__addr40 bucket_entry_info *b_info;

	if(!pif_plugin_hdr_tcp_present(headers)) 
	{
		return PIF_PLUGIN_RETURN_DROP;
	}

	ipv4 = pif_plugin_hdr_get_ipv4(headers);
	tcp = pif_plugin_hdr_get_tcp(headers);

	if(pif_plugin_meta_get__standard_metadata__ingress_port(headers) != 0) {
		pif_plugin_meta_set__standard_metadata__egress_spec(headers, 0);

		return PIF_PLUGIN_RETURN_FORWARD;
	}
	
	hash_core[0] = (ipv4->src >> 16) & 0xFFFF;
	hash_core[1] = (ipv4->src) & 0xFFFF;
	hash_core[2] = (ipv4->dst >> 16) & 0xFFFF;
	hash_core[3] = (ipv4->dst) & 0xFFFF;
	hash_core[4] = tcp->src;
	hash_core[5] = tcp->dst;

	hash_key[0] = ipv4->src;
	hash_key[1] = ipv4->dst;
	hash_key[2] = (tcp->src << 16) | tcp->dst;
	hash_value = hash_core[0] ^ hash_core[1] ^ hash_core[2] ^ hash_core[3] ^ hash_core[4] ^ hash_core[5];
	rss_entry  = hash_value & (RSS_SIZE-1);
	hash_entry = hash_value & (TABLE_SIZE-1);

	hit = 0;
	semaphore_down(&global_semaphores[hash_entry]);

	pending = pendingtable[hash_entry].bucket_entry_info_value.state;
	if(pending != 0)
	{
		if(pending == 1)
		{
			for(i = 0; i < BUCKET_SIZE; i++)
			{
				mem_read_atomic(hash_key_r, (__mem __addr40 void*) &(hashtable[hash_entry].entry[i].key), sizeof(hash_key_r));
	
				if(hash_key_r[0] == 0) 
				{
					key_addr = &(hashtable[hash_entry].entry[i].key);
					{
	                			__xwrite uint32_t data[6];
		        		        data[0] = hash_key[0];
				                data[1] = hash_key[1];
				                data[2] = hash_key[2];
	                			data[3] = 1;
				                data[4] = pendingtable[hash_entry].bucket_entry_info_value.ip;
                				data[5] = pendingtable[hash_entry].bucket_entry_info_value.port;

				                mem_write32(&data, key_addr, sizeof(data));
        				}
					break;
				}
			}
		} else 
		{
			for(i = 0; i < BUCKET_SIZE; i++)
			{
				mem_read_atomic(hash_key_r, (__mem __addr40 void*) &(hashtable[hash_entry].entry[i].key), sizeof(hash_key_r));
				
				if(hash_key_r[0] == pendingtable[hash_entry].key.key0 && hash_key_r[1] == pendingtable[hash_entry].key.key1 && hash_key_r[2] == pendingtable[hash_entry].key.key2)
				{
					key_addr = &(hashtable[hash_entry].entry[i].key);
					{
	                			__xwrite uint32_t data[6];
		        		        data[0] = 0;
				                data[1] = 0;
				                data[2] = 0;
	                			data[3] = 0;
				                data[4] = 0;
                				data[5] = 0;

				                mem_write32(&data, key_addr, sizeof(data));
        				}
					break;
				}	
			}
		}

		{
			__xwrite uint32_t data;

			data = 0;
	
			mem_write32(&data, &pendingtable[hash_entry].bucket_entry_info_value.state, sizeof(data));
		}
	}

	for(i = 0; i < BUCKET_SIZE; i++) 
	{
		mem_read_atomic(hash_key_r, (__mem __addr40 void*) &(hashtable[hash_entry].entry[i].key), sizeof(hash_key_r));

		if(hash_key_r[0] == 0)
			continue;

		if(hash_key_r[0] == hash_key[0] && hash_key_r[1] == hash_key[1] && hash_key_r[2] == hash_key[2]) 
		{
			hit = 1;
			b_info = &(hashtable[hash_entry].entry[i].bucket_entry_info_value);

			break;
		}
	}

	if(hit == 1) 
	{
		uint32_t csum;
		uint32_t temp0;
		uint32_t temp1;
		PIF_PLUGIN_ethernet_T *eth;

		semaphore_up(&global_semaphores[hash_entry]);

		csum = checksum_increment32(ipv4->dst, b_info->ip);
		ipv4->checksum = fold_checksum((~ipv4->checksum & 0xFFFF) + csum);
		tcp->checksum = fold_checksum((~tcp->checksum & 0xFFFF) + checksum_increment16(tcp->dst, b_info->port) + csum);
		ipv4->src = b_info->ip;
		tcp->src = b_info->port;

		eth = pif_plugin_hdr_get_ethernet(headers);
		temp0 = eth->dst;
		temp1 = eth->__dst_1;
		eth->dst = (eth->src << 16) | (eth->__src_1 >> 16);
		eth->__dst_1 = (eth->__src_1 & 0xFFFF);
		eth->src = (temp0 >> 16);
		eth->__src_1 = ((temp0 & 0xFFFF) << 16) | temp1;

		b_info->state += pif_plugin_scan_payload(headers, match_data);
		pif_plugin_meta_set__standard_metadata__egress_spec(headers, 0);

		return PIF_PLUGIN_RETURN_FORWARD;
	}

	if(ipv4->diffserv == 0x00)
	{
		if(pif_plugin_meta_get__standard_metadata__ingress_port(headers) == 0)
		{
			semaphore_up(&global_semaphores[hash_entry]);

			ipv4->checksum = fold_checksum((~ipv4->checksum & 0xFFFF) + checksum_increment16(ipv4->id, (uint16_t) hash_value));
			ipv4->id = (uint16_t) hash_value;
			pif_plugin_meta_set__standard_metadata__egress_spec(headers, rss_buckets[rss_entry]);

			return PIF_PLUGIN_RETURN_FORWARD;
		}
	}

	for(i = 0; i < BUCKET_SIZE; i++) 
	{
		if(hashtable[hash_entry].entry[i].key.key0 == 0) 
		{
			key_addr = &(hashtable[hash_entry].entry[i].key);
			b_info = &(hashtable[hash_entry].entry[i].bucket_entry_info_value);

			break;
		}
	}

	if(i == BUCKET_SIZE) 
	{
		semaphore_up(&global_semaphores[hash_entry]);
		return PIF_PLUGIN_RETURN_DROP;
	}
	
	randval = local_csr_read(local_csr_timestamp_low);
	newIP = public_ips[randval & (MAX_NUM_PUBLIC_IPS-1)];
	randval = local_csr_read(local_csr_timestamp_low);
	newPort = randval & (MAX_PORTS-1);

	{
		__xwrite uint32_t data[6];
		data[0] = hash_key[0];
		data[1] = hash_key[1];
		data[2] = hash_key[2];
		data[3] = 1;
		data[4] = newIP;
		data[5] = newPort;

		mem_write32(&data, key_addr, sizeof(data));
	}

	semaphore_up(&global_semaphores[hash_entry]);

	oldIP = ipv4->src;
	oldPort = tcp->src;
	csum = checksum_increment32(ipv4->src, newIP);
	ipv4->checksum = fold_checksum((~ipv4->checksum & 0xFFFF) + csum);
	tcp->checksum = fold_checksum((~tcp->checksum & 0xFFFF) + checksum_increment16(tcp->src, newPort) + csum);
	ipv4->src = newIP;
	tcp->src = newPort;

	{
		uint32_t temp0;
		uint32_t temp1;
		PIF_PLUGIN_ethernet_T *eth;
		
		eth = pif_plugin_hdr_get_ethernet(headers);
		temp0 = eth->dst;
		temp1 = eth->__dst_1;
		eth->dst = (eth->src << 16) | (eth->__src_1 >> 16);
		eth->__dst_1 = (eth->__src_1 & 0xFFFF);
		eth->src = (temp0 >> 16);
		eth->__src_1 = ((temp0 & 0xFFFF) << 16) | temp1;
	
		b_info->state += pif_plugin_scan_payload(headers, match_data);	
		pif_plugin_meta_set__standard_metadata__egress_spec(headers, 0);
	}

	return PIF_PLUGIN_RETURN_FORWARD;
}
