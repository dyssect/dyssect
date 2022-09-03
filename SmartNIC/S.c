#include <stdint.h>
#include <nfp.h>
#include <nfp/me.h>
#include <nfp/mem_atomic.h>
#include <pif_common.h>
#include <std/hash.h>
#include "pif_plugin.h"

#define VFS 				1
#define BUCKET_SIZE 			16
#define TABLE_SIZE			262140
#define MAX_PORTS			65536
#define RSS_SIZE			16
#define MAX_NUM_PUBLIC_IPS 		32
#define IP_ADDR(a, b, c, d) 	((a << 24) | (b << 16) | (c << 8) | d)

__shared __export __addr40 __emem uint32_t rss_buckets[RSS_SIZE];

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
}

int pif_plugin_processing(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data) 
{
	PIF_PLUGIN_tcp_T *tcp;
	PIF_PLUGIN_ipv4_T *ipv4;
	volatile uint32_t rss_entry;
	volatile uint32_t hash_value;
	volatile uint16_t hash_core[6];

	if(!pif_plugin_hdr_tcp_present(headers)) 
	{
		return PIF_PLUGIN_RETURN_DROP;
	}

	ipv4 = pif_plugin_hdr_get_ipv4(headers);
	tcp = pif_plugin_hdr_get_tcp(headers);
	
	hash_core[0] = (ipv4->src >> 16) & 0xFFFF;
	hash_core[1] = (ipv4->src) & 0xFFFF;
	hash_core[2] = (ipv4->dst >> 16) & 0xFFFF;
	hash_core[3] = (ipv4->dst) & 0xFFFF;
	hash_core[4] = tcp->src;
	hash_core[5] = tcp->dst;
	hash_value = hash_core[0] ^ hash_core[1] ^ hash_core[2] ^ hash_core[3] ^ hash_core[4] ^ hash_core[5];
	rss_entry = hash_value & (RSS_SIZE-1);

	if(pif_plugin_meta_get__standard_metadata__ingress_port(headers) != 0) 
	{
		pif_plugin_meta_set__standard_metadata__egress_spec(headers, 0);
	} else
	{
		ipv4->checksum = fold_checksum((~ipv4->checksum & 0xFFFF) + checksum_increment16(ipv4->id, (uint16_t) hash_value));	
		ipv4->id = (uint16_t) hash_value;
		pif_plugin_meta_set__standard_metadata__egress_spec(headers, rss_buckets[rss_entry]);
	}

	return PIF_PLUGIN_RETURN_FORWARD;
}
