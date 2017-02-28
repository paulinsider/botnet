#define WIN32
#include <stdlib.h>   
//#include <pthread.h>   
#include "pkt_proc.h" /* packet processing               */
#include "p2f.h"      /* joy data structures       */
#include "err.h"      /* error codes and error reporting */
//#include "anon.h"     /* address anonymization           */
#include "tls.h"      /* TLS awareness                   */
#include "dns.h"      /* DNS awareness                   */
#include "classify.h" /* inline classification           */
#include "http.h"     /* http header data                */
#include "procwatch.h"  /* process to flow mapping       */
//#include "radix_trie.h" /* trie for subnet labels        */
//#include "config.h"     /* configuration                 */
//#include "output.h"     /* compressed output             */
#define flow_key_hash_mask 0x000fffff
// #define flow_key_hash_mask 0xff
#define MAX_TTL 255

#define FLOW_RECORD_LIST_LEN (flow_key_hash_mask + 1)

flow_record_list flow_record_list_array[FLOW_RECORD_LIST_LEN] = { 0, };
static void flow_key_copy(struct flow_key *dst, const struct flow_key *src) {
	dst->sa.s_addr = src->sa.s_addr;
	dst->da.s_addr = src->da.s_addr;
	dst->sp = src->sp;
	dst->dp = src->dp;
	dst->prot = src->prot;
}
static inline void timer_clear(struct timeval *a) {
	a->tv_sec = a->tv_usec = 0;
}
void http_init(http_data_t *data) {
	data->header = NULL;
	data->header_length = 0;
}
void header_description_init(header_description_t *hd) {
	if (hd != NULL) {
		memset(hd->const_value, 0, sizeof(hd->const_value));
		memset(hd->const_mask, 0, sizeof(hd->const_mask));
		memset(hd->seq_mask, 0, sizeof(hd->seq_mask));
		hd->num_headers_seen = 0;
	}
}
static void flow_record_init(/* @out@ */ struct flow_record *record,
	/* @in@  */ const struct flow_key *key) {
	record->id = 0;
	flow_key_copy(&record->key, key);
	record->np = 0;
	record->op = 0;
	record->ob = 0;
	record->nbr = 0;
	record->nbs = 0;
	record->nps = 0;
	record->npr = 0;
	record->num_bytes = 0;
	record->bd_mean = 0.0;
	record->bd_variance = 0.0;
	record->initial_seq = 0;
	record->seq = 0;
	record->ack = 0;
	record->invalid = 0;
	record->retrans = 0;
	record->ttl = MAX_TTL;
	timer_clear(&record->start);
	timer_clear(&record->end);
	record->last_pkt_len = 0;
	memset(record->byte_count, 0, sizeof(record->byte_count));
	memset(record->compact_byte_count, 0, sizeof(record->compact_byte_count));
	memset(record->pkt_len, 0, sizeof(record->pkt_len));
	memset(record->pkt_time, 0, sizeof(record->pkt_time));
	memset(record->pkt_flags, 0, sizeof(record->pkt_flags));
	record->exe_name = NULL;
	record->tcp_option_nop = 0;
	record->tcp_option_mss = 0;
	record->tcp_option_wscale = 0;
	record->tcp_option_sack = 0;
	record->tcp_option_fastopen = 0;
	record->tcp_option_tstamp = 0;
	record->tcp_initial_window_size = 0;
	record->tcp_syn_size = 0;
	//  memset(record->dns.dns_name, 0, sizeof(record->dns.dns_name));
	// dns_init(&record->dns);
	record->idp = NULL;
	record->idp_len = 0;
	record->exp_type = 0;
	record->first_switched_found = 0;
	record->next = NULL;
	record->prev = NULL;
	record->time_prev = NULL;
	record->time_next = NULL;
	record->twin = NULL;

	/* initialize TLS data */
	//tls_record_init(&record->tls_info);
	record->tls_info = NULL;

	http_init(&record->http_data);
	header_description_init(&record->hd);

#ifdef END_TIME
	record->end_time_next = NULL;
	record->end_time_prev = NULL;
#endif
}
static int flow_key_is_eq(const struct flow_key *a, const struct flow_key *b) {
	//return (memcmp(a, b, sizeof(struct flow_key)));
	// more robust way of checking keys are equal
	//   0: flow keys are equal
	//   1: flow keys are not equal
	if (a->sa.s_addr == b->sa.s_addr) {
		if (a->da.s_addr != b->da.s_addr) {
			return 1;
		}
		if (a->sp != b->sp) {
			return 1;
		}
		if (a->dp != b->dp) {
			return 1;
		}
		if (a->prot != b->prot) {
			return 1;
		}
	}
	else if (a->sa.s_addr == b->da.s_addr){
		if (a->da.s_addr != b->sa.s_addr) {
			return 1;
		}
		if (a->sp != b->dp) {
			return 1;
		}
		if (a->dp != b->sp) {
			return 1;
		}
		if (a->prot != b->prot) {
			return 1;
		}
	}
	else {
		return 1;
	}
	// match was found
	return 0;
}
/**
* \fn struct flow_record *flow_key_get_record (const struct flow_key *key,
unsigned int create_new_records)
* \param key
* \param create_new_records
* \return pointer to the flow record structure
* \return NULL if expired or could not create or retireve record
*/
struct flow_record *flow_key_get_record(const struct flow_key *key, struct flow_record *record_root) {
	struct flow_record *record = record_root;
	unsigned int hash_key;

	/* find a record matching the flow key, if it exists */
	while (record != NULL) {
		if (flow_key_is_eq(key, &record->key) == 0) {
			debug_printf("LIST (head location: %p) record %p found\n", list, record);
			return record;
		}
		record = record->next;
	}
	return record;
}

struct flow_record* create_new_records(const struct flow_key *key, struct flow_record *record_root)
{
	struct flow_record *record;
	record = malloc(sizeof(struct flow_record));
	flow_record_init(record, key);
	struct flow_record *tmp;
	tmp = record_root;
	while (tmp->next != NULL){
		tmp = tmp->next;
	}
	tmp->next = record;
	record->id = create_flow();
	return record;
}
void delete_record(struct flow_record *record, struct flow_record *record_root)
{
	struct flow_record *tmp;
	tmp = record_root;
	while (tmp->next != record)
	{
		tmp = tmp->next;
	}
	tmp->next = record->next;
	return;
}