#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <arpa/inet.h>
#include <string.h>

static struct route_table_entry *rtable;
static int rtable_len;

static struct arp_entry *mac_table;
static int mac_table_len;

static char buf[MAX_PACKET_LEN];

static int interface;
static size_t len;
static queue mac_queue;

struct route_table_entry *get_best_route(uint32_t ip_dest)
{
	struct route_table_entry *rt_entry = NULL;
	for (int i = 0; i < rtable_len; i++) {
		if (rtable[i].prefix == (ip_dest & rtable[i].mask)) {
			if (rt_entry == NULL) {
				rt_entry = &rtable[i];
			}
			if (rt_entry != NULL && rt_entry->mask < rtable[i].mask) {
				rt_entry = &rtable[i];
			}
		}
	}

	return rt_entry;
}

struct arp_entry *get_mac_entry(uint32_t given_ip)
{
	for (int i = 0; i < mac_table_len; i++) {
		if (mac_table[i].ip == given_ip)
			return &mac_table[i];
	}
	return NULL;
}

void add_mac_entry(struct arp_entry *mac_entry) {
	memcpy(&mac_table[mac_table_len], mac_entry, sizeof(struct arp_entry));
	mac_table_len++;
}

void send_arp_request(struct route_table_entry *entry) {
	printf("%x\n", entry->next_hop);

	struct packet_info *packet = malloc(sizeof(struct packet_info));
	packet->table_entry = entry;
	packet->len = len;
	memcpy(packet->buf, buf, len);
	queue_enq(mac_queue, packet);

	struct ether_header *eth_hdr = (struct ether_header *)buf;
	struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));
	len = sizeof(*eth_hdr) + sizeof(*arp_hdr);

	arp_hdr->hlen = 6;
	arp_hdr->htype = htons(1);
	arp_hdr->op = htons(1);
	arp_hdr->plen = 4;
	arp_hdr->ptype = htons(ETHERTYPE_IP);
	memset(arp_hdr->tha, 0, 6);
	arp_hdr->tpa = entry->next_hop;
	get_interface_mac(entry->interface, arp_hdr->sha);
	arp_hdr->spa = get_interface_ip(entry->interface);

	memset(eth_hdr->ether_dhost, 0xFF, 6);
	get_interface_mac(entry->interface, eth_hdr->ether_shost);
	eth_hdr->ether_type = htons(ETHERTYPE_ARP);
	send_to_link(entry->interface, buf, len);
}

void handle_send_error(uint8_t type) {
	struct ether_header *eth_hdr = (struct ether_header *)buf;
	struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
	struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));

	int len_icmp_body = sizeof(struct iphdr) + 8;
	void *icmp_body = malloc(len_icmp_body);
	memcpy(icmp_body, ip_hdr, len_icmp_body);
	
	memset(icmp_hdr, 0, sizeof(struct icmphdr));
	icmp_hdr->code = 0;
	icmp_hdr->type = type;
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr)));

	ip_hdr->daddr = ip_hdr->saddr;
	ip_hdr->ttl = 64;
	ip_hdr->saddr = get_interface_ip(interface);
	ip_hdr->protocol = IPPROTO_ICMP;
	ip_hdr->tot_len = htons((uint16_t)len_icmp_body + sizeof(struct icmphdr) + sizeof(struct iphdr));
	ip_hdr->check = 0;
	ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
	get_interface_mac(interface, eth_hdr->ether_shost);

	memcpy((char *)icmp_hdr + sizeof(struct icmphdr), icmp_body, len_icmp_body);
	int len_to_send = len_icmp_body + sizeof(struct ether_header) + sizeof(struct iphdr) +
					  sizeof(struct icmphdr);

	send_to_link(interface, buf, len_to_send);
	free(icmp_body);
}

void respond_ping() {
	printf("Cv1\n");
	struct ether_header *eth_hdr = (struct ether_header *)buf;
	struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
	struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));

	int len_icmp_body = ntohs(ip_hdr->tot_len) - sizeof(struct iphdr) - sizeof(struct icmphdr);
	printf("%d\n", len_icmp_body);
	void *icmp_body = malloc(len_icmp_body);
	memcpy(icmp_body, (char *)(icmp_hdr) + sizeof(struct icmphdr), len_icmp_body);
	
	icmp_hdr->code = 0;
	icmp_hdr->type = 0;
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr)));

	ip_hdr->daddr = ip_hdr->saddr;
	ip_hdr->ttl = 64;
	ip_hdr->saddr = get_interface_ip(interface);
	ip_hdr->protocol = IPPROTO_ICMP;
	ip_hdr->tot_len = htons((uint16_t)len_icmp_body + sizeof(struct icmphdr) + sizeof(struct iphdr));
	ip_hdr->check = 0;
	ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
	get_interface_mac(interface, eth_hdr->ether_shost);

	memcpy((char *)icmp_hdr + sizeof(struct icmphdr), icmp_body, len_icmp_body);
	int len_to_send = len_icmp_body + sizeof(struct ether_header) + sizeof(struct iphdr) +
					  sizeof(struct icmphdr);

	send_to_link(interface, buf, len_to_send);
	free(icmp_body);
}

void handle_ip_request()
{
	struct ether_header *eth_hdr = (struct ether_header *)buf;
	struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

	// 1. verificare daca el este destinatia
	if (ip_hdr->daddr == get_interface_ip(interface))
	{
		respond_ping();
		return;
	}

	// 2.checksum
	uint16_t check = ntohs(ip_hdr->check);
	ip_hdr->check = 0;
	ip_hdr->check = checksum((uint16_t *)ip_hdr, sizeof(*ip_hdr));
	if (check != ip_hdr->check)
	{
		printf("Drop checksum\n");
		return;
	}
	// 4. cautare in tabela
	struct route_table_entry *best_router = get_best_route(ip_hdr->daddr);
	if (best_router == NULL)
	{
		handle_send_error(3);
		return;
	}

	// 3. verif + actualizare ttl + checksum

	if (ip_hdr->ttl > 1) {
		ip_hdr->ttl--;
		ip_hdr->check = 0;
		ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(*ip_hdr)));
	}
	else {
		handle_send_error(11);
		return;
	}

	struct arp_entry *mac_entr = get_mac_entry(best_router->next_hop);
	if (mac_entr == NULL)
	{
		send_arp_request(best_router);
		return;
 	}
	memcpy(eth_hdr->ether_dhost, mac_entr->mac, sizeof(mac_entr->mac));
	get_interface_mac(best_router->interface, eth_hdr->ether_shost);
	send_to_link(best_router->interface, buf, len);
}

void handle_arp_request()
{	
	printf("----- MAC TABLE -----\n");
	for (int i = 0; i < mac_table_len; i++) {
		printf("0x%x\n", mac_table[i].ip);
	}
	printf("--- END MAC TABLE ----\n");

	struct ether_header *eth_hdr = (struct ether_header *)buf;
	struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));
	// request
	if (arp_hdr->op == htons(1)) {
		if (arp_hdr->tpa != get_interface_ip(interface))
			return;
		printf("%x\n", arp_hdr->spa);
		arp_hdr->op = htons(2);
		memcpy(arp_hdr->tha, arp_hdr->sha, 6);
		arp_hdr->tpa = arp_hdr->spa;
		get_interface_mac(interface, arp_hdr->sha);
		arp_hdr->spa = get_interface_ip(interface);
		get_interface_mac(interface, eth_hdr->ether_shost);
		memcpy(eth_hdr->ether_dhost, arp_hdr->tha, 6);
		send_to_link(interface, buf, len);
		return;
	} else if (arp_hdr->op == htons(2)) {
		queue helper_queue = queue_create();
		struct arp_entry new_entry;
		new_entry.ip = arp_hdr->spa;
		memcpy(new_entry.mac, arp_hdr->sha, 6);
		printf("%x\n", new_entry.ip);
		add_mac_entry(&new_entry);
		while (!queue_empty(mac_queue)) {
			printf("cv2\n");
			struct packet_info *packet = queue_deq(mac_queue);
			struct ether_header *eth_hdr_pack = (struct ether_header *)packet->buf;
			struct arp_entry *mac_entr = get_mac_entry(packet->table_entry->next_hop);
			if (mac_entr == NULL) {
				printf("cv3\n");
				queue_enq(helper_queue, packet);
				continue;
			}
			memcpy(eth_hdr_pack->ether_dhost, mac_entr->mac, 6);
			get_interface_mac(packet->table_entry->interface, eth_hdr_pack->ether_shost);
			send_to_link(packet->table_entry->interface, packet->buf, packet->len);
			free(packet);
		}
		free(mac_queue);
		mac_queue = helper_queue;
	}
}

int main(int argc, char *argv[])
{

	// Do not modify this line
	init(argc - 2, argv + 2);

	rtable = malloc(sizeof(struct route_table_entry) * 100000);
	DIE(rtable == NULL, "Memory\n");

	mac_table = malloc(sizeof(struct arp_entry) * 100);
	DIE(mac_table == NULL, "Memory\n");

	/* Read the static routing table and the MAC table */
	rtable_len = read_rtable(argv[1], rtable);
	mac_table_len = 0;
	//mac_table_len = parse_arp_table("arp_table.txt", mac_table);
	mac_queue = queue_create();
	while (1) {
		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *)buf;

		if (eth_hdr->ether_type == htons(ETHERTYPE_IP)) {
			handle_ip_request();
			continue;
		}
		else if (eth_hdr->ether_type == htons(ETHERTYPE_ARP)) {
			handle_arp_request();
			continue;
		}
		else {
			printf("Unknown\n");
		}
	}
}
