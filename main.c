#include "struct.h"
pdata *head;
pcap_t* pcap;

void show_strength(u_int8_t * data,u_int8_t * macaddr){
    BeaconFrame * pkt = (data + (*(radiotap_header *)(data)).it_len);
    int8_t psig = *(int8_t * )(data + (*(radiotap_header *)(data)).it_len-2);
    //int8_t psig = *(int8_t * )(data + 18);
    if((pkt->subtype == 0x80 || pkt->subtype == 0x94 ||pkt->subtype == 0xd0 ||pkt->subtype == 0x20 ||pkt->subtype == 0x50 || pkt->subtype == 0x40 ||pkt->subtype == 0xb0 ||pkt->subtype == 0x88||pkt->subtype == 0x08||pkt->subtype == 0x48||pkt->subtype == 0x84||pkt->subtype == 0xb4) && (!memcmp(pkt->src_mac,macaddr,6))){
        if ((int8_t)(psig-0xff) == 1){
            printf("\t %02x:%02x:%02x:%02x:%02x:%02x\n",macaddr[0],macaddr[1],macaddr[2],macaddr[3],macaddr[4],macaddr[5]);    
            return;
        }
        printf("%d\t %02x:%02x:%02x:%02x:%02x:%02x\n",(int8_t)(psig),macaddr[0],macaddr[1],macaddr[2],macaddr[3],macaddr[4],macaddr[5]);
    }
}
int main(int argc, char* argv[]){
    uint8_t *interface_;
    u_int8_t tmac[6];
    uint8_t errbuf[PCAP_ERRBUF_SIZE];
    uint8_t channel = 1;

    if(argc != 3 ){
        printf("signal-strength <interface> <mac>\n");
        exit(-1);
    }
    interface_ = argv[1];
     sscanf(argv[2],"%2X:%2X:%2X:%2X:%2X:%2X",&tmac[0],&tmac[1],&tmac[2],&tmac[3],&tmac[4],&tmac[5]);
    pcap = pcap_open_live(interface_, BUFSIZ, 1, 1000, errbuf);

    if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", interface_, errbuf);
		return -1;
	}
    while(1){
        struct pcap_pkthdr* header;
		const uint8_t* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
		}
        show_strength(packet,tmac);
    }
    pcap_close(pcap);
}
