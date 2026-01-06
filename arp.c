#include <netinet/in.h>
#include <stdio.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

typedef unsigned char u8;

int main(void) {
	struct ifreq ifr;
	struct sockaddr_ll sll = {0};
	int fd, id;
	u8 mac[6], ip4[4]; /* MAC-адрес и IP адрес отправителя */
	u8 ethernet[14];
	u8 arp[8];
	u8 arpreq[20]; /* MAC отправителя/получателя + IPv4 отправителя/получателя */
	u8 frame[sizeof(ethernet) + sizeof(arpreq) + sizeof(arp)];
	size_t ret;
	u8 rbuf[512]; /* буффер для получения ответа */

	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", "wlp0s20f3"); /* запись имени интерфейса */
	if ((fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) return 0;

	/* получение индекса интерфейса */
	if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) return 0;
	id = ifr.ifr_ifindex;

	/* получение MAC-адреса отправителя */
	if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) return 0;
	memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);

	/* получение IP-адреса отправителя */
	if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) return 0;
	memcpy(ip4, ifr.ifr_addr.sa_data+2, 4); /* +2 для пропуска номера порта sin_port */

	/* заполняю Ethernet заголовок */
	memset(ethernet, 0xff, 6); /* broadcast-адрес, чтобы пакет пришёл всем */
	memcpy(ethernet+6, mac, 6); /* свой MAC-адрес */
	ethernet[12] = 0x08; /* Type ARP: 0x0806 */
	ethernet[13] = 0x06;

	/* заполняю поля ARP заголовка */
	arp[0] = 0x00; /* Hardware type: Ethernet (0x0001) */
	arp[1] = 0x01;
	arp[2] = 0x08; /* Protocol type: IPv4 (0x0800)*/
	arp[3] = 0x00;
	arp[4] = 0x06; /* Hardware size: 6 (длина MAC-адреса) */
	arp[5] = 0x04; /* Protocol size: 4 (размер IPv4) */
	arp[6] = 0x00; /* Opcode request: 0x0001 */
	arp[7] = 0x01;

	/* поля отправителя */
	memcpy(arpreq, mac, 6);
	memcpy(arpreq+6, ip4, 4);
	memset(arpreq+6+4, 0x00, 6);
	arpreq[6+4+6] = 192;
	arpreq[6+4+6+1] = 168;
	arpreq[6+4+6+2] = 0;
	arpreq[6+4+6+3] = 231;

	puts("Get 192.168.0.231 MAC address");

	/* заполнение итогового кадра полученными данными */
	memcpy(frame, ethernet, sizeof(ethernet));
	memcpy(frame + sizeof(ethernet), arp, sizeof(arp));
	memcpy(frame + sizeof(ethernet) + sizeof(arp), arpreq, sizeof(arpreq));

	/* отправка пакета */
	sll.sll_family = PF_PACKET;
	sll.sll_ifindex = id;
	sll.sll_protocol = 0x0806;
	sendto(fd, frame, sizeof(frame), 0, (struct sockaddr *)&sll, sizeof(sll));

	/* получение ответа */
	for (;;) {
		if (ret = recv(fd, rbuf, sizeof(rbuf), 0) == -1 ) return 0;
		/* сравниваю Target IP address с моим */
		if (rbuf[14+8+6+4+6] == arpreq[6] &&
			rbuf[14+8+6+4+6+1] == arpreq[7] &&
			rbuf[14+8+6+4+6+2] == arpreq[8] &&
			rbuf[14+8+6+4+6+3] == arpreq[9]) 
			break;
	}
	close(fd);

	/* печать MAC-адреса получателя */
	for (int i = 0; i < 6; i++)
		printf("%02x%s",rbuf[14+8+i], (i ==5) ? "\n" : ":");

	return 0;
}
