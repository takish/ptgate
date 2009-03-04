#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
//#include <arpa/inet.h>
//#include <netinet/in.h>
//#include <sys/socket.h>

struct {
	int id;
	int mask;
} NETMASK[] =
{
{0,0x00000000},
{1,0x00000001},
{2,0x00000003},
{3,0x00000007},
{4,0x0000000f},
{5,0x0000001f},
{6,0x0000003f},
{7,0x0000007f},
{8,0x000000ff},
{9,0x000001ff},
{10,0x000003ff},
{11,0x000007ff},
{12,0x00000fff},
{13,0x00001fff},
{14,0x00003fff},
{15,0x00007fff},
{16,0x0000ffff},
{17,0x0001ffff},
{18,0x0003ffff},
{19,0x0007ffff},
{20,0x000fffff},
{21,0x001fffff},
{22,0x003fffff},
{23,0x007fffff},
{24,0x00ffffff},
{25,0x01ffffff},
{26,0x03ffffff},
{27,0x07ffffff},
{28,0x0fffffff},
{29,0x1fffffff},
{30,0x3fffffff},
{31,0x7fffffff},
{32,0xffffffff}
};

int filter_frame(u_char *buffer, session_t *sp);
int v4orv6(u_char *buffer);
