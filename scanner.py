import scapy.all as scapy
from optparse import OptionParser

def taking_arg():
    parser = OptionParser()
    parser.add_option('-r', '--range', dest='range', help="Enter IP range which you want to scan (eg:- -r 192.168.1.0/24)")
    (options, args) = parser.parse_args()
    if(options.range):
        return parser.parse_args()
    else:
        print('Oops you forgot to mention -r agrument, use -h for help')
        exit()

def scan(IP):
    answered_arp_list = []
    answered, unanswered = scapy.srp(scapy.Ether(dst='ff:ff:ff:ff:ff:Ff') / scapy.ARP(pdst=IP), timeout=2, verbose=False)
    i = 1
    for element in answered:
        ans_dict = {'id': i, 'ip': element[1].psrc, 'mac': element[1].hwsrc}
        answered_arp_list.append(ans_dict)
        i += 1
    return answered_arp_list
def print_design(ans):
    print('_____________________________________________')
    print('  IP\t\t\t MAC Address\t')
    print('---------------------------------------------')
    for element in ans:
        print(element['ip']+'\t\t'+element['mac'])

(options, args) = taking_arg()
ans = scan(str(options.range))
print_design(ans)
