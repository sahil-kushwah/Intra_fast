import scapy.all as scapy

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
    print('  IP\t\t\tMAC Address\t')
    print('---------------------------------------------')
    for element in ans:
        print(element['ip']+'\t\t'+element['mac'])

ans = scan('192.168.1.0/24')
print_design(ans)
