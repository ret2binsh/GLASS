*************************************************************
                  TARP - Trigger on ARP 
************************************************************
Establishes a raw socket listener that will trigger based
off of an ARP packet that has the hardware type set to 0x0018.
It will then utilize the arp_sha struct to gather then reverse
IP and PORT mapping in order to establish the tcp connection to
the attacker. That field is the sender hardware address (MAC).

HARDWARE TYPE = ether[14:15] 
-------------
| 00 |  18  | 
-------------
  |_____|
    /
 IEEE 1394 hw type



SENDER HARDWARE ADDRESS = ether[22:27]
-------------------------------
| 1f | 77 | c0 | a8 | 01 | ee | 
-------------------------------
  |____|    |______________|
    /               /
  PORT        ATTACKER IP
  8055       192.168.1.238
 
