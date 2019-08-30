#!/usr/bin/python
import os
import select
import socket
import sys
import threading
from cmd import Cmd

class Handler(object):
    """Build the socket listener handler object"""
    def __init__(self):

        self.listen_port = 8080
        self.listen_addr = "0.0.0.0"
        self.max_listen  = 1
        self.session = 1
        self.bag = {}
        self.listeners = {}
        self.lcount = 1

class HandlerPrompt(Cmd):

    def __init__(self,parent,mainHandler):
        super(HandlerPrompt,self).__init__()
        self.handler = mainHandler
        self.prompt = "%s::handler> " % parent

    #Establish what no characters are passed to the cmd parsers
    def emptyline(self):
        pass

    #If provided input does not match available options, this is the default
    def default(self,inp):
        if inp == "q" or inp == "quit" or inp == "back":
            return True
        os.system(inp)
   
    #Next two functions handle tab completion after the first level
    def completedefault(self, text, line, begidx, endidx):
        tokens = line.split()
        if tokens[0].strip() == "show":
            return self.show_matches(text,self.show_options)
        elif tokens[0].strip() == "set":
            return self.show_matches(text,self.set_options)
        elif tokens[0].strip() == "interact":
            return self.show_matches(text,self.interact_options)
        return []

    def show_matches(self,text,sub_options):
        matches = []
        n = len(text)
        for word in sub_options:
            if word[:n] == text:
                matches.append(word)
        return matches

    def do_kill(self,inp):

        try:
            session = int(inp)
            if session in self.handler.bag.keys():
                print("Closing session %d" % session)
                self.handler.bag[session][0].close()
                del self.handler.bag[session]
        except ValueError as err:
            print("Invalid session")

    show_options = ["options","listeners"]

    def do_show(self,inp):

        if inp == "options":
            print("\nListen Port:               %d" % self.handler.listen_port)
            print("Listen Addr:               %s" % self.handler.listen_addr)
            print("Max Connections:           %d\n" % self.handler.max_listen)
        
        elif inp == "listeners":
            for x in self.handler.listeners.keys():
                print("%d: %s:%d" % (x, self.handler.listeners[x][1], 
                                     self.handler.listeners[x][2]))

    set_options = ["port","max"]

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
            
            lcount = self.handler.lcount
            self.handler.listeners[lcount] = (s, self.handler.listen_addr, self.handler.listen_port)
            self.handler.lcount = lcount + 1

            x = threading.Thread(target=self.catch_shell, args=(s, self.handler.listen_port, lcount))
            x.setDaemon(True)
            x.start()
            print("Starting listener: %s:%d" % (self.handler.listen_addr, self.handler.listen_port))
        except socket.error as err:
            print(err.strerror)

    def do_sessions(self,inp):

        for key in self.handler.bag.keys():
            print("%d: %d<-----%s" % (key,self.handler.bag[key][2],self.handler.bag[key][1][0]))


    def do_interact(self,inp):
        try:
            sesh = int(inp)
            if sesh in self.handler.bag.keys():
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

    def catch_shell(self,sock,lport,lcount):
    
        sock.listen(self.handler.max_listen)
        client,c_info = sock.accept()
        print("\nReceving connection from %s!" % c_info[0])
        del self.handler.listeners[lcount]
        self.handler.bag[self.handler.session] = (client,c_info,lport)
        sock.close()
        self.handler.session = self.handler.session + 1
        self.interact_options = str(self.handler.bag.keys())
    
    def handle_shell(self,session):
    
        callback = self.handler.bag[session][0]
        c_info = self.handler.bag[session][1]
        sys.stdout.write("%s>" % c_info[0])
        sys.stdout.flush()
        while True:

            # ulitizes select to determine which stream has data to be received from
            sock_list = [sys.stdin,callback]
            read_sockets, write_socket, error_socket = select.select(sock_list,[],[])
    
            for sock in read_sockets:
                if sock == callback:
                    data = ""
                    buffer = 1024
                    while True:
                        message = sock.recv(buffer)
                        data += message.decode()
                        if data[-1] == "\n":
                            break
                    sys.stdout.write("\n" + data + "%s>" % c_info[0])
                    sys.stdout.flush()
                else:
                    message = sys.stdin.readline().strip()
                    if message.strip() == "exit" or message.strip() == "background":
                        break
                    else:
                        callback.send(message.encode() + '\n'.encode())
                        sys.stdout.write("%s>" % c_info[0])
                        sys.stdout.flush()
    
            if message == "exit":
                callback.send(message.encode() + '\n'.encode())
                callback.shutdown(socket.SHUT_RDWR)
                callback.close()
                print("Closing down session %d" % session)
                del self.handler.bag[session]
                break
            elif message == "background":
                break 

def main():
    p = HandlerPrompt()
    p.cmdloop()
    
if __name__ == "__main__":
    main()
