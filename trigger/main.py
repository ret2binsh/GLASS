#!/usr/bin/python3
import logging
import os
import sys
import shutil
from cmd import Cmd

import handler

logging.basicConfig(level=logging.DEBUG)

class MainMenu(Cmd):

    def __init__(self):
        super(MainMenu,self).__init__()
        self.mainHandle = handler.Handler()
    level = "frACK"
    prompt = "%s> " % level


    def print_center(self,message):
        width = shutil.get_terminal_size()[0]
        print(" " * int(width/4 - len(message)/2) + message)

    def emptyline(self):
        pass

    def default(self,inp):
        if inp == "q" or inp == "quit" or inp == "exit":
            print(inp)
            return True
        else:
            os.system(inp)

    #call the handler submenu and pass the menu level and the handler object
    def do_handler(self,inp):
        handler.HandlerPrompt(self.level, self.mainHandle).cmdloop()

    def help_handler(self):
        output = ["=======frACK Handler=======",
                  "Enters the handler submenu",
                  "This is for creating manual handlers",
                  "such as reverse shell callbacks."]
        for line in output:
            self.print_center(line)

    def do_sessions(self,inp):
        try:
            for key in self.mainHandle.bag.keys():
                print("%d: %d<-----%s" % (key,self.mainHandle.bag[key][2],self.mainHandle.bag[key][1][0]))    
        except AttritubeError as err:
            logging.debug(err)
            pass

    def do_exit(self,inp):
        try:
            if len(self.mainHandle.bag) > 0:
                while True:
                    ans = input("You have open sessions. Exit?").lower()
                    if ans == "y" or ans == "yes":
                        print("Exiting")
                        #Close the active client connections
                        for key in self.mainHandle.bag.keys():
                            self.mainHandle.bag[key][0].close()
                        return True
                    elif ans == "n" or ans == "no":
                        break
            else:
                print("Exiting")
                return True
        except AttributeError as err:
            #Gracefully handle the absence of the handler object and exit as normal
            logging.debug(err)
            print("Exiting")
            return True
    
def main():

    frack = MainMenu()
    frack.cmdloop()


if __name__ == "__main__":
    main()
