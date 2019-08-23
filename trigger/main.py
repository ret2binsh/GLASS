#!/usr/bin/python3
import os
import sys
import handler
from cmd import Cmd

class MainMenu(Cmd):

    prompt = "frACK> "

    def default(self,inp):
        if inp == "q" or inp == "quit" or inp == "exit":
            print(inp)
            return True
        else:
            os.system(inp)

def main():

    frack = MainMenu()
    frack.cmdloop()


if __name__ == "__main__":
    main()
