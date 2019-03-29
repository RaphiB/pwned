#!/usr/bin/python

import sys
import requests
import os
import hashlib
import getpass
import re
import argparse
import json

class color:
    OKGREEN = '\033[92m'
    WARNING = '\u001b[31m'
    ENDC = '\033[0m'

def checkEmail():
    print("First we will check if your email is affected")
    numberEmail = input("How many email adresses do you want to check: ")
    for i in range(int(numberEmail)):
        email = input("Enter your email: ")
        try:
             r = requests.get('https://haveibeenpwned.com/api/v2/breachedaccount/' + email) #+ '?truncateResponse=true')
        except Exception as error:
            print(color.WARNING + 'ERROR', "Can\'t connect to database")
        else:
            if r:
                 # print(color.WARNING + r.text + "\n")
                 dic = json.loads(r.text)
                 print(color.WARNING+"\nYour email has been found in following leaks:\n")
                 for leaks in dic:
                     print("[*]Breach {Name}({Domain}) has been leaked on the {BreachDate} and {PwnCount} accounts where affected.\n\n".format(**leaks))
                 print(color.ENDC)
            else:
                 print(color.OKGREEN + "Your email isn\'t affected :)\n"+color.ENDC)

def checkPassword():
    print("\nNow lets check if your password is unsafe and occurs in the database\nThe passwords you insert are hashed and only a certain part of the hash is sent to the API")
    numberPassword = input("How many passwords do you want to check: ")
    for i in range(int(numberPassword)):
        try:
            password = getpass.getpass()
        except Exception as error:
            print('ERROR', error)
        else:
            print('Searching for password...')

        sha1 = hashlib.sha1(password.encode())
        firstFive = sha1.hexdigest()[0:5].upper()
        lastChars = sha1.hexdigest()[5::].upper()
        try:
             r = requests.get('https://api.pwnedpasswords.com/range/'+ firstFive)
        except Exception as error:
            print(color.WARNING + 'ERROR', '- Can not connect to API!')
        else:
            s = re.search(lastChars+".*",r.text)
            #a = re.search(":.*",s.group())
            if s:
                 print(color.WARNING + 'Found a match!')
                 a = re.search(":.*",s.group())
                 print("Number of occurence:", a.group()[1::]+color.ENDC)
            else:
                 print(color.OKGREEN + 'Password not found!'+color.ENDC)



def main():
    print("This program can check if credentials are listed in the database off Troy Hunt (pwnedpasswords.com)\n\n")
    while True:
        checkEmail()
        checkPassword()
        answer = input("Do you want to continue?:")
        if answer.lower().startswith("y"):
            print("\nRestarting....\n\n")
        elif answer.lower().startswith("n"):
            print("Adios!")
            exit(0)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print('\n Interrupted by human...')
        sys.exit(0)

