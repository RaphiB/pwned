#!/usr/bin/python

import sys
import requests
import os
import hashlib
import getpass
import re
import argparse
import json
import logging



headers = {
    'User-Agent': 'python-hibpwned-checker'
}

logger = logging.getLogger(__name__)

# Uncomment next line for debugging
#logging.basicConfig(level=logging.DEBUG)

# Response codes can be found in the api description https://haveibeenpwned.com/API/v2 
response_code = {200 : "Ok — everything worked and there\'s a string array of pwned sites for the account", 400 : "Bad request — the account does not comply with an acceptable format (i.e. it\'s an empty string)", 403 : "Forbidden — no user agent has been specified in the request", 404 : "Not found — the account could not be found and has therefore not been pwned", 429 : "Too many requests — the rate limit has been exceeded"}


class color:
    OKGREEN = '\033[92m'
    WARNING = '\u001b[31m'
    ENDC = '\033[0m'


"""Prompts for email address a given time and  """
def checkEmail(numberEmail):
    for i in range(int(numberEmail)):
        email = input("Enter your email: ")
        try:
             r = requests.get('https://haveibeenpwned.com/api/v2/breachedaccount/' + email, headers=headers)
        except Exception as error:
            logger.error(color.WARNING + "Error - Can\'t connect to database:\n {0}".format(error) + color.ENDC)
        else:
            logger.debug(response_code[r.status_code])
            if r:
                 dic = json.loads(r.text)
                 print(color.WARNING+"\nYour email has been found in following leaks:\n")
                 for leaks in dic:
                     print("[*]Breach {Name}({Domain}) has been leaked on the {BreachDate} and {PwnCount} accounts where affected.\n\n".format(**leaks))
                 print(color.ENDC)
            else:
                 print(color.OKGREEN + "Your email isn\'t affected :)\n"+color.ENDC)

def checkPassword(numberPassword):
    for i in range(int(numberPassword)):
        try:
            password = getpass.getpass()
        except Exception as error:
            logger.error(color.WARNING + 'ERROR - {0}'.format(error) + color.ENDC)
        else:
            print('Searching for password...')

        sha1 = hashlib.sha1(password.encode())
        firstFive = sha1.hexdigest()[0:5].upper()
        lastChars = sha1.hexdigest()[5::].upper()
        try:
             r = requests.get('https://api.pwnedpasswords.com/range/'+ firstFive)
        except Exception as error:
            logger.error(color.WARNING + 'ERROR - Can\'t connect to API!:\n{0}'.format(error) + color.ENDC)
        else:
            s = re.search(lastChars+".*",r.text)
            if s:
                 print(color.WARNING + 'Found a match!')
                 a = re.search(":.*",s.group())
                 print("Number of occurence:", a.group()[1::]+color.ENDC)
            else:
                 print(color.OKGREEN + 'Password not found!'+color.ENDC)

def isInt(query):
    while True:
        try:
             val = int(input("How many {0} do you want to check?: ".format(query)))
        except ValueError:
             print("That's not an int!")
             continue
        return val


def main():
    print("This program can check if credentials are listed in the database off Troy Hunt (pwnedpasswords.com)\n\n")
    while True:
        print("First we will check if your email is affected")
        numberEmail = isInt("email adresses")
        checkEmail(numberEmail)
        print("\nNow lets check if your password is unsafe and occurs in the database\nThe passwords you insert are hashed and only a certain part of the hash is sent to the API")
        numberPassword = isInt("passwords")
        checkPassword(numberPassword)
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
        print('\nInterrupted by human...')
        sys.exit(0)

