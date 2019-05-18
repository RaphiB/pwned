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
from huepy import *
from pyfiglet import Figlet

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
                 print(bold(red("\nYour email has been found in following leaks:\n")))
                 for leaks in dic:
                     print(bad("Breach {Name}({Domain}) has been leaked on the {BreachDate} and {PwnCount} accounts where affected.\n\n".format(**leaks)))
            else:
                 print(good(green("Your email isn\'t affected :)\n")))

def checkPassword(numberPassword):
    for i in range(int(numberPassword)):
        try:
            password = getpass.getpass()
        except Exception as error:
            logger.error(color.WARNING + 'ERROR - {0}'.format(error) + color.ENDC)
        else:
            print(run('Searching for password...'))

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
                 print(bad(red('Found a match!')))
                 a = re.search(":.*",s.group())
                 print(bad(red("Number of occurence: " + a.group()[1::])))
            else:
                 print(good(green('Password not found!')))

def isInt(query):
    while True:
        try:
             val = int(input(que("How many {0} do you want to check?: ".format(query))))
        except ValueError:
             print("That's not an int!")
             continue
        return val


def main():
    banner()
    print(bg(orange("This program can check if credentials are listed in the database off Troy Hunt (pwnedpasswords.com)\n\n")))
    while True:
        print(bg(orange("First we will check if your email is affected")))
        numberEmail = isInt("email adresses")
        checkEmail(numberEmail)
        print(bg(orange("\nNow lets check if your password is unsafe and occurs in the database\nThe passwords you insert are hashed and only a certain part of the hash is sent to the API")))
        numberPassword = isInt("passwords")
        checkPassword(numberPassword)
        answer = input(que("Do you want to continue?:"))
        if answer.lower().startswith("y"):
            print(run("Restarting....\n\n"))
        elif answer.lower().startswith("n"):
            print(run("Adios!"))
            exit(0)


def banner():
    custom_banner = Figlet(font='graffiti')
    print(lightred(custom_banner.renderText('pwned?')))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print('\n')
        print(run('Interrupted by human...'))
        sys.exit(0)

