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
import time

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
        email = input(que("Email adress: "))
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
                     print(bad(red("""Breach:            {Name} - Domain ({Domain}) 
    Date:              {BreachDate}
    Affected accounts: {PwnCount}\n""".format(**leaks))))
                 dump(email)
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
            time.sleep(1.5)

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
        print('\n')
        try:
             val = int(input(que("Number of {0} to check: ".format(query))))
        except ValueError:
             print("That's not an int!")
             continue
        return val


def main():
       while True:
           banner()
           print(orange("""This program can check if credentials are listed in the database off Troy Hunt (pwnedpasswords.com)
You can query for email addresses and passwords. Your password will never be sent in plaintext (checks for possible password leak local).
This tool hashes your password, sends a partial hash to the API and then receives a bunch of possible hashed candidates which eventually
will contain your password.  \n\n"""))
           numberEmail = isInt("email adresses")
           checkEmail(numberEmail)
           numberPassword = isInt("passwords")
           checkPassword(numberPassword)
           print('\n')
           answer = input(que("Restart(y/n): "))
           if answer.lower().startswith("y"):
               print(run("Restarting....\n\n"))
               time.sleep(1)
           elif answer.lower().startswith("n"):
               print(run("Adios!"))
               exit(0)


def banner():
    os.system('clear')
    custom_banner = Figlet(font='graffiti')
    print(lightred(custom_banner.renderText('pwned?')))

def dump(email):
    dumplist = []
    print('\n')
    print(run('Looking for Dumps...\n'))
    time.sleep(1.5)
    rq = requests.get('https://haveibeenpwned.com/api/v2/pasteaccount/{}'.format(email), headers= headers, timeout=10)
    sc = rq.status_code
    if sc != 200:
            print(good(green('[ No Dumps Found ]\n\n')))
    else:
            print(bad(red('[ Dumps Found ]\n')))
            json_out = rq.content.decode('utf-8', 'ignore')
            simple_out = json.loads(json_out)

            for item in simple_out:
                    if (item['Source']) == 'Pastebin':
                            link = item['Id']
                            try:
                                    url = 'https://www.pastebin.com/raw/{}'.format(link)
                                    page = requests.get(url, timeout=10)
                                    sc = page.status_code
                                    if sc == 200:
                                            dumplist.append(url)
                                            print('Collecting dumps : '+str(len(dumplist)), end='\r')
                            except requests.exceptions.ConnectionError:
                                    pass
                    elif (item['Source']) == 'AdHocUrl':
                            url = item['Id']
                            try:
                                    page = requests.get(url, timeout=10)
                                    sc = page.status_code
                                    if sc == 200:
                                            dumplist.append(url)
                                            print('Collecting dumps : ' + str(len(dumplist)), end='\r')
                            except requests.exceptions.ConnectionError:
                                    pass


    if len(dumplist) != 0:
            print('\n\n') 
            print(bad(red(' Passwords:\n')))
            for entry in dumplist:
                    time.sleep(1.2)
                    try:
                            page = requests.get(entry, timeout=10)
                            dict = page.content.decode('utf-8', 'ignore')
                            passwd = re.search('{}:(\w+)'.format(email), dict)
                            if passwd:
                                    print(bad(passwd.group(1)))
                            elif not passwd:
                                    for line in dict.splitlines():
                                            passwd = re.search('(.*{}.*)'.format(email), line)
                                            if passwd:
                                                    print(bad(passwd.group(0)))
                    except requests.exceptions.ConnectionError:
                            pass




if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print('\n')
        print(run('Interrupted by human...'))
        sys.exit(0)

