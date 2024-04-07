#!/usr/bin/python3

#  _*_ coding:utf-8 _*_

# a python tool for detecting phishing emails
# checks the url redirection ; checks the protocol of the url
# fetch important info from email's header file

# <--- to-do: --->  
# > to check for spelling mistake in the email content
# > to check the redirected url 
# > and finally to decide whether it is a phishing email or not


#  Usage: python3 main.py -h header.txt -e email.txt

try:
    import urllib.parse
    import requests,sys
    from getopt import getopt
    from bs4 import BeautifulSoup
    import re
    from textblob import TextBlob    #for checking the spellings!
    from email.parser import BytesParser
    from email.policy import default
except:
    #pass
    print(f'[+] Installing Dependencies...')
    import os;os.system('pip install -r requirements.txt')


# <--- GLOBAL VALUES --->
# <--- TERMCOLOR --->

RED = "\033[0;31m"
WHITE = "\033[0m"
YLW = "\033[1;33m"
GRN = '\033[1;92m'
BLUE = "\033[0;34m"
BOLD =  '\033[1m'


#firefox header
header = {
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0'
}

#header analysis
class emailheaderanalyzer:
    def basicemailinfo(self,file):
        try:
            with open(file, "rb") as fh:
                msg = BytesParser(policy=default).parse(fh)

            #basic information
            print(f"{BLUE}[+]{WHITE} {GRN}From:{WHITE} {BOLD}{msg['From']}{WHITE}")
            print(f"{BLUE}[+]{WHITE} {GRN}To:{WHITE} {BOLD}{msg['To']}{WHITE}")
            print(f"{BLUE}[+]{WHITE} {GRN}Delivered-To:{WHITE} {BOLD}{msg['Delivered-To']}{WHITE}")
            print(f"{BLUE}[+]{WHITE} {GRN}Date:{WHITE} {BOLD}{msg['Date']}{WHITE}")
            print(f"{BLUE}[+]{WHITE} {GRN}Bcc:{WHITE} {BOLD}{msg['Bcc']}{WHITE}")
            print(f"{BLUE}[+]{WHITE} {GRN}Subject:{WHITE} {BOLD}{msg['Subject']}{WHITE}\n")

            #security checking headers
            print(f"{BLUE}[+]{WHITE} {GRN}Message-ID:{WHITE} {BOLD}{msg['Message-ID']}{WHITE}")
            print(f"{BLUE}[+]{WHITE} {GRN}X-Received:{WHITE} {BOLD}{msg['X-Received']}{WHITE}")
            print(f"{BLUE}[+]{WHITE} {GRN}Received:{WHITE} {BOLD}{msg['Received']}{WHITE}")
            print(f"{BLUE}[+]{WHITE} {GRN}Return Path:{WHITE} {BOLD}{msg['Return-Path']}{WHITE}")
            print(f"\n{BLUE}[+]{WHITE} {GRN}DKIM-Signature:{WHITE} {BOLD}{msg['DKIM-Signature']}{WHITE}\n")
            print(f"{BLUE}[+]{WHITE} {GRN}Authentication-Results:{WHITE} {BOLD}{msg['Authentication-Results']}{WHITE}\n")
            
            print(f"{BLUE}[+]{WHITE} {GRN}Received-SPF:{WHITE} {BOLD}{msg['Received-SPF']}{WHITE}")  #SPF
            print(f"{BLUE}[+]{WHITE} {GRN}Content-Type:{WHITE} {BOLD}{msg['Content-Type']}{WHITE}")

        except:
            pass

# <--- body analyzing scripts --->

#link shortening domain checker
def linkshortener(URL):
    domain = urllib.parse.urlparse(URL).netloc
    if 'tinyurl' or 'bitly' or 'rb' in domain:
        print(f'{RED}[!]{WHITE} URL Shortening Identified! --> {domain}')


#to be implemented
#checks the spellings
def spellcheck(file):
    with open (file) as fh:
        content = fh.read().split()

    #checking the spellings of each words
    for x in content:
        if x == TextBlob(x).correct():
            pass
        else:
            print(f'{RED}[!]{WHITE} Spelling Correction: {x} --> {BOLD}{TextBlob(x).correct()}{WHITE}')



#checks the protocol [https://www.example.com  --> https]
def checkprotocol(URL):
    pattern = r'^([a-zA-Z]+)://'   #protocol checking
    match = re.match(pattern, URL)

    if match:
        print(f'{BLUE}[!]{WHITE} Protocol: {BOLD}{match.group(1)}{WHITE}')
    else:
        pass


# urlxray.com [checks the redirection of the url]
def redirectto(URL):
    urlxraysearch = f'http://urlxray.com/display.php?url={URL}'
    urlxraypage = requests.get(urlxraysearch,headers=header)       #getting the html code of the page
    soup = BeautifulSoup(urlxraypage.content,'html.parser')  #beautifulsoup object
    destination_url = soup.find('div',class_='resultURL2').find_all('a')[0].get('href')  #extracting the redirected url
    
    if URL == destination_url:
        print(f'{GRN}[✔]{WHITE} Redirecting to same url --> {destination_url}')
        checkprotocol(destination_url)
    else:
        print(f'{RED}[!]{WHITE} Redirecting to --> {destination_url}')
        checkprotocol(destination_url)
        linkshortener(URL)


def email_reader(file):
    try:
        if file.endswith('.txt') or file.endswith('.eml'):
            with open(file) as fh:
                content = fh.read()
    except:
        sys.exit('[+] Invalid File Type')
    
    #url pattern
    url_pattern = re.compile(r'https?://\S+')

    #finding url
    url = url_pattern.findall(content)
    if len(url) > 0:
        for x in url:
            print(f'{RED}[!]{WHITE} URL Identified: {BOLD}{x}{WHITE}')
            redirectto(x)

    
if __name__ == '__main__':
    if sys.hexversion >= 0x03080000:
        
        #banner
        print()
        print(f'{GRN} ╔═╗┌─┐┌─┐┌─┐╔╦╗┌─┐┬┬   {WHITE}')
        print(f'{GRN} ╚═╗├─┤├┤ ├┤ ║║║├─┤││   {WHITE}')
        print(f'{GRN} ╚═╝┴ ┴└  └─┘╩ ╩┴ ┴┴┴─┘ {WHITE}')
        print('         -@Debang5hu SaifMail v1.0\n')


        #cli input:
        try:
            arguments=sys.argv[1:]
            args,null=getopt(arguments,"h:e:w:",["header=","email=","write="])

            for x,y in args:
                if x in ['-h','--header']:
                    headerfile = y
                if x in ['-e','--email']:
                    emailfile = y
                #if x in ['-w','--write']:

            
            #header analyzing
            print(f'\n{YLW}[[:]] Analyzing Email Header:{WHITE}\n')        
            obj = emailheaderanalyzer()  #init
            obj.basicemailinfo(headerfile)

            #body analyzing
            print(f'\n\n{YLW}[[:]] Analyzing Email Body:{WHITE}\n')
            email_reader(emailfile)
            
        except:
                print('''
Usage:  python3 main.py -h header.txt -e email.txt
                  
        -h $HEADERFILE  --header $HEADERFILE
        -e $EMAILFILE  --email $EMAILFILE''')

    else:
        print(f'{RED}[+]{WHITE} Required Python Version > 3.8!')
