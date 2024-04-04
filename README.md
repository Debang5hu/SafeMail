A Phishing Analyzer made in python 3.11  

---  

# Working  

It scans both the email header and the email body and collects informations  

### Email Header:  

1. It fetches the necessary and important details of the email like __Sender__,__DKIM-Signature__,__Authentication-Results__ and __Received-SPF__,etc   

### Email Body:  

1. It fetches all the url(http/https) present in the email and checks whether the link redirects to the same url or to any other site  
2. Tries to identify if any link shortening technique was used or not    
3. Checks the Protocol of the url 

 
---  
# Installation  

## Linux  
  
```
#clone the repo
git clone https://github.com/Debang5hu/SafeMail.git

#changind the directory
cd SafeMail

#install the requirements.txt
pip3 install -r requirements.txt

#to run
python3 main.py -h

```  
---  
# TO-DO  

1. To check for Spelling and grammatical mistakes in the body of the email  
2. To take decision whether the email is safe or not  
3. If any attachment is present then to scan its hash value against malicious hash[to identify whether the attachment is safe or not]

---  
*__PS__* : you need to have __python > 3.8__ to run the tool  


Contributions are most welcome ❤️ 
