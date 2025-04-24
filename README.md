# Enumeration
Enumeration Techniques

# Explore Google hacking and enumeration 

# AIM:

To use Google for gathering information and perform enumeration of targets

## STEPS:

### Step 1:

Install kali linux either in partition or virtual box or in live mode

### Step 2:

Investigate on the various Google hacking keywords and enumeration tools as follows:


### Step 3:
Open terminal and try execute some kali linux commands

## Pen Test Tools Categories:  

Following Categories of pen test tools are identified:
Information Gathering.

Google Hacking:

Google hacking, also known as Google dorking, is a technique that involves using advanced operators to perform targeted searches on Google. These operators can be used to search for specific types of information, such as sensitive data that may have been inadvertently exposed on the web. Here are some advanced operators that can be used for Google hacking:

site: This operator allows you to search for pages that are within a specific website or domain. For example, "site:example.com" would search for pages that are on the example.com domain.
Following searches for all the sites that is in the domain yahoo.com

![1](https://github.com/user-attachments/assets/72193219-2516-4520-a47c-f369b93b7586)

filetype: This operator allows you to search for files of a specific type. For example, "filetype:pdf" would search for all PDF files.
Following searches for pdf file in the domain yahoo.com

![2](https://github.com/user-attachments/assets/cac6c0a9-fd80-4cd3-bcd8-33a3e5af6442)


intext: This operator allows you to search for pages that contain specific text within the body of the page. For example, "intext:password" would search for pages that contain the word "password" within the body of the page.

![3](https://github.com/user-attachments/assets/5cb84e3f-53ed-4a8c-8c00-9682a23a0017)


inurl: This operator allows you to search for pages that contain specific text within the URL. For example, "inurl:admin" would search for pages that contain the word "admin" within the URL.

![4](https://github.com/user-attachments/assets/d1c1e8e0-bc40-4159-801f-6d305ea96ace)

intitle: This operator allows you to search for pages that contain specific text within the title tag. For example, "intitle:index of" would search for pages that contain "index of" within the title tag.

![5](https://github.com/user-attachments/assets/bd19ed7c-0c78-4613-8988-c6fc9fb40880)

link: This operator allows you to search for pages that link to a specific URL. For example, "link:example.com" would search for pages that link to the example.com domain.

![6](https://github.com/user-attachments/assets/835b6b14-46cb-4c94-b380-1ecafb12d05b)

cache: This operator allows you to view the cached version of a page. For example, "cache:example.com" would show the cached version of the example.com website.

 ![7](https://github.com/user-attachments/assets/b6111872-a80e-4c45-be2b-ae9935436baf)

#DNS Enumeration


##DNS Recon
provides the ability to perform:
Check all NS records for zone transfers
Enumerate general DNS records for a given domain (MX, SOA, NS, A, AAAA, SPF , TXT)
Perform common SRV Record Enumeration
Top level domain expansion
## OUTPUT:

![8](https://github.com/user-attachments/assets/0b9df989-a540-4d84-a9d0-d211e2b5baad)

![9](https://github.com/user-attachments/assets/b8b565e4-c859-4482-836c-01b4f6e92929)





##dnsenum
Dnsenum is a multithreaded perl script to enumerate DNS information of a domain and to discover non-contiguous ip blocks. The main purpose of Dnsenum is to gather as much information as possible about a domain. The program currently performs the following operations:

Get the host’s addresses (A record).
Get the namservers (threaded).
Get the MX record (threaded).
Perform axfr queries on nameservers and get BIND versions(threaded).
Get extra names and subdomains via google scraping (google query = “allinurl: -www site:domain”).
Brute force subdomains from file, can also perform recursion on subdomain that have NS records (all threaded).
Calculate C class domain network ranges and perform whois queries on them (threaded).
Perform reverse lookups on netranges (C class or/and whois netranges) (threaded).
Write to domain_ips.txt file ip-blocks.
This program is useful for pentesters, ethical hackers and forensics experts. It also can be used for security tests.

![10](https://github.com/user-attachments/assets/cf323191-1095-448f-b01c-c15789c105ce)


##smtp-user-enum
Username guessing tool primarily for use against the default Solaris SMTP service. Can use either EXPN, VRFY or RCPT TO.

![11](https://github.com/user-attachments/assets/d5998451-57ac-406e-94ae-b5290906d5c5)


In metasploit list all the usernames using head /etc/passwd or cat /etc/passwd:

![12](https://github.com/user-attachments/assets/8d6230df-89f4-461a-96b2-640fb328ae78)

select any username in the first column of the above file and check the same

![13](https://github.com/user-attachments/assets/33bf0286-2e2d-4c84-9ecd-4abeb918c829)

#Telnet for smtp enumeration
Telnet allows to connect to remote host based on the port no. For smtp port no is 25
telnet <host address> 25 to connect
and issue appropriate commands
  
![14](https://github.com/user-attachments/assets/3a87762f-5b28-4370-a652-2a010e1df1d5)

  
  

## nmap –script smtp-enum-users.nse <hostname>

The smtp-enum-users.nse script attempts to enumerate the users on a SMTP server by issuing the VRFY, EXPN or RCPT TO commands. The goal of this script is to discover all the user accounts in the remote system.


## OUTPUT:
![15](https://github.com/user-attachments/assets/fe82dc88-83a8-484b-8e20-edc135eda72e)


## RESULT:
The Google hacking keywords and enumeration tools were identified and executed successfully

