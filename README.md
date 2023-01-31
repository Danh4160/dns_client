## Domain Name Server Client ##

This python application is a domain name server client which allows to query for type A (IP address), MX (mail server) and NS (name server) records. It outputs the information of each record in the console. This program is written by Dan Hosi and Harsh Patel.

### How to use it? ###
In the command line, do the following command:  
`python DnsClient.py [-t timeout] [-r max-retries] [-p port] [-mx | -ns] @server name`  

Here is an example of a type A query using Google's DNS server for the mcgill.ca domain name.
![image](https://user-images.githubusercontent.com/63082166/215377957-04d9f645-09f5-4e57-8022-f94c0c5dedf3.png)

