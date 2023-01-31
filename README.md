## Domain Name Server Client ##

This python application is a domain name server client which allows to query for type A (IP address), MX (mail server) and NS (name server) records. It outputs the information of each record in the console. The Python version used 3.8.5

### How to use it? ###
In the command line, do the following command:  
`python DnsClient.py [-t timeout] [-r max-retries] [-p port] [-mx | -ns] @server name`  
  
where `-t` is a flag to specify the response timeout (Default value 5). `r` is a flag to specify the amount of times the program retries to query (Default value 3). `p` is a flag to specify a port to use (Default value 53). `-mx` is to specify a Mail Server type query while `-ns` is to specify a Name Server type query. These two flags cannot be used together, only one must be specified. If none are specified, the default value is a A type query.`@server` is the server IP address and `name` is the domain name to query.

Here is an example of a type A query using Google's DNS server for the mcgill.ca domain name.
![image](https://user-images.githubusercontent.com/63082166/215377957-04d9f645-09f5-4e57-8022-f94c0c5dedf3.png)


### Contributors
Dan Hosi 260984332  
Harsh Patel 260987849  


