# Nettrigger  
A trigger which can generate custom TCP packets to Remote include PAWS.  

# Preparation  
Preparation for Client(especially IPtables command) and Server can be found by annotation of each function

# Build 
`make`  

# usage  
`sudo ./nettrigger  --help`

# Example  
The following command will generate PAWS at remote Server 2.2.2.2:9999. 

Client Preparation
```
sudo iptables -t filter -I OUTPUT -p tcp --sport 12345 --tcp-flags RST RST -j DROP
```  
We will use 12345 as client port and do now want kernel stack to answer it.  

Server:  
```
python3 -m http.server 9999
```

Trigger PAWS  
```
# assume the client address is 1.1.1.1:12345 where 1.1.1.1 is the address of eth0  
# assume a http server listening on 2.2.2.2:9999
sudo ./nettrigger -i eth0 -s 1.1.1.1:12345 -d 2.2.2.2:9999 -action paws
```  
Client will first generate Full handshake with Server, then send BAD HTTP content(Default content is "474554202f20485454502f312e310d0a0d0a", `-d "your hex data"` could be used if you want) 
Then Server closes the connection with 4-way handshake and enter TIME_WAIT state.  

Finally client will send TCP SYN packet with choreographed TS to generate PAWS on Server.  

