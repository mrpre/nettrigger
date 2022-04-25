# Nettrigger  
A trigger wihch can generate choreographed TCP packets to Remote include PAWS.  

# Preparation  
Preparation for Client(especially IPtables command) and Server can be found by annotation of each function

# Build 
`make`  

# usage  
`sudo ./nettrigger  --help`

# Example  
If you want PAWS happended in Server 2.2.2.2 

Client Preparation
```
sudo iptables -t filter -I OUTPUT -p tcp --sport 12345 --tcp-flags RST RST -j DROP
```  

Send Tcp Packet  
```  
# assume the Address of eth0 is 1.1.1.1 and the 12345 is what you want use  
# assume server address is 2.2.2.2 whose HTTP server run on 9999
sudo ./nettrigger -i eth0 -s 1.1.1.1:12345 -d 2.2.2.2:9999 -action paws
```  
It will first generate TCP connection with Establish for Server, then send BAD HTTP content(Default content is "474554202f20485454502f312e310d0a0d0a", `-d "your hex data"` could be used if you want) 
Then Server close the connection with 4-way handshake. Finally Client send choreographed TCP SYN packet to make PAWS happen.  

