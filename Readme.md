# pyws

A simple Python WSMAN library using lxml and some AMT commandline utilities.

## AMT KVM VNCViewer launcher

This utility will start VNC server at a random TCP port, delay executes VNC client to connect to the specified random port, establish authenticated websocket redirection session to AMT system upon accepting VNC client connection, and then shuffles the packet between websocket and VNC connection.

```mermaid
sequenceDiagram
    VNC_Client ->> VNC_Server: VNC connect
    VNC_Server ->> AMT_Redirection: Digest authenticate /index.htm
    AMT_Redirection -->> VNC_Server: Digest session
    VNC_Server ->> AMT_Redirection: Websocket /ws-redirection with Digest
    AMT_Redirection -->> VNC_Server: successful connection
    VNC_Server ->> AMT_Redirection: Start KVM
    AMT_Redirection -->> VNC_Server: Redirection Reply
    VNC_Server ->> AMT_Redirection: Send empty Kerberos Auth
    AMT_Redirection -->> VNC_Server: Auth success
    VNC_Server ->> AMT_Redirection: Send direct
    AMT_Redirection -->> VNC_Server: Direct success + RFB protocol
    VNC_Server ->> VNC_Client: RFB protocol from AMT
    VNC_Client -> AMT_Redirection: VNC Server shuffles packets

```

## AMT SOL PuTTY launcher

This utility will start Telnet server at a random TCP port, delay executes PuTTY client to connect to the specified random port, establish authenticated websocket redirection session to AMT system upon accepting VNC client connection, and then shuffles the packet between websocket and Telnet connection.

```mermaid
sequenceDiagram
    PuTTY ->> Telnet_Server: Telnet connect
    Telnet_Server ->> AMT_Redirection: Digest authenticate /index.htm
    AMT_Redirection -->> Telnet_Server: Digest session
    Telnet_Server ->> AMT_Redirection: Websocket /ws-redirection with Digest
    AMT_Redirection -->> Telnet_Server: successful connection
    Telnet_Server ->> AMT_Redirection: Start SOL
    AMT_Redirection -->> Telnet_Server: Redirection Reply
    Telnet_Server ->> AMT_Redirection: Send empty Kerberos Auth
    AMT_Redirection -->> Telnet_Server: Auth success
    Telnet_Server ->> AMT_Redirection: Send SOL Terminal
    AMT_Redirection -->> Telnet_Server: Terminal setting
    
    loop Every 2 seconds
        Telnet_Server ->> AMT_Redirection: Send keepalive
    end 

    loop Shuffling Thread 1
        PuTTY ->> Telnet_Server: Terminal input
        Telnet_Server ->> Telnet_Server: Format SOL message
        Telnet_Server ->> AMT_Redirection: Send SOL message
    end

    loop Shuffling Thread 2
        AMT_Redirection ->> Telnet_Server: AMT SOL Message
        Telnet_Server ->> Telnet_Server: Filter only Terminal output
        Telnet_Server ->> PuTTY: Send Terminal output
    end
```