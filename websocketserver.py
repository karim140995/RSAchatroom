import asyncio
import json
import websockets
# The set of clients connected to this server. It is used to distribute
# messages.
clients = {} #: {websocket: name}

@asyncio.coroutine
def client_handler(websocket, path):
    print('New client', websocket)
    print(' ({} existing clients)'.format(len(clients)))

    # The first line from the client is the name
    name = yield from websocket.recv()

    messageObj = {}
    messageObj["from"]= "System"
    messageObj["message"] = 'Welcome to websocket-chat, {}'.format(name)
    yield from websocket.send(json.dumps(messageObj))
    messageObj["message"] = 'There are {} other users connected: {}'.format(len(clients), list(clients.values()))
    try :
        yield from websocket.send(json.dumps(messageObj))
    except websockets.exceptions.ConnectionClosed :
        del clients[websocket]
        
    clients[websocket] = name
    for client, _ in clients.items():
        messageObj["message"] = name + ' has joined the chat'
        try : 
            yield from client.send(json.dumps(messageObj))
        except websockets.exceptions.ConnectionClosed :
            del clients[websocket]
    destination = path.replace("/","")
    # Handle messages from this client
    while True:
        try : 
            message = yield from websocket.recv()
        except websockets.exceptions.ConnectionClosed :
            del clients[websocket]
        if message is None:
            their_name = clients[websocket]
            del clients[websocket]
            for client, _ in clients.items():
                 messageObj["message"] = their_name + ' has left the chat'
                 yield from client.send(json.dumps(messageObj))
            break
        
        # Send message to all clients
        for client, _ in clients.items():
            messageObj = {}
            print(message)
            messageRcv = json.loads(message)
            if( _ ==  messageRcv['to']) :
                messageObj["from"] = name
                messageObj["message"]= messageRcv["message"]
                try :
                    yield from client.send(json.dumps(messageObj))
                except  websockets.exceptions.ConnectionClosed :
                    del clients[websocket]


                
