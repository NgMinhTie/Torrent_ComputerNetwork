import bencodepy
import sys
import hashlib
import urllib
import requests
import socket
import struct
from queue import Queue
from concurrent.futures import ThreadPoolExecutor, as_completed
from peer import Peer
from urllib.parse import unquote, quote
import threading
import os

socket_lock = threading.Lock()


PEER_ID = "00000000000000000001"
PORT = 6881
UPLOADED = 0
DOWNLOADED = 0
COMPACT = 1
MAX_PEERS = 10
peer_socket={}
client=[]
peer_swarm=[]

def decode_string(bencoded_value):
    first_colon_index = bencoded_value.find(b":")
    if first_colon_index == -1:
        raise ValueError("Invalid encoded value")
    length = int(bencoded_value[:first_colon_index].decode())
    start_index = first_colon_index + 1
    try:
        return bencoded_value[start_index:start_index + length].decode('utf-8'), bencoded_value[start_index+length:]
    except:
        return bencoded_value[start_index:start_index + length], bencoded_value[start_index+length:]
def decode_integer(bencoded_value):
    first_e_index = bencoded_value.find(b"e")
    if first_e_index == -1:
        raise ValueError("Invalid encoded value")
    decoded_string = bencoded_value[1:first_e_index].decode()
    return int(decoded_string), bencoded_value[first_e_index+1:]
def decode_list(bencoded_value):
    decoded_list = []
    i = 1
    while bencoded_value[i] != ord('e'):
        element, remaining = decode_bencode(bencoded_value[i:])
        decoded_list.append(element)
        i = len(bencoded_value) - len(remaining)
    
    return decoded_list, bencoded_value[i+1:]
def decode_dict(bencoded_value):
    decoded_dict = {}
    i = 1
    while bencoded_value[i] != ord('e'):
        key, remaining = decode_bencode(bencoded_value[i:])
        i = len(bencoded_value) - len(remaining)
        value, remaining = decode_bencode(bencoded_value[i:])
        i = len(bencoded_value) - len(remaining)
        decoded_dict[key] = value
    
    return decoded_dict, bencoded_value[i+1:]     
    
def decode_bencode(bencoded_value):
    if chr(bencoded_value[0]).isdigit():
        return decode_string(bencoded_value)
    elif chr(bencoded_value[0]) == 'i':
        return decode_integer(bencoded_value)
    elif chr(bencoded_value[0]) == 'l':
        return decode_list(bencoded_value)    
    elif chr(bencoded_value[0]) == 'd':
        return decode_dict(bencoded_value)      
    else:
        raise NotImplementedError("Only strings and numbers are supported at the moment")
def get_decoded_value(bencoded_file):
    f = open(bencoded_file, "rb")
    bencoded_value = f.read()
    f.close()
    decoded_value,_ = decode_bencode(bencoded_value)
    return decoded_value
def integer_to_byte(integer):
    return struct.pack('>I', integer)
def byte_to_integer(byte):
    return struct.unpack('>I', byte)[0]
def get_list_peer_magnet(tracker_url, info_hash_bytes):
    paras = {
            "info_hash": info_hash_bytes,
            "peer_id": "3a5f9c1e2d4a8e3b0f6c",
            "port": 6881,
            "uploaded": 0,
            "downloaded": 0,
            "left": 1024,
            "compact": 1
        }
    response = requests.get(tracker_url, params=paras)
    dicti = bencodepy.decode(response.content)
    # print(dicti)
    peers = dicti[b"peers"]
    # print(f"Peers in function get_list_peers: {peers}")
    peers_list = []
    index = 0
    #! QUESTION: THE ROLE OF THIS LOOP AND "!H"?
    while index < len(peers):
        peer_ip = peers[index:index+4]
        # DEBUG: print(peer_ip)
        index += 4
        IPv4 = socket.inet_ntoa(peer_ip)
        #DEBUG: print (IPv4)
        peer_port_bytes = peers[index:index+2]
        peer_port = struct.unpack("!H", peer_port_bytes)[0]
        #DEBUG: print(peer_port)
        #DEBUG: print("IPv4:", IPv4, "Port:", peer_port)
        index += 2
        peers_list.append((IPv4, peer_port))
        #DEBUG: print(peers_list)
    # print(peers_list)
    return peers_list
    pass
def get_meta_data(peer_ip, peer_port, info_hash_bytes, client_elemeent):
    client_id = client_elemeent.id
    print("DEBUG1")
    peer_id = '3a5f9c1e2d4a8e3b0f6c'
    handshake=(
        b"\x13BitTorrent protocol\x00\x00\x00\x00\x00\x10\x00\x00" 
        + info_hash_bytes + peer_id.encode()
    )   
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((peer_ip, int(peer_port)))
    s.send(handshake)
    s.recv(1)
    s.recv(19)
    s.recv(8)
    s.recv(20)
    s.recv(20)
    s.recv(4)
    s.recv(1)
    s.recv(4)
    print("DEBUG2")
    magnet_dict = {"m": {
        "ut_metadata": 18
    }}
    encoded_magnet_dict = bencodepy.encode(magnet_dict)
    s.sendall(integer_to_byte(len(encoded_magnet_dict) + 2))
    s.sendall(b'\x14')
    s.sendall(b'\x00')
    s.sendall(encoded_magnet_dict)
    print("DEBUG3")
    payload_size = byte_to_integer(s.recv(4)) - 2
    s.recv(1)
    s.recv(1)
    handshake_message = s.recv(payload_size)
    print("DEBUG4")
    request_metadata = {
        'msg_type': 0,
        'piece': 0
    }
    
    request_metadata = bencodepy.encode(request_metadata)
    s.sendall(integer_to_byte(len(request_metadata) + 2))
    s.sendall(b'\x14')
    s.sendall(b'\x00')
    s.sendall(request_metadata)
    print("DEBUG5")
    payload_size = byte_to_integer(s.recv(4)) - 2
    print("DEBUG 6")
    s.recv(1)
    s.recv(1)
    handshake_message = bencodepy.decode(s.recv(payload_size))
    print(handshake_message)
    pass
    handshake_info_dict = bencodepy.decode(handshake_message[1])[0]
    print("DEBUG6")

    print(handshake_info_dict)
    pass
def set_up_peer(peer_list, num_pieces):
    id = None
    index = 0
    for peer in peer_list:
        peer = Peer(id, num_pieces, peer[0],f"{index+1}" ,peer[1])
        peer_swarm.append(peer)
        index+=1
    # for peer in peer_swarm:
    #     print("Peer in peer_swarm", peer.ip, peer.port)

def download_file_command(client_element):
    output_file = f"C:/Users/Admin/Downloads/Like-Torrent_Ass1/Assignment1_ComputerNetworks-main/main/sample{client_element.id}.txt"
        
    #* SET UP A QUEUE
    #* SET UP A THREAD FOR EACH PEER
    #* CHECK VALID PIECE (QUEUE, HASH)
    #* ADD 
    torrent_content, _, hash_info = initial(sys.argv[2])
    pieces = torrent_content[b'info'][b'pieces']
    num_pieces = len(pieces) // 20
    peer_list = get_list_peers_connect_code(client_element)
    # 
    set_up_peer(peer_list, num_pieces)
    # print(num_pieces)
    index = 0
    queue_piece = Queue()
    while (index < num_pieces):
        queue_piece.put(index)
        index += 1
    # while (index > 0):
    #     front = queue_piece.get()
    #     index -= 1
    #     print(front)
    torrent_content, _, hash_info = initial(sys.argv[2])
    peers_bitfields=[]
    # print(f"PEER LIST {peer_list}")
    with ThreadPoolExecutor(MAX_PEERS) as executor:
        futures = [executor.submit(get_bitfilds, peer, hash_info, client_element) for peer in peer_swarm]
        for future in as_completed(futures):
            result_bitfield_string= future.result()
            
            if(result_bitfield_string):
                if(not len(result_bitfield_string[1]) == 0):
                    peers_bitfields.append(result_bitfield_string)
                    if(result_bitfield_string[0][1] == 51532):
                        print(f"Received handshake peer 1 from client {client_element.id}")
                    elif(result_bitfield_string[0][1] == 51556):
                        print(f"Received handshake peer 2 from client {client_element.id}")
                    elif(result_bitfield_string[0][1] == 51437):
                        print(f"Received handshake peer 3 from client {client_element.id}")
                # DEBUG: print(f"Handshake successful with {peer_ip}:{peer_port}, Peer ID: {s}")
                
            
            else:
                print(f"Handshake failed with")
    # download_file(queue_piece)
    # length_piece_bitfield = len(peers_bitfields)
    # index = 0
    # while(index < length_piece_bitfield):
    #     print(peers_bitfields[index])
    #     index+=1
    length_bitfield_string = len(peers_bitfields[0][1])
    # print(length_bitfield_string)  
    number_peers = len(peers_bitfields)
    # print(number_peers)
    
    index_peer_array = 0
    index_count_piece_array = 0
    
    count_piece_array=[] #![(index_piece, number_pieces)]
    peer_piece_array=[] #![(index_piece), ((peer_ip, peer_port))]
    while(index_count_piece_array < length_bitfield_string):
        count = 0
        peer_array = []
        while(index_peer_array < number_peers):
            if(peers_bitfields[index_peer_array][1][index_count_piece_array] == "1"):
                count+=1
                peer_array.append(peers_bitfields[index_peer_array][0])
            index_peer_array+=1
        count_piece_array.append((index_count_piece_array, count))
        peer_piece_array.append((index_count_piece_array, peer_array))
        index_peer_array = 0
        index_count_piece_array+=1
    # print(count_piece_array)
    # print(peer_piece_array)
    # print(sort_rarest_first(count_piece_array, peer_piece_array))
    rarest_piece_array = sort_rarest_first(count_piece_array, peer_piece_array)
    queue_piece = create_queue(rarest_piece_array, peer_piece_array)
    # print(queue_piece.qsize())
    #! CHECK THE EXISTENCE OF SOCKET
    # print(f"The whole value of peer_socket is {peer_socket}")
    # for key, value in peer_socket.items():
    #     print(f"This is the socket of {key[0]}:{key[1]}")
    num_pieces = queue_piece.qsize()
    with ThreadPoolExecutor(MAX_PEERS) as executor:
        futures = []
        # futures = [executor.submit(download_piece_rarest_first, socket_peer, queue_piece_ele, peer_piece_array) for socket_peer, queue_piece_ele in peer_socket, queue_piece.get()]
        
        # for socket_peer_key, socket_peer_value in peer_socket.items():
        while (not queue_piece.empty()):
            queue_piece_element = queue_piece.get()
            # print(queue_piece_element)
            futures.append(executor.submit(download_piece_rarest_first, queue_piece_element, peer_piece_array, peer_socket, num_pieces))
        #print(futures) #MY OUTPUT IS: []
        for future in as_completed(futures):
            content, piece_index = future.result()
            piece_length = torrent_content[b"info"][b"piece length"]
            if not os.path.exists(output_file):
                with open(output_file, 'wb') as f:
                    f.write(b'')  # Viết dữ liệu rỗng vào để tạo file
            with open(output_file, "r+b") as file:
                # if(front == num_pieces-1):
                #     piece_length = find_piece_length(torrent_content, front)
                # else: 
                #     piece_length = torrent_content[b"info"][b"piece length"]
                file.seek(piece_index* piece_length)
                file.write(content)
            # print("Finish piece number: ", piece_index)
    print("Finish integrating entire file")
    return 1, client_element.id
def bytes_to_str(raw_value):
    if isinstance(raw_value, bytes):
        return raw_value.decode()

# __tmp__ = bencodepy.Bencode(encoding="utf-8")
# def decode(raw_value):
#     raw_value = bytes_to_str(raw_value)
        
#     return __tmp__.decode(raw_value)
    

def get_list_peers_connect_code(client):
    torrent_content, _, hash_info = initial(sys.argv[2])
    left = torrent_content[b"info"][b"length"]
    tracker_url = torrent_content[b"announce"].decode()
    paras = {
        "info_hash": hash_info,
        "peer_id": client.id,
        "port": 6881,
        "uploaded": UPLOADED,
        "downloaded": DOWNLOADED,
        "left": left,
        "compact": COMPACT
    }
    response = requests.get(tracker_url, params=paras)
    dict= bencodepy.decode(response.content)
    peers = dict[b"peers"]
    print(f"Peers in function get_list_peers: {peers}")
    peers_list = []
    index = 0
    #! QUESTION: THE ROLE OF THIS LOOP AND "!H"?
    while index < len(peers):
        peer_ip = peers[index:index+4]
        # DEBUG: print(peer_ip)
        index += 4
        IPv4 = socket.inet_ntoa(peer_ip)
        #DEBUG: print (IPv4)
        peer_port_bytes = peers[index:index+2]
        peer_port = struct.unpack("!H", peer_port_bytes)[0]
        #DEBUG: print(peer_port)
        #DEBUG: print("IPv4:", IPv4, "Port:", peer_port)
        index += 2
        peers_list.append((IPv4, peer_port))
        #DEBUG: print(peers_list)
    print(f"Client: Received {len(peers_list)} peers ip and port successfully")
    return peers_list
    pass

def calculate_num_piece(torrent_content):
    pieces = torrent_content[b'info'][b'pieces']
    num_pieces = len(pieces) // 20
    return num_pieces
    pass
def find_piece_length(torrent_content, piece_index):
    file_length = torrent_content[b"info"][b"length"]
    piece_length = torrent_content[b"info"][b"piece length"]
    return file_length - (piece_length)*piece_index
    pass
def calculate_length_block(index_block, piece_length):
    current_number_block = index_block + 1
    if(piece_length - current_number_block*(2**14) < 0):
        return piece_length - (current_number_block-1)*(2**14)
    return 2**14
    pass
def calculate_num_block(piece_length):
    if(piece_length % (16*1024) != 0):
        return (piece_length // (16*1024)) + 1
    else:
        return (piece_length // (16*1024))

def receive_message(s):
    # print("Function receive_message")
    length = s.recv(4)
    # message_length = int.from_bytes(length)
    # print("Message length:", message_length)
    if not length or not int.from_bytes(length):
        length = s.recv(4)
    message = s.recv(int.from_bytes(length))
    while len(message) < int.from_bytes(length):
        message += s.recv(int.from_bytes(length) - len(message))
    return length + message



#!
#!
#!
###! THIS BLOCK IS TO DOWNLOAD PIECE

###! THIS BLOCK IS TO DOWNLOAD FILE
#!
#!
#!

    
#!
#!
#!
###! THIS BLOCK IS TO DOWNLOAD FILE

###! THIS BLOCK IS TO INITIAL
#!
#!
#!
def initial(file_path):
    file_path = sys.argv[2]
    with open(file_path, "rb") as file:
        torrent = file.read()
    torrent_content = bencodepy.decode(torrent)
    hash_info_hex = hashlib.sha1(bencodepy.encode(torrent_content[b"info"])).hexdigest()
    hash_info_dig = hashlib.sha1(bencodepy.encode(torrent_content[b"info"])).digest()
    
    return torrent_content, hash_info_hex, hash_info_dig
#!
#!
#!
###! THIS BLOCK IS TO INITIAL
def main():
    command = sys.argv[1]
    file_path = sys.argv[2]
    with open(file_path, "rb") as file:
        torrent = file.read()
    torrent_content = bencodepy.decode(torrent)
    hash_info_hex = hashlib.sha1(bencodepy.encode(torrent_content[b"info"])).hexdigest()
    hash_info_dig = hashlib.sha1(bencodepy.encode(torrent_content[b"info"])).digest()
    
    print("Tracker URL: ", torrent_content[b"announce"].decode())
    print("Length: ", torrent_content[b"info"][b"length"])
    print("Hash Info: ", hash_info_hex)
    print("Piece length: ", torrent_content[b"info"][b"piece length"])
    if command == "download_file":
        torrent_content, _, hash_info = initial(sys.argv[2])
        num_pieces = calculate_num_piece(torrent_content)
        
        #! EXAMPLE HAVING 3 PEERS
        
        client_element = Peer("00000000000000000001", num_pieces , None, 6881)
        client.append(client_element)
        
        
        # print(client[0].id, client[1].id, client[2].id)
        peer_list = get_list_peers_connect_code(client[0])
        # print(f"This is from client: {client.bit_field}")
        print(f"This is from connect code {peer_list}")
        with ThreadPoolExecutor(MAX_PEERS) as executor:
            futures = []
            for client_element in client:
                futures.append(executor.submit(download_file_command, client_element))

            for future in as_completed(futures):
                result, peer_id = future.result()
                if (result == 1):
                    print(f"Successful with {peer_id}")
                else:
                    print(f"Failed with {peer_id}")
        
    elif command == "download_file_concurrent":
        torrent_content, _, hash_info = initial(sys.argv[2])
        num_pieces = calculate_num_piece(torrent_content)
        
        #! EXAMPLE HAVING 3 PEERS
        
        client_element = Peer("00000000000000000001", num_pieces , None, 6881)
        client.append(client_element)
        
        # client_element = Peer("00000000000000000003", num_pieces ,None, 6882)
        # client.append(client_element)
        
        # client_element = Peer("00000000000000000004", num_pieces ,None, 6883)
        # client.append(client_element)
        
        # print(client[0].id, client[1].id, client[2].id)
        # peer_list = get_list_peers_connect_code(client[0])
        # print(f"This is from client: {client.bit_field}")
        # print(f"This is from connect code {peer_list}")
        with ThreadPoolExecutor(MAX_PEERS) as executor:
            futures = []
            for client_element in client:
                futures.append(executor.submit(download_file_command, client_element))

            for future in as_completed(futures):
                result, peer_id = future.result()
                if (result == 1):
                    print(f"Successful with {peer_id}")
                else:
                    print(f"Failed with {peer_id}")
        
    elif command == "magnet_parse":
        magnet_link = sys.argv[2]
        query_params = magnet_link[8:].split("&")
        params = dict()
        for p in query_params:
            key, value = p.split("=")
            params[key] = value
        info_hash = params["xt"][9:]
        tracker_url = unquote(params["tr"])
        # print(f"Tracker URL: {tracker_url}")
        # print(f"Info Hash: {info_hash}")
        info_hash_bytes = bytes.fromhex(info_hash)  # Chuyển từ hex sang bytes
        info_hash_encoded = quote(info_hash_bytes) 
        message_request = {
            "info_hash": info_hash_bytes,
            "peer_id": "3a5f9c1e2d4a8e3b0f6c",
            "port": 6881,
            "uploaded": 0,
            "downloaded": 0,
            "left": 1024,
            "compact": 1
        }
        response = requests.get(tracker_url, params=message_request)
        dicti = bencodepy.decode(response.content)
        peers = dicti[b"peers"]
        peers_list = []
        
        index = 0
    #! QUESTION: THE ROLE OF THIS LOOP AND "!H"?
        while index < len(peers):
            peer_ip = peers[index:index+4]
            # DEBUG: print(peer_ip)
            index += 4
            IPv4 = socket.inet_ntoa(peer_ip)
            #DEBUG: print (IPv4)
            peer_port_bytes = peers[index:index+2]
            peer_port = struct.unpack("!H", peer_port_bytes)[0]
            #DEBUG: print(peer_port)
            #DEBUG: print("IPv4:", IPv4, "Port:", peer_port)
            index += 2
            peers_list.append((IPv4, peer_port))
            #DEBUG: print(peers_list)
        # print(peers_list)
        peer_id, sock = tcpHandshake(
            info_hash=info_hash_bytes,
            ip=peers_list[0][0],
            port=peers_list[0][1],
            reserved_bytes=b"\x00\x00\x00\x00\x00\x10\x00\x00",
        )
        sock.recv(4)
        sock.recv(1)
        sock.recv(4)
        magnet_dict = {"m": {
                "ut_metadata": 18
            }}
            
        encoded_magnet_dict = bencodepy.encode(magnet_dict)
        sock.sendall(integer_to_byte(len(encoded_magnet_dict) + 2))
        sock.sendall(b'\x14')
        sock.sendall(b'\x00')
        sock.sendall(encoded_magnet_dict)
        
        payload_size = byte_to_integer(sock.recv(4)) - 2
        sock.recv(1)
        sock.recv(1)
        handshake_message = sock.recv(payload_size)
        
        request_metadata = {
            'msg_type': 0,
            'piece': 0
        }
        
        request_metadata = bencodepy.encode(request_metadata)
        sock.sendall(integer_to_byte(len(request_metadata) + 2))
        sock.sendall(b'\x14')
        sock.sendall(b'\x00')
        sock.sendall(request_metadata)
        payload_size = byte_to_integer(sock.recv(4)) - 2
        sock.recv(1)
        sock.recv(1)
        handshake_message = decode_bencode(sock.recv(payload_size))
        handshake_info_dict = decode_bencode(handshake_message[1])[0]
        print(f'Tracker URL: {tracker_url}')   
        print(f'Length: {handshake_info_dict['length']}')
        print(f'Info Hash: {info_hash}')
        print(f'Piece Length: {handshake_info_dict['piece length']}')
        print(f'Piece Hashes:')
        piece_hashes = handshake_info_dict['pieces'].hex()
        print(piece_hashes)
        return peers_list
def download_piece_rarest_first(queue_piece_element, peer_piece_array, peer_socket, num_pieces):
    piece_index_queue = queue_piece_element[0]
    peer_turple = peer_piece_array[piece_index_queue][1]
    torrent_content, _, hash_info = initial(sys.argv[2])

    # print(peer_socket)           
    if(piece_index_queue == 0):
        peer_socket_value = peer_socket[('165.232.35.114', 51437)]
    elif (piece_index_queue == 1):
        peer_socket_value = peer_socket[('165.232.38.164', 51532)]
    elif (piece_index_queue == 2):
        peer_socket_value = peer_socket[('165.232.41.73', 51556)]
    peer_element = peer_swarm[piece_index_queue]
    # print("We are downloading the piece number", piece_index_queue)
    interest_packet = struct.pack(">IB", 1, 2)
    peer_socket_value.send(interest_packet)
    message = receive_message(peer_socket_value)
    while True:
        if len(message) < 5:
            # print("Message too short, waiting for more data...")
            message = receive_message(peer_socket_value)
            continue

        if message[4] == 1:  # Unchoke
            # print("Peer has unchoked us!")
            break

        # print("Peer is still choking us. Retrying...")
        message = receive_message(peer_socket_value)
        
    peer_element.am_choking()
    # print("num_pieces", piece_index_queue)
    piece_length = torrent_content[b"info"][b"piece length"]
    if(piece_index_queue == num_pieces-1):
        piece_length = find_piece_length(torrent_content, piece_index_queue)
    
    num_block = calculate_num_block(piece_length)
        # print("num_blocks", num_block)
    begin_bytes_block = 0
    length_block = None
    index_block = 0
    data = None
    data = bytearray()


    while (index_block < num_block):

        # print("You are in the loop")
        length_block = calculate_length_block(index_block, piece_length)
        begin_bytes_block = index_block*(2**14)
        message_request = struct.pack(">IBIII", 13, 6, piece_index_queue, begin_bytes_block, length_block)
        # print(struct.unpack(">IBIII", message_request))
        peer_socket_value.send(message_request)
        # print("DEBUG 1")
        message = receive_message(peer_socket_value)
        # print("DEBUG 2")
        data.extend(message[13:])
        print(f"Finish downloading the block number {index_block} of the piece number {piece_index_queue}\n from the peer:{peer_element.name }")
        index_block+=1    
        # print("You are outside the loop")
    peer_element.am_unchoking()
    print(f"Finish piece number {piece_index_queue}")
    return data, piece_index_queue
def create_queue(rarest_piece_array, peer_piece_array):
    # print(rarest_piece_array)
    number_ele_count_piece_array = len(rarest_piece_array)
    queue_piece = Queue()
    index_count_piece_array = 0
    while(index_count_piece_array < number_ele_count_piece_array):
        if(rarest_piece_array[index_count_piece_array][1] == 0):
            index_count_piece_array+=1
            continue
        else:
            queue_piece.put(rarest_piece_array[index_count_piece_array])
        index_count_piece_array+=1
    # while(not queue_piece.empty()):
    #      print(queue_piece.get())
    print("Create queue for rarest first method")
    return queue_piece
def sort_rarest_first(count_piece_array, peer_piece_array):
    return sorted(count_piece_array, key=lambda x: x[1])
    pass
def handshake_each_peer(peer_ip, peer_port, client_element):
    torrent_content,_, hash_info = initial(sys.argv[2])
    client_id = client_element.id
    handshake = (
        b"\x13BitTorrent protocol\x00\x00\x00\x00\x00\x00\x00\x00"
        + hash_info + client_id.encode()
    )
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((peer_ip, int(peer_port)))
    s.send(handshake)
    if (peer_port == 51556):
        print(f"Finish sending handshake to peer: 1")
    elif (peer_port == 51532):
        print(f"Finish sending handshake to peer: 2")
    elif (peer_port == 51437):
        print(f"Finish sending handshake to peer: 3")
    return s

def get_bitfilds(peer , hash_info, client_element):
    peer_ip = peer.ip
    peer_port = peer.port
    
    s = handshake_each_peer(peer_ip, peer_port, client_element)
    with socket_lock:
        response = s.recv(68)
        message = receive_message(s)
    if (len(message) >= 5):
        while (message[4] != 5 ):
            # print("The system sent Bitfield ID")
            message = receive_message(s)
    length = int.from_bytes(message[0:4], 'big')
    # print(length)
    #! LENGTH CONSISTS 1 BYTE ID AND 1 BYTE PAYLOAD
    # i = 5
    # while (i < 4 + length):
    #     print(bin(message[i]))
    #     i+=1
    peer_socket[(peer_ip, peer_port)] = s
    # print("HELLO",''.join(format(byte, '08b') for byte in message[5:]))
    return (peer_ip, peer_port), ''.join(format(byte, '08b') for byte in message[5:])
def tcpHandshake(
    info_hash, ip, port, reserved_bytes=b"\x00\x00\x00\x00\x00\x00\x00\x00", timeout=5
):
    # info = bencodepy.encode(data[b'info'])
    # info_hash = hashlib.sha1(info).digest()
    """hanshake consist of 19+BitTorrent Protocol+8 zeros+info_hash+peerID"""
    handshake = (
        b"\x13"
        + b"BitTorrent protocol"
        + reserved_bytes
        + info_hash
        + b"01234567890123456789"
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(25)
    # with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.connect((ip, int(port)))
    sock.send(handshake)
    data = sock.recv(68)
    # sock.close()
    """ 48 because 1byte(19)+19bytes(BitTorrent Protocol)+8bytes(0's)+20bytes(info hash) then we have the peerID"""
    peer_id = data[48:].hex()
    # print("handshake : ",data[25]==0x10)
    # print("Peer ID:",peer_id)
    return peer_id, sock
if __name__ == "__main__":
    main()
#!     IPv4: 165.232.41.73 Port: 51556
#!     IPv4: 165.232.38.164 Port: 51532
#!     IPv4: 165.232.35.114 Port: 51437
