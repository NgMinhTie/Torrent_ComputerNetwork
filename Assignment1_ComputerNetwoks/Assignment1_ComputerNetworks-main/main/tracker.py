import struct
import peer

import requests
import logging
from bcoding import bdecode
import socket
from torrent import Torrent

MAX_PEERS_TRY_CONNECT = 30
MAX_PEERS_CONNECTED = 8

class SockAddr:
    def __init__(self, ip, port, allowed=True):
        self.ip = ip
        self.port = port
        self.allowed = allowed

    def __hash__(self):
        return "%s:%d" % (self.ip, self.port)


class Tracker(object):
    def __init__(self, torrent):
        self.torrent = [torrent]
        self.threads_list = []
        self.connected_peers = {}
        self.dict_sock_addr = {}

    def get_peers_from_trackers(self):
        self.send_tracker_request('started')
        self.try_peer_connect()
        return self.connected_peers

    
    # def find_torrent(self):
    #     file_require = sys.argv[2]
        
    #     pass
    def send_tracker_request(self, event):
        for i, tracker in enumerate(self.torrent.announce_list):
            if len(self.dict_sock_addr) >= MAX_PEERS_TRY_CONNECT:
                break

            tracker_url = tracker[0]

            if str.startswith(tracker_url, "http"):
                try:
                    self.http_scraper(self.torrent, tracker_url, event)
                except Exception as e:
                    logging.error("HTTP scraping failed: %s " % e.__str__())
            else:
                logging.error("unknown scheme for: %s " % tracker_url)

    def try_peer_connect(self):
        logging.info("Trying to connect to %d peer(s)" % len(self.dict_sock_addr))

        for _, sock_addr in self.dict_sock_addr.items():
            if len(self.connected_peers) >= MAX_PEERS_CONNECTED:
                break

            new_peer = peer.Peer(int(self.torrent.number_of_pieces), sock_addr.ip, sock_addr.port)
            if not new_peer.connect():
                continue

            self.connected_peers[new_peer.__hash__()] = new_peer
            print('Connected to %d/%d peers' % (len(self.connected_peers), MAX_PEERS_CONNECTED))

    def http_scraper(self, torrent, tracker, event):
        params = {
            'info_hash': torrent.info_hash,
            'peer_id': torrent.peer_id,
            'uploaded': 0,
            'downloaded': 0,
            'port': 6881,
            'left': torrent.total_length,
            'event': event
        }

        try:
            answer_tracker = requests.get(tracker, params=params, timeout=5)
            list_peers = bdecode(answer_tracker.content)

            if 'failure reason' in list_peers:
                logging.error("Tracker error: %s" % list_peers['failure reason'])
                return

            if 'warning message' in list_peers:
                logging.warning("Tracker warning: %s" % list_peers['warning message'])

            if 'tracker id' in list_peers:
                self.tracker_id = list_peers['tracker id']

            index = 0
            if not type(list_peers['peers']) == list:
                for _ in range(len(list_peers['peers'])//6):
                    ip = struct.unpack_from("!i", list_peers['peers'], index)[0]
                    ip = socket.inet_ntoa(struct.pack("!i", ip))
                    index += 4
                    port = struct.unpack_from("!H",list_peers['peers'], index)[0]
                    index += 2
                    s = SockAddr(ip,port)
                    self.dict_sock_addr[s.__hash__()] = s
            else:
                for p in list_peers['peers']:
                    s = SockAddr(p['ip'], p['port'])
                    self.dict_sock_addr[s.__hash__()] = s

        except Exception as e:
            logging.exception("HTTP scraping failed: %s" % e.__str__())

    def stop(self):
        self.send_tracker_request('stopped')

    def complete(self):
        self.send_tracker_request('completed')

# def main():
#     t = Torrent()
#     path_1 = "torrent_file/sample.torrent"

#     torrent = t.load_from_path(path_1)

#     tracker = Tracker(torrent)

#     tracker_response = tracker.get_peers_from_trackers()
#     for peer_hash, peer in tracker_response.items():
#         print(f"Connected to peer: {peer_hash} - IP: {peer.ip} - Port: {peer.port}")

#     print(tracker.torrent.announce_list)

#     tracker.complete()
#     tracker.stop()

# if __name__ == "__main__":
#     main()