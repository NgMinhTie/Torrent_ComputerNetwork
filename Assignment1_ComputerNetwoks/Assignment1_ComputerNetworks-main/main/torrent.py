#--------------------TORRENT FILES-----------------------
#--------------------DATE: 2/11/2024 --------------------
#
#
#
#REFERENCES: https://markuseliasson.se/article/bittorrent-in-python/

import math
import hashlib
import time
from bcoding import bencode, bdecode
from urllib.parse import urlparse, parse_qs
import os

class Torrent(object):
    def __init__(self):
        self.torrent_file = {}
        self.total_length: int = 0
        self.piece_length: int = 0
        self.pieces: int = 0
        self.info_hash: str = ''
        self.peer_id: str = ''
        self.announce_list = ''
        self.file_names = []
        self.number_of_pieces: int = 0

    def load_from_path(self, path):
        with open(path, 'rb') as file:
            contents = bdecode(file)

        self.torrent_file = contents
        self.piece_length = self.torrent_file['info']['piece length']
        self.pieces = self.torrent_file['info']['pieces']
        raw_info_hash = bencode(self.torrent_file['info'])
        self.info_hash = hashlib.sha1(raw_info_hash).digest()
        self.peer_id = self.generate_peer_id()
        self.announce_list = self.get_trackers()
        self.init_files()
        self.number_of_pieces = math.ceil(self.total_length / self.piece_length)
        
        assert(self.total_length > 0)
        assert(len(self.file_names) > 0)

        return self

    def init_files(self):
        root = self.torrent_file['info']['name']

        if 'files' in self.torrent_file['info']:
            if not os.path.exists(root):
                os.mkdir(root, 0o0766 )

            for file in self.torrent_file['info']['files']:
                path_file = os.path.join(root, *file["path"])

                if not os.path.exists(os.path.dirname(path_file)):
                    os.makedirs(os.path.dirname(path_file))

                self.file_names.append({"path": path_file , "length": file["length"]})
                self.total_length += file["length"]

        else:
            self.file_names.append({"path": root , "length": self.torrent_file['info']['length']})
            self.total_length = self.torrent_file['info']['length']

    @property
    def announce(self) -> str:
        if 'announce-list' in self.torrent_file:
            return bdecode(self.torrent_file['announce-list'])
        return self.torrent_file['announce']
    
    def get_trackers(self):
        trackers = []
        if 'announce-list' in self.torrent_file:
            for tier in self.torrent_file['announce-list']:
                filtered_tier = [url for url in tier if url.startswith('http://')]
                if filtered_tier:
                    trackers.append(filtered_tier)
        elif 'announce' in self.torrent_file:
            if self.torrent_file['announce'].startswith('http://'):
                trackers.append([self.torrent_file['announce']])
        return trackers

    def generate_peer_id(self):
        seed = str(time.time())
        return hashlib.sha1(seed.encode('utf-8')).digest()
