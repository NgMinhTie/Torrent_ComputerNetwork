#-------------STEVEN + HAO TASK------------------
#----------------2/11/2024-----------------------
#------------------USERS-------------------------
#
#
# REFERENCES: https://markuseliasson.se/article/bittorrent-in-python/
import sys
from readTorrentFIle import readTorrentFile
from tracker import __tracker__
from torrent import *

TORRENT_FILE_PATH = '__torrent_file_path__'
DOWNLOAD_PATH = '__download_path__'
UPLOAD_PATH = '__upload_path__'
MAX_USERS = '__max_users__'
RATE_TRANSACTION = '__rate_transaction__'

class users():
    def __init__(self, user):
        print("IMPLEMENTATION")
        
        __torrent_path__ = user[TORRENT_FILE_PATH]
        
        self.__in4_torrent__ = readTorrentFile(__torrent_path__)
        
        self.__init_req__ = {
            'uploading': None,
            'downloading': None,
            'upload_rate': 50,
            'download_rate': 50,
            'max_peers': 10
        }
        
        #TODO: Assign value
        if (user[DOWNLOAD_PATH] is not None):
            self.__init_req__['downloading'] = user[DOWNLOAD_PATH]
            if(user[RATE_TRANSACTION] is not None):
                self.__init_req__['download_rate'] = (int) (user[RATE_TRANSACTION])
        elif (user[UPLOAD_PATH] is not None):
            self.__init_req__['uploading'] = user[UPLOAD_PATH]
            if(user[RATE_TRANSACTION] is not None):
                self.__init_req__['upload_rate'] = (int) (user[RATE_TRANSACTION])
                
        if (user[MAX_USERS] is not None):
            self.__init_req__['max_peers'] = (int) (user[MAX_USERS])
            
        self.torrent = torrent(self.__in4_torrent__.get_data(), self.__init_req__)
    def __connect_tracker__(self):
        print("We are trying to connect Tracker...")
        
        #TODO: Get tracker
        self.__tracker__ = __tracker__(self.torrent)
        
        
    def __get_peers__(self):
        print("IMPLEMENTATION")
        __peer_list__ = self.__tracker__.__peer_list__()
        
#------------------------------------------------------------
#------------EXTRA CREDIT: RAREST-FIRST----------------------
    def __download_file__(self):
        print("IMPLEMENTATION")
        
    def __upload_file__(self):
        print("IMPLEMENTATION")