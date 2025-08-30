#---------------MAIN IMPLEMENTATION--------------
#--------------STEVEN + HAO TASK-----------------
#----------------2/11/2024-----------------------
#
#
# REFERENCES: https://markuseliasson.se/article/bittorrent-in-python/
from users import *

import sys

import argparse

def main(user):
    print("IMPLEMENTATION")
    
    #TODO: Add the new user
    client = users(user)
    
    #TODO: Connect Tracker
    client.__connect_tracker__()
    
    #TODO: Get list of users(peers)
    client.__get_peers__()
    
    #TODO: Download file
    client.__download_file__()
    
if __name__ == '__main__':
    parser = argparse.ArgumentParser('Running to add argument')
    parser.add_argument(TORRENT_FILE_PATH, help='import file path of torrent')
    parser.add_argument("-d", "--" + DOWNLOAD_PATH, help = 'path of downloading')
    parser.add_argument("-u", "--" + UPLOAD_PATH, help = 'path of uploading')
    parser.add_argument("-mu", "--" + MAX_USERS, type=int ,help = 'max num of users')
    parser.add_argument("-mr", "--" + RATE_TRANSACTION, type = int,help = 'max rate of uploading and downloading')
    
    #* THIS LINE IS TO ANALYSIS THE INPUT OF THE USER
    __in4__ = vars(parser.parse_args(sys.argv[1:]))
    
    #* THIS LINE IS TO THROW THE ERRORS
    if (__in4__[DOWNLOAD_PATH] is None and __in4__[UPLOAD_PATH] is None):
        print('You should include the download path OR upload path')
        sys.exit()
        
    if (__in4__[MAX_USERS] > 10):
        print('The input users exceeds 10')
        sys.exit()
        
    if (__in4__[RATE_TRANSACTION] <= 0):
        print('The rate of exchanging must be larger than 0')
        sys.exit()
        
    main(__in4__)