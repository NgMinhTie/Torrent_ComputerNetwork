import logging
import socket
import time
import struct
import message

def serve_piece(peer, piece_index, block_offset, block_data):
    """
    Serve a specific piece to the peer.

    :param peer: Peer object
    :param piece_index: Index of the requested piece
    :param block_offset: Offset of the block in the piece
    :param block_data: Data of the requested block
    """
    try:
        piece_message = message.Piece(piece_index, block_offset, block_data).to_bytes()
        peer.send_to_peer(piece_message)
        logging.debug(f"Sent piece {piece_index}, offset {block_offset} to {peer.ip}")
    except Exception as e:
        logging.error(f"Failed to send piece to peer {peer.ip}: {e}")


def handle_piece_requests(peer, torrent_data):
    """
    Handle incoming piece requests from a peer.

    :param peer: Peer object
    :param torrent_data: A dictionary containing pieces of the torrent
                         (e.g., {piece_index: [block1, block2, ...]})
    """
    try:
        for msg in peer.get_messages():
            if isinstance(msg, message.Request):
                piece_index = msg.piece_index
                block_offset = msg.block_offset
                block_length = msg.block_length

                # Get the block data
                if piece_index in torrent_data:
                    block_data = torrent_data[piece_index][block_offset:block_offset + block_length]
                    serve_piece(peer, piece_index, block_offset, block_data)
                else:
                    logging.warning(f"Peer {peer.ip} requested invalid piece {piece_index}.")
    except Exception as e:
        logging.error(f"Error handling requests from {peer.ip}: {e}")


def upload_torrent_to_peer(peer_class, peer_ip, peer_port, torrent_data):
    """
    Initiate the torrent upload process to a peer.

    :param peer_class: The Peer class or its compatible implementation
    :param peer_ip: IP address of the peer
    :param peer_port: Port of the peer
    :param torrent_data: A dictionary containing pieces of the torrent
                         (e.g., {piece_index: [block1, block2, ...]})
    """
    peer = peer_class(len(torrent_data), peer_ip, peer_port)
    if peer.connect():
        logging.info(f"Connected to peer {peer.ip}:{peer.port}. Starting upload...")
        try:
            while peer.healthy:
                handle_piece_requests(peer, torrent_data)
        except KeyboardInterrupt:
            logging.info("Stopping upload due to interruption.")
        except Exception as e:
            logging.error(f"Error during upload to {peer.ip}: {e}")
    else:
        logging.error(f"Failed to connect to peer {peer_ip}:{peer_port}.")


def split_into_blocks(piece, block_size=16384):
    """
    Split a torrent piece into smaller blocks.

    :param piece: The complete data of the piece
    :param block_size: The size of each block (default is 16KB)
    :return: List of blocks
    """
    return [piece[i:i + block_size] for i in range(0, len(piece), block_size)]

# unchoke, interest
# choke, not_interested