import chess
from chess import Board
from Crypto.Util.number import long_to_bytes

dic_tile_to_bits = { 
    f"{chr(col + ord('a'))}{8 - row}": f"{row % 2}{col % 2}"
    for row in range(8)
    for col in range(8)
}

def bits_to_string(b):
    return long_to_bytes(int(b, 2)).decode()

def parse_pgns(pgn_list):
    list_of_ucis = []
    for pgn in pgn_list:
        chess_board = Board()
        uci_moves = []
        moves = pgn.split()
        for move in moves:
            if move and not move[0].isdigit() and move != "*":
                try:
                    uci_moves.append(chess_board.parse_san(move).uci())
                    chess_board.push(chess.Move.from_uci(uci_moves[-1]))
                except chess.InvalidMoveError:
                    continue
        list_of_ucis.append(uci_moves)
    return list_of_ucis

def decode_from_pgn(pgn_list):
    bits = ""
    
    list_of_ucis = parse_pgns(pgn_list)

    for uci_moves in list_of_ucis:
        for uci_move in uci_moves:
            bits += dic_tile_to_bits[uci_move[2:4]]

    return bits_to_string(bits)

def input_and_parse_pgns():
    print("Enter the PGN games. Include all the details about the game. Type 'END' on a new line to finish input.")
    pgn_input = []
    while True:
        line = input()
        if line.strip() == "END":
            break
        pgn_input.append(line)
    
    pgn_string = "\n".join(pgn_input)
    pgn_games = pgn_string.split("\n\n[Event")
    
    # Add the '[Event' back to each game except the first one
    pgn_games = [pgn_games[0]] + ["[Event" + game for game in pgn_games[1:]]
    pgn_games= pgn_games[0].split("*\n")
    return pgn_games
