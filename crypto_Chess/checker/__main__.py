from pwn import remote
import sys

if len(sys.argv) != 3:
    print(f"Usage: {sys.argv[0]} <host> <port>")
    sys.exit(1)
host, port = sys.argv[1], int(sys.argv[2])
io = remote(host, port)

from src.pseudorandom import XorShift128
from sage.all import *
import chess
from chess import Board, pgn
from collections import defaultdict
from Crypto.Util.number import bytes_to_long, long_to_bytes


STATE_DIM = 128

def emulate_leak():
    state0 = random.getrandbits(64)
    state1 = random.getrandbits(64)

    print(f"state0: {state0}")
    print(f"state1: {state1}")

    prng = XorShift128(state0, state1)

    leak = []

    for _ in range(512):
        r = random.getrandbits(64)

        if r % 2 == 0:
            bit = (prng.next())%2
        else: 
            prng.next()
            bit = None
        
        leak.append(bit)

    return leak

def symbolic_left_shift(v, n):
    return vector(list(v[n:]) + ([0]*n))

def symbolic_right_shift(v, n):
    return vector(([0]*n) + list(v[:-n]))

def symbolic_prng(state0, state1):
    s1 = state0
    s0 = state1
    state0 = s0

    #s1 ^= s1 << 23
    s1 = s1 + symbolic_left_shift(s1, 23)
    #s1 ^= s1 >> 17
    s1 = s1 + symbolic_right_shift(s1, 17)
    #s1 ^= s0
    s1 = s1 + s0
    #s1 ^= s0 >> 26
    s1 = s1 + symbolic_right_shift(s0, 26)

    state1 = s1

    return state0 , state1

class SymbolicXorShift128:
    
    def __init__(self, state0, state1):
        self.state0 = state0
        self.state1 = state1

    def next(self):
        self.state0, self.state1 = symbolic_prng(self.state0, self.state1)
        return self.state0 + self.state1


def recover_states(leak_vector):

    PR = BooleanPolynomialRing(STATE_DIM, "x") 
    x = PR.gens()

    state0 = vector(PR, x[0:64])
    state1 = vector(PR, x[64:128])
        
    sym_prng = SymbolicXorShift128(state0, state1)

    rows = []
    bs = []

    for i in range(len(leak_vector)):
        res = sym_prng.next()[-1] 
        res = [res.monomial_coefficient(x[j]) for j in range(STATE_DIM)]

        if leak_vector[i] is not None:
            rows.append(res)
            bs.append(leak_vector[i])
        
    A = matrix(GF(2), rows)
    b = vector(GF(2), bs)

    sol = A.solve_right(b)

    recovered_state0 = int("".join([str(int(i)) for i in sol[:64]]), 2)
    recovered_state1 = int("".join([str(int(i)) for i in sol[64:]]), 2)

    return recovered_state0, recovered_state1


def string_to_bits(s):
    binary_string = bin(bytes_to_long(s.encode()))[2:]

    padding_length = (8 - len(binary_string) % 8) % 8
    
    padded_binary_string = binary_string.zfill(len(binary_string) + padding_length)
    
    return padded_binary_string

def bits_to_string(b):
    return long_to_bytes(int(b, 2)).decode()


dic_tile_to_bits = { 
    f"{chr(col + ord('a'))}{8 - row}": f"{row % 2}{col % 2}"
    for row in range(8)
    for col in range(8)
}


dic_bits_to_tile = defaultdict(list)

for k, v in dic_tile_to_bits.items():
    dic_bits_to_tile[v].append(k)

dic_bits_to_tile = dict(dic_bits_to_tile)



def parse_pgns(pgns):
    game_strings =  [pgn[pgn.find("1."):] for pgn in pgns]

    list_of_ucis = []

    for game_string in game_strings:
        game_moves = game_string.split(" ")
        game_moves = [ move for move in game_moves if "." not in move ]
    
        #convert to uci 
        uci_moves = []
        chess_board = Board()
        for move in game_moves:
            if move == "*":
                chess_board = Board()
                break
            uci_moves.append(chess_board.parse_san(move).uci())
            chess_board.push_san(move)

        list_of_ucis.append(uci_moves)

    return list_of_ucis


def get_leaks_from_pgns(output_pgns):
    list_of_games_in_uci = parse_pgns(output_pgns)

    leaks = []
    for game in list_of_games_in_uci:
        chess_board = Board()
        for move in game:
            legal_moves = list(str(k) for k in list(chess_board.generate_legal_moves()))

            possible_moves = dic_bits_to_tile[dic_tile_to_bits[move[2:4]]]

            legal_possible_moves = [] 
        
            for legal_move in legal_moves:
                for encoding_move in possible_moves:
                    if (legal_move[2:4]) == encoding_move: 
                        legal_possible_moves.append(legal_move)

            leaked_bit= (legal_possible_moves.index(move))%2
            if(len(legal_possible_moves)%2 == 0 ):
                leaks.append(leaked_bit)
            else:
                leaks.append(None)
            chess_board.push(chess.Move.from_uci(move))

    return leaks

# requires a list of pgns, long enough, so it expects the pgns of the encoding of 300chars ideally
def solve_chall(games):

    players = [
    b"Magnus Carlsen", b"Hikaru Nakamura", b"Garry Kasparov", b"Bobby Fischer",
    b"Viswanathan Anand", b"Vladimir Kramnik", b"Fabiano Caruana", b"Ding Liren",
    b"Ian Nepomniachtchi", b"Anatoly Karpov", b"Mikhail Tal", b"Alexander Alekhine",
    b"Jose Raul Capablanca", b"Paul Morphy", b"Judith Polgar", b"Wesley So",
    b"Levon Aronian", b"Maxime Vachier-Lagrave", b"Sergey Karjakin", b"Shakhriyar Mamedyarov",
    b"Teimour Radjabov", b"Boris Spassky", b"Tigran Petrosian", b"Veselin Topalov",
    b"Peter Svidler", b"Anish Giri", b"Richard Rapport", b"Jan-Krzysztof Duda",
    b"Viktor Korchnoi", b"Bent Larsen", b"David Bronstein", b"Samuel Reshevsky",
    b"Efim Geller", b"Mikhail Botvinnik", b"Alexander Grischuk", b"Vassily Ivanchuk",
    b"Nigel Short", b"Michael Adams", b"Gata Kamsky", b"Ruslan Ponomariov",
    b"Vladimir Akopian", b"Peter Leko", b"Evgeny Bareev", b"Alexei Shirov",
    b"Vladimir Malakhov", b"Boris Gelfand", b"Vladimir Fedoseev", b"Daniil Dubov",
    b"Wei Yi", b"Alireza Firouzja", b"Vladislav Artemiev", b"Dmitry Andreikin", 
    b"Radoslaw Wojtaszek", b"Leinier Dominguez", b"Pentala Harikrishna", b"Sergey Movsesian",
    b"Ernesto Inarkiev", b"David Navara", b"Vladislav Kovalev", b"Jorden Van Foreest",
    b"Nihal Sarin", b"Vincent Keymer", b"Awonder Liang", b"Jeffery Xiong",
    b"Praggnanandhaa Rameshbabu", b"Raunak Sadhwani"]

    print("getting leaks...")

    leaks = get_leaks_from_pgns(games)

    print("recovering states...")

    recovered_state0, recovered_state1 = recover_states(leaks)

    #print(f"recovered state0: {hex(recovered_state0)}")
    #print(f"recovered state1: {hex(recovered_state1)}")

    print("running prng to align with leaks...")

    prng = XorShift128(recovered_state0, recovered_state1)

    for _ in range(len(leaks)):
        prng.next()

    print("predicting players...")

    predicted_players = []
    for _ in range(50):
        choice = prng.choice(players)
        predicted_players.append(choice)

    return predicted_players


def get_flag():

    print("sending random chars...")

    io.recvuntil(b"Enter your choice (1/2/3/4):")   
    io.sendline(b"1")
    io.recvuntil(b"Enter the string to encode (max 300 characters):")   
    io.sendline(b"A"*300)

    print("received games...")

    io.recvuntil(b"encoded pgns:\n")
    pgns = io.recvuntil(b"Invalid choice. Please try again.")
    pgns = pgns.replace(b"Invalid choice. Please try again.", b"")
    pgns = pgns.split(b"\n[Event")
    pgns = [pgn for pgn in pgns if pgn != b""]  
    pgns = [pgns[0]] + [b"[Event" + pgn for pgn in pgns[1:]]
    pgns = [game.strip().decode() for game in pgns]

    print("parsed games into pgn list...")

    predicted_players = solve_chall(pgns)

    io.recvuntil(b"Enter your choice (1/2/3/4):")
    io.sendline(b"3")

    print("sending predicted players...")

    for player in predicted_players:
        io.recvuntil(b"Which chess player am I thinking of?")
        io.sendline(player)

    io.recvuntil(b"Here is the flag ---> ")
    flag = io.recvline().strip().decode()

    print(f"flag: {flag}")

get_flag()