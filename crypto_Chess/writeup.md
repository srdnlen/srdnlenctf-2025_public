# CHESS CHALLENGE Writeup

## Understanding the Challenge

The source code for the CHESS CHALLENGE is divided into several files, but it is relatively concise. The main menu offers three options: encoding arbitrary strings into chess games, decoding them or playing a trivia game with the bot.

### Exploring the Trivia Game

Let's first explore the trivia game option. When selecting this option, you are prompted to guess the name of a chess player. However, there is no guidance on how to guess correctly. If you guess incorrectly, the service terminates.

By examining the `trivia.py` file, we discover that the trivia game can only be won by correctly guessing the names of 50 chess players in a row. The players are chosen randomly using a `choice()` function from a pseudorandom number generator (PRNG).

```python
def trivia(prng):
    for _ in range(50):
        choice = prng.choice(players)
        print("Which chess player am I thinking of?")
        if input() == choice:
            print("Well done!")
        else:
            print("Skill issue")
            exit(1)
            return 
    else: 
        print("Here is the flag ---> ", FLAG)
        exit(1)
```

The pool of possible players is extensive, making a brute-force approach impractical.


### Analyzing the PRNG

In the `pseudorandom.py` file, we find the implementation of the xorshift128 and two methods utilized in the challenge.

```python
def xorshift128(state0, state1):
    s1 = state0
    s0 = state1
    state0 = s0
    s1 ^= s1 << 23 
    s1 &= 0xFFFFFFFFFFFFFFFF
    s1 ^= s1 >> 17
    s1 ^= s0
    s1 ^= s0 >> 26
    state1 = s1
    return state0 & 0xFFFFFFFFFFFFFFFF, state1 & 0xFFFFFFFFFFFFFFFF

    
```

```python
    def next(self):
        self.state0, self.state1 = xorshift128(self.state0, self.state1)
        return self.state0 + self.state1

    def choice(self, l):
        return l[self.next() % len(l)]
```

### Encoding a String to PGN

The first option in the menu allows us to encode a string into chess games. While most of the encoding logic in the `encode_to_pgn_2bit.py` file is not directly relevant to solving the challenge, key details are highlighted below.

#### The Encoding Process

The `encode_to_pgn_2bit.py` file begins with some imports and the preparation of dictionaries that map specific bits to chess moves.

```python
dic_tile_to_bits = { 
    f"{chr(col + ord('a'))}{8 - row}": f"{row % 2}{col % 2}"
    for row in range(8)
    for col in range(8)
}

# Inverse dictionary with lists to handle duplicates
dic_bits_to_tile = defaultdict(list)

for k, v in dic_tile_to_bits.items():
    dic_bits_to_tile[v].append(k)
    
dic_bits_to_tile = dict(dic_bits_to_tile)
```

By examining the dictionaries, we observe that the chessboard is divided into smaller 2x2 squares, with each tile encoding two bits.

```console
{'a8': '00', 'b8': '01', 'c8': '00', 'd8': '01', 'e8': '00', 'f8': '01', 'g8': '00', 'h8': '01',
 'a7': '10', 'b7': '11', 'c7': '10', 'd7': '11', 'e7': '10', 'f7': '11', 'g7': '10', 'h7': '11',
 'a6': '00', 'b6': '01', 'c6': '00', 'd6': '01', 'e6': '00', 'f6': '01', 'g6': '00', 'h6': '01', 
 'a5': '10', 'b5': '11', 'c5': '10', 'd5': '11', 'e5': '10', 'f5': '11', 'g5': '10', 'h5': '11', 
 'a4': '00', 'b4': '01', 'c4': '00', 'd4': '01', 'e4': '00', 'f4': '01', 'g4': '00', 'h4': '01', 
 'a3': '10', 'b3': '11', 'c3': '10', 'd3': '11', 'e3': '10', 'f3': '11', 'g3': '10', 'h3': '11', 
 'a2': '00', 'b2': '01', 'c2': '00', 'd2': '01', 'e2': '00', 'f2': '01', 'g2': '00', 'h2': '01', 
 'a1': '10', 'b1': '11', 'c1': '10', 'd1': '11', 'e1': '10', 'f1': '11', 'g1': '10', 'h1': '11'}
```
```console
{'00': ['a8', 'c8', 'e8', 'g8', 'a6', 'c6', 'e6', 'g6', 'a4', 'c4', 'e4', 'g4', 'a2', 'c2', 'e2', 'g2'],
 '01': ['b8', 'd8', 'f8', 'h8', 'b6', 'd6', 'f6', 'h6', 'b4', 'd4', 'f4', 'h4', 'b2', 'd2', 'f2', 'h2'],
 '10': ['a7', 'c7', 'e7', 'g7', 'a5', 'c5', 'e5', 'g5', 'a3', 'c3', 'e3', 'g3', 'a1', 'c1', 'e1', 'g1'],
 '11': ['b7', 'd7', 'f7', 'h7', 'b5', 'd5', 'f5', 'h5', 'b3', 'd3', 'f3', 'h3', 'b1', 'd1', 'f1', 'h1']}
```

In the encoding function, the input string is converted to its binary representation, which is then processed two bits at a time. For each pair of bits, the function intersects the legal moves from the current position with the moves that can encode the given pair of bits.

```python
legal_possible_moves = [ legal_move for legal_move in legal_moves if legal_move[2:4] in possible_moves ]
```

The result is a list of moves in UCI format (where the starting and ending positions of the moved pieces are explicitly stated). It is important to note that not every part of a move encodes bits; only the arrival square of the move is used for encoding the bits.

Here's an example of a list of possible moves that encode the same two bits:
```python
['h2h4', 'f2f4', 'd2d4', 'b2b4']
```

The function proceeds by selecting a random move from the list or starting a new game if no suitable moves are available to encode the specific bits. This process continues until all bits are encoded, and the function returns a list of games in PGN format.

## The Flaw

By examining the `main.py` file, we notice that the same PRNG is used for both the encoding process and the trivia game. By understanding the encoding mechanism and extracting some data from it, we can attempt to recover the state of the PRNG. This knowledge can then be leveraged to predict the trivia game outcomes and win the game.


### Understanding the leak process

Our objective is to recover the initial state of the PRNG. To achieve this, we need to construct a system of equations that involve the unknown initial state.
The xorshift128 is a bit-based PRNG, which allows us to express its update function as a series of linear equations based on the symbolic variables of the initial state.
The XorShift128.next method updates the state and returns the sum of the two current states. However, the addition operation introduces a carry, making it non-linear in terms of bit operations. Consequently, the only linear bit we can reliably extract is the least significant bit (LSB).

By examining the XorShift128.choice method, we can retrieve the PRNG outputs modulo the length of the input list.
It is important to note that not every output is useful for recovering the state. Specifically, we cannot obtain information about the LSB when using the choice function with a list of odd length. This is because the distribution of even and odd indices in such lists does not provide a clear indication of the LSB.

### Explanation

When using a pseudorandom number generator (PRNG) to select an item from a list, the PRNG generates a random number that is used to index into the list. The least significant bit (LSB) of this random number can be either 0 or 1, which affects whether the index is even or odd.

#### Even-Length List

For a list of even length, every possible index can be either even or odd. This means that the LSB of the random number used to index into the list can be directly inferred from the index:
- If the index is even, the LSB is 0.
- If the index is odd, the LSB is 1.

#### Odd-Length List

For a list of odd length, the distribution of even and odd indices is not balanced. There is one more even index than odd indices (or vice versa). This imbalance means that the LSB of the random number cannot be reliably inferred from the index:
- The PRNG might generate a number with an LSB of 0, but the corresponding index might still be odd due to the wrapping around of the list length.
- Similarly, the PRNG might generate a number with an LSB of 1, but the corresponding index might be even.

When using the `choice` function over a list of odd length, the LSB of the random number used by the PRNG cannot be reliably inferred from the index. This means that not every output is significant for the retrieval of the state, as the LSB information is lost in the process.

## The leak process

To efficiently recover the bits, we need to play out the games we get as output to be able to track the choices made along the process. 
In the following code we first parse all the games into a list of moves in uci format, then we build the same listthat the program used in that position so we can retrieve if the chosen move was even or odd, and that's our bit leak, or we still append None to represent the cases where the length of the list was odd.

```python
def get_leaks_from_pgns(output_pgns):
    # Here we expect a list of lists of UCI moves, like [["a2b3", "e7e8"], ["a2b4", "e1e3"]]
    list_of_games_in_uci = parse_pgns(output_pgns)

    leaks = []

    for game in list_of_games_in_uci:
        chess_board = Board()
        for move in game:
            # Generate a list of legal moves in UCI format
            legal_moves = list(str(k) for k in list(chess_board.generate_legal_moves()))

            # Get the possible moves that can encode the bits for the destination square
            possible_moves = dic_bits_to_tile[dic_tile_to_bits[move[2:4]]]

            legal_possible_moves = [] 
        
            # Filter the legal moves to find those that match the possible encoding moves
            for legal_move in legal_moves:
                for encoding_move in possible_moves:
                    if (legal_move[2:4]) == encoding_move: 
                        legal_possible_moves.append(legal_move)

            # Determine the leaked bit based on the index of the move in the list of legal possible moves
            leaked_bit = (legal_possible_moves.index(move)) % 2

            # Append the leaked bit if the number of legal possible moves is even
            if len(legal_possible_moves) % 2 == 0:
                leaks.append(leaked_bit)
            else:
                leaks.append(None)

            # Make the move on the chess board
            chess_board.push(chess.Move.from_uci(move))

    return leaks
```
### Symbolic PRNG

To compute all the linear equations that cover the states of the PRNG we define a symbolic `xorshift128` that, when executed, will return the complete list of equations for every bit of the state.

```python
def symbolic_left_shift(v, n):
    return vector(list(v[n:]) + ([0]*n))

def symbolic_right_shift(v, n):
    return vector(([0]*n) + list(v[:-n]))

def symbolic_prng(state0, state1):
    s1 = state0
    s0 = state1
    state0 = s0

    # s1 ^= s1 << 23
    s1 = s1 + symbolic_left_shift(s1, 23)
    # s1 ^= s1 >> 17
    s1 = s1 + symbolic_right_shift(s1, 17)
    # s1 ^= s0
    s1 = s1 + s0
    # s1 ^= s0 >> 26
    s1 = s1 + symbolic_right_shift(s0, 26)

    state1 = s1

    return state0 , state1
```

### Utilising the leaks

Having recovered the leaks, our next step is to build a system of equations that map each leaked bit to its corresponding symbolic equation. This involves using `sage` to construct a matrix where each row represents the coefficients of all the state variables related to the least significant bit (LSB).
We then solve the linear system, `Ax = b` where `b` is the leak vector.
In the code we skip the rows where the leak vector contains `None`

To solve the system we just use the standard method `solve_right(b)` and output the solution in two parts, ready to start a new instance of the prng with the correct state.

```python
def recover_states(leak_vector):

    # Define a Boolean Polynomial Ring with 128 variables
    PR = BooleanPolynomialRing(STATE_DIM, "x") 
    x = PR.gens()

    # Initialize the symbolic state vectors
    state0 = vector(PR, x[0:64])
    state1 = vector(PR, x[64:128])
        
    # Create an instance of the symbolic PRNG
    sym_prng = SymbolicXorShift128(state0, state1)

    rows = []
    bs = []

    # Iterate over the leak vector to build the system of equations
    for i in range(len(leak_vector)):

        # Get the least significant bit (LSB) of the next state
        res = sym_prng.next()[-1] 
        # Extract the monomial coefficients for the LSB
        res = [res.monomial_coefficient(x[j]) for j in range(STATE_DIM)]

        # If the leak is not None, add the equation to the system
        if leak_vector[i] is not None:
            rows.append(res)
            bs.append(leak_vector[i])
        
    # Convert the rows and bs to matrices over GF(2)
    A = matrix(GF(2), rows)
    b = vector(GF(2), bs)

    # Solve the system of linear equations
    sol = A.solve_right(b)

    # Recover the initial states from the solution
    recovered_state0 = int("".join([str(int(i)) for i in sol[:64]]), 2)
    recovered_state1 = int("".join([str(int(i)) for i in sol[64:]]), 2)

    return recovered_state0, recovered_state1
```

### Solving the challenge

We first need to input a sufficiently long string into option number one from the main menu. In our testing, 300 random letters and numbers were enough to generate the necessary data. Once we have input the string, we then recover the output PGN games generated by the encoding process. 

Next, we can use the `get_leaks_from_pgns` function to extract the leaks from the PGN games. This function processes the moves in the games and determines the leaked bits based on the legal moves and their encoding. After extracting the leaks, we call the `recover_states` function with the extracted leaks to recover the initial state of the PRNG. 

Finally, we initialise and use the PRNG to predict the next 50 players for the trivia game by calling the `choice` method with the list of players. By following these steps, we can successfully recover the initial state of the PRNG and use it to predict the trivia game answers, ultimately solving the challenge.

```python
def solve_chall(games):
    # List of players from the trivia file
    players = [ ... ]

    # Extract leaks from the provided PGN games
    leaks = get_leaks_from_pgns(games)

    # Recover the initial states of the PRNG using the leaks
    recovered_state0, recovered_state1 = recover_states(leaks)

    # Print the recovered states in hexadecimal format
    print(f"recovered state0: {hex(recovered_state0)}")
    print(f"recovered state1: {hex(recovered_state1)}")

    # Initialize the PRNG with the recovered states
    prng = XorShift128(recovered_state0, recovered_state1)

    # Advance the PRNG state to match the number of leaks
    for _ in range(len(leaks)):
        prng.next()

    # Predict the next 50 players for the trivia game
    predicted_players = []
    for _ in range(50):
        choice = prng.choice(players)
        predicted_players.append(choice)

    return predicted_players
```

