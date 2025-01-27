from src.encode_to_pgn_2bit import encode_to_pgn
from src.trivia import trivia
from src.pseudorandom import XorShift128
from src.decode_from_pgn_2bit import decode_from_pgn, input_and_parse_pgns
import secrets 
SIZE = 64
MAX_STRING = 300

def main_menu():
    prng = XorShift128(secrets.randbits(SIZE), secrets.randbits(SIZE))

    while True:
            print("\nMain Menu")
            print("1. Encode a string to PGN")
            print("2. Decode a PGN to string")
            print("3. Play trivia")
            print("4. Exit")
            choice = input("Enter your choice (1/2/3/4): ")

            if choice == "1":
                while True:
                    string_to_encode = input(f"Enter the string to encode (max {MAX_STRING} characters): ")

                    if len(string_to_encode) <= MAX_STRING:
                        break
                    else:
                        print(f"String too long! Please enter a string with at most {MAX_STRING} characters.")

                results = [ pgn for pgn in encode_to_pgn(string_to_encode, prng)]
                
                print("encoded pgns:\n")
                for result in results:
                    print(result)

            if choice == "2":
                list_of_pgns = input_and_parse_pgns()

                print("decoded string:\n")
                print(decode_from_pgn(list_of_pgns))
                
            elif choice == "3":
                trivia(prng)
            elif choice == "4":
                print("Exiting...")
                break
            else:
                print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main_menu()