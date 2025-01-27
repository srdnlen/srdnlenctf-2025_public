import os

FLAG = os.environ.get("FLAG")

players = [
    "Magnus Carlsen", "Hikaru Nakamura", "Garry Kasparov", "Bobby Fischer",
    "Viswanathan Anand", "Vladimir Kramnik", "Fabiano Caruana", "Ding Liren",
    "Ian Nepomniachtchi", "Anatoly Karpov", "Mikhail Tal", "Alexander Alekhine",
    "Jose Raul Capablanca", "Paul Morphy", "Judith Polgar", "Wesley So",
    "Levon Aronian", "Maxime Vachier-Lagrave", "Sergey Karjakin", "Shakhriyar Mamedyarov",
    "Teimour Radjabov", "Boris Spassky", "Tigran Petrosian", "Veselin Topalov",
    "Peter Svidler", "Anish Giri", "Richard Rapport", "Jan-Krzysztof Duda",
    "Viktor Korchnoi", "Bent Larsen", "David Bronstein", "Samuel Reshevsky",
    "Efim Geller", "Mikhail Botvinnik", "Alexander Grischuk", "Vassily Ivanchuk",
    "Nigel Short", "Michael Adams", "Gata Kamsky", "Ruslan Ponomariov",
    "Vladimir Akopian", "Peter Leko", "Evgeny Bareev", "Alexei Shirov",
    "Vladimir Malakhov", "Boris Gelfand", "Vladimir Fedoseev", "Daniil Dubov",
    "Wei Yi", "Alireza Firouzja" , "Vladislav Artemiev", "Dmitry Andreikin", 
    "Radoslaw Wojtaszek", "Leinier Dominguez", "Pentala Harikrishna", "Sergey Movsesian",
    "Ernesto Inarkiev", "David Navara", "Vladislav Kovalev", "Jorden Van Foreest",
    "Nihal Sarin", "Vincent Keymer", "Awonder Liang", "Jeffery Xiong",
    "Praggnanandhaa Rameshbabu", "Raunak Sadhwani"
]


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

        
