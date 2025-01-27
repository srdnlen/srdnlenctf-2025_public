import asyncio

questions = [
    {"question": "What is the VT detection score?", "answer": "62/72"},
    {"question": "Give the popular threat label", "answer": "virus.virlock/polyransom"},
    {"question": "When was it created?", "answer": "2018-06-26 16:16:29 UTC"},
    {"question": "What is the target machine?", "answer": "Intel 386"},
    {"question": "Which dlls are used? Give just the name without .dll extension. If more than one put a comma (e.g. 1, 2)", "answer": "kernel32, user32"},
    {"question": "What is the malicious IP address?", "answer": "144.76.195.253"},
    {"question": "What is the registrar of the domain related to the previous bitcoin address?", "answer": "Hetzner Online GmbH"},
    {"question": "Which persistence techniques according to MITRE does it have? If more than one put a comma (e.g. 1, 2)", "answer": "T1053, T1542, T1542.003, T1547, T1547.001, T1574, T1574.002"},
    {"question": "Which defence/evasion techniques according to MITRE does it have? If more than one put a comma (e.g. 1, 2)", "answer": "T1014, T1027, T1027.002, T1036, T1055, T1112, T1202, T1497, T1542, T1542.003, T1548, T1548.002, T1562, T1562.001, T1562.006, T1564, T1564.001, T1574, T1574.002"},
    {"question": "Which anti-behavioral analysis techniques according to MITRE does it have? If more than one put a comma (e.g. 1, 2)", "answer": "B0007, B0007.008, F0001"},
    {"question": "Which anti-static analysis technique according to MITRE does it have?", "answer": "F0001"}
    
]

TIMEOUT = 60  # seconds
PORT = 8888

def welcome_message():
    return ("\n" +
            "##############################################\n" +
            "#   Welcome to DFIR.4 MalThrInt Challenge!   #\n" +
            "##############################################\n" +
            "\n")

def challenge_instructions():
    return ("In this challenge, you have to retrieve information from VirusTotal using the hash correctly answered in the last question of DFIR.3-RAMsomwhere \n" + 
            "You will answer a series of questions.\n" +
            "Each correct answer will take you closer to the flag srdnlen{something}\n" +
            "Good luck!\n\n")

async def handle_client(reader, writer):
    addr = writer.get_extra_info('peername')
    print(f"Client connected: {addr}")

    try:
        # Send welcome message with graphics
        writer.write(welcome_message().encode())
        await writer.drain()
        
        # Send challenge instructions
        writer.write(challenge_instructions().encode())
        await writer.drain()

        for q in questions:
            while True:
                writer.write((q["question"] + "\n").encode())
                await writer.drain()

                try:
                    answer = await asyncio.wait_for(reader.readline(), timeout=TIMEOUT)
                    answer = answer.decode().strip()
                except asyncio.TimeoutError:
                    print(f"Client {addr} timed out.")
                    writer.write(b"Connection closed due to inactivity.\n")
                    await writer.drain()
                    writer.close()
                    await writer.wait_closed()
                    return

                if answer.lower() == q["answer"].lower():
                    writer.write(b"Correct!\n")
                    await writer.drain()
                    break
                else:
                    writer.write(b"Incorrect. Try again.\n")
                    await writer.drain()

        writer.write(b"Congratulations! You have completed the quiz.\n")
        writer.write(b"Here's your flag for challenge DIR_4_MalThrInt: srdnlen{DFIR4:VirusTotal4PPID_ThreatIntelligence}\n")
        await writer.drain()
    except Exception as e:
        print(f"Error with client {addr}: {e}")
    finally:
        print(f"Client disconnected: {addr}")
        writer.close()
        await writer.wait_closed()

async def main():
    server = await asyncio.start_server(handle_client, '0.0.0.0', PORT)

    addr = server.sockets[0].getsockname()
    print(f"Server running on {addr}")

    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nServer shutting down.")
