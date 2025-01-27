import asyncio

questions = [
    {"question": "What is the PID of the process found in the evtx analysis?", "answer": "2240"},
    {"question": "Which IP does not compare in the given pcap file?", "answer": "127.0.0.1"},
    {"question": "What is the name in the manifest of the chrome extension found in the pcap and not in the RAM?", "answer": "AutofillCore"},
    {"question": "Give the PID of the displayed suspicious processes (do not consider does already analysed, neither their sons). If more than one put a comma (e.g. 1, 2)", "answer": "6444, 1236"},
    {"question": "What is the directory of the file related to process 6444? Give the complete path from the root directory to the extension. (e.g. C:\\path\\my\\process.extension)", "answer": "C:\\Users\\User\\kOIUsMQU\\MEMYUoYU.exe"},
    {"question": "What is the directory of the file related to process 1236? Give the complete path from the root directory to the extension. (e.g. C:\\path\\my\\process.extension)", "answer": "C:\\ProgramData\\hwQkYMwk\\ceIcEMkw.exe"},
    {"question": "What is the parent PID of the malicious processes?", "answer": "4680"},
    {"question": "How many files have been encrypted?", "answer": "288"},
    {"question": "Give the filename of the file containing the list of the files to be encrypted. (only the filename not the whole path).", "answer": "ZcgU.txt"},
    {"question": "Which cryptocurrency is used?", "answer": "BitCoin"},
    {"question": "Which GET request is not present in the pcap? Give the whole request (METHOD resource, e.g. POST /accessed/resource)", "answer": "GET /maps/api/staticmap?center=32.33597550,-111.04410110&zoom=14"},
    {"question": "Why did you have to pay a fine?", "answer": "unauthorized or pirated software"},
    {"question": "What is the amount of fine? (e.g. €10,000)", "answer": "$250,000"},
    {"question": "Which forum is used to ask for BitCoin AMT?", "answer": "reddit"},
    {"question": "What is the BitCoin address at charts01.bitcoincharts.com?", "answer": "1yQBzAaZx7FojqMmTtHPTfZ42T4t6Q1Uh"},
    {"question": "From which directory does process 6444 come from? Give only the local path with directory name (NOT the absolute path, i.e. without Desktop, e.g. mydirectory)", "answer": "ch2"},
    {"question": "What is the filename of the process which executed the two malware with PID 4680? Give only the filename with extension (e.g. myfile.ext)", "answer": "0002bdf0923262600d3ef66d1ec6b2396a434e6f7626a9d70241a5663ee2f736.exe"},
]

TIMEOUT = 60  # seconds
PORT = 8888

def welcome_message():
    return ("\n" +
            "##############################################\n" +
            "#  Welcome to DFIR.3 RAMsomewhere Challenge!  #\n" +
            "##############################################\n" +
            "\n")

def challenge_instructions():
    return ("In this challenge, you have to retrieve information from the given memory dump. \n" + 
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
        writer.write(b"Here's your flag for challenge DFIR_3_RAMsomwhere: srdnlen{DFIR3:Windows_RAMsomware}\n")
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
