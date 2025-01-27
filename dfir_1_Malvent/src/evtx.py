import asyncio

questions = [
    {"question": "What is the name of the suspicious service installed?", "answer": "QcUcMElh"},
    {"question": "From which process it has been generated? Give also the extension", "answer": "lmIcgUEQ.exe"},
    {"question": "What is its event ID?", "answer": "7045"},
    {"question": "Give the events IDs corresponding to unsecured data (e.g. cryptography). If more than one put a comma (e.g. 1, 2)", "answer": "15, 18"},
    {"question": "Which event ID is related to the state of the account protection?", "answer": "16977"},
    {"question": "Give the compromised CLSID stating that malicious code could be executed. If more than one, put a comma (e.g. str1, str2)", "answer": "Windows.SecurityCenter.SecurityAppBroker, Windows.SecurityCenter.WscBrokerManager"},
    {"question": "What is the port number listening for remote control?", "answer": "3387"},
    {"question": "Give the event ID related to the manipulation of specific data (e.g. registry key manipulation, deletion, creation, modification)", "answer": "16"},
    {"question": "Give the application name whose corruption could depend from the malware. (First letter uppercase, add also the extension).", "answer": "Widgets.exe"},
    {"question": "Is Windows Defender on?", "answer": "yes"},
    {"question": "What is the event ID stating this?", "answer": "15"},
    {"question": "Give the event ID related to the wrong management of different sessions and users in remote desktop", "answer": "6003"},
    {"question": "Which event ID states that the malware could have read the credentials?", "answer": "5379"}
]

TIMEOUT = 60  # seconds
PORT = 8888

def welcome_message():
    return ("\n" +
            "##############################################\n" +
            "#    Welcome to DFIR.1 Malvent Challenge!    #\n" +
            "##############################################\n" +
            "\n")

def challenge_instructions():
    return ("In this challenge, you have to retrieve information from the given evtx files from al_evtx.zip \n" + 
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
        writer.write(b"Here's your flag for Malvent: srdnlen{DFIR1:evtx4system_mngmnt&malwan}\n")
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
