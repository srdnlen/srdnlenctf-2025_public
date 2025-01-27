import asyncio

questions = [
    {"question": "Which packet contains the header of an executable file?", "answer": "2137"},
    {"question": "To which flow does it correspond? (PROTOCOLO FLOW_ID, e.g. HTTP 1)", "answer": "TCP 40"},
    {"question": "Into how many parts is the executable fragmented? Give the total number of files", "answer": "29"},
    {"question": "What is the resource name accessed in the GET resource containing the executable file?. Give the complete name (e.g. /myfile/file1/this-is-the-file?A0=something&A1=other%3d%3d)", "answer": "/filestreamingservice/files/7d9cd93c-1d5e-449b-9ad7-f1e8d6b90509?P1=1736543287&P2=404&P3=2&P4=A4bbVZMC2rLzoHuEoqkGyn%2bfjFNZYtKNVXsPbIbY5Amz3v4r%2bQitB5Uc%2fXCKOEvShr8HAJPOsSVdpx2t0DGgKQ%3d%3d"},
    {"question": "What is the sha256 of the first part of the executable file?", "answer": "b56b0ee4af8f4395455ed4f83b2d25498444c939fcf77d49ec9ec83c68983e52"},
    {"question": "To which of the extracted files does it correspond? As done by Wireshark, use the enumeration starting from 0", "answer": "2"},
    {"question": "What is the sha256sum of the reconstructed file?", "answer": "26f6728a7327ecb881a8d7989b2ec93debbc2a7e1c844ce4b2a6549f00763e0e"},
    {"question": "How many downloaded chrome extensions are not corrupted?", "answer": "5"},
    {"question": "Which packet is related to cryptomining?", "answer": "290"},
    {"question": "To which flow does it correspond? (PROTOCOLO FLOW_ID, e.g. UDP 0)", "answer": "HTTP 8"},
    {"question": "What is the resource name? Give the complete name (e.g. /myfile/file1/this-is-the-file?A0=something&A1=other%3d%3d)", "answer": "/filestreamingservice/files/dfeb2940-49d3-4f29-8fd8-d984a787dc6e?P1=1736222766&P2=404&P3=2&P4=H1jtSvldNZpuTpd5fP9uKkWsRR%2f5pXzccLVud6a0mJoxofqoKB34dNqF4qXGEwhkbPhjKQoon413psf1XzNktA%3d%3d"},
    {"question": "Give the sha256 of the file related to cryptocurrency.", "answer": "364dfe0f3c1ad2df13e7629e2a7188fae3881ddb83a46c1170112d8d3b5a73de"}
    
    
    
]

TIMEOUT = 60  # seconds
PORT = 8888

def welcome_message():
    return ("\n" +
            "##############################################\n" +
            "#    Welcome to DFIR.2 MalNet Challenge!     #\n" +
            "##############################################\n" +
            "\n")

def challenge_instructions():
    return ("In this challenge, you have to retrieve information from the given pcap capture_net.pcap \n" + 
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
        writer.write(b"Here's your flag for challenge Malnet: srdnlen{DFIR2:network_analysis_R34L_malware}\n")
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
