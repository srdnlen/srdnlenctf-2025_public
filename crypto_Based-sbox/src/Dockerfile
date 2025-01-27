FROM python:3.12.7-slim

WORKDIR /usr/app/src
COPY ./server.py ./requirements.txt /usr/app/src/

RUN pip install --no-cache-dir -r requirements.txt
RUN apt update && apt install -y socat

ENV FLAG="srdnlen{that_sbox_was_truly_ba5ed_right?...hopefully_you_learned_a_bit_about_its_history}"

EXPOSE 1337
CMD socat -d TCP-LISTEN:1337,reuseaddr,fork EXEC:"python3 ./server.py"
