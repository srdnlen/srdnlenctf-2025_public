FROM python:3.12.0a5-slim-bullseye

WORKDIR /usr/app/src
COPY ./chall.py ./requirements.txt /usr/app/src/

RUN pip install --no-cache-dir -r requirements.txt
RUN apt update && apt install -y socat

ENV FLAG="srdnlen{I_h0p3_th15_Gl4ss_0f_M1rt0_w4rm3d_y0u_3n0ugh}"

EXPOSE 1337
CMD socat -d TCP-LISTEN:1337,reuseaddr,fork EXEC:"python ./chall.py"
