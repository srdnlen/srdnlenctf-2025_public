FROM python:3.12.0a5-slim-bullseye

WORKDIR /usr/app/src
COPY ./network.py ./requirements.txt /usr/app/src/

RUN pip install --no-cache-dir -r requirements.txt
RUN apt update && apt install -y socat

EXPOSE 8888
CMD ["python", "./network.py"]
