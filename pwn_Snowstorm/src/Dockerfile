FROM ubuntu:24.04

RUN apt-get clean
RUN apt-get update
RUN apt-get install -y socat
RUN rm -rf /var/lib/apt/lists/*

RUN useradd -m -d /home/userchall userchall
WORKDIR /home/userchall

COPY --chown=root:userchall --chmod=050 ./snowstorm .
COPY --chown=root:userchall --chmod=040 ./flag.txt .

USER userchall

EXPOSE 1089
ENTRYPOINT ["socat", "-t", "300", "-T", "30", "TCP-LISTEN:1089,reuseaddr,nodelay,fork", "EXEC:./snowstorm,stderr"]
