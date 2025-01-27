FROM python:3.12.4-slim

RUN apt-get clean && \
    apt-get update && \
    apt-get install -y gdb grep socat && \
    rm -rf /var/lib/apt/lists/*

COPY --chown=root:root --chmod=400 ./chall.py /root
COPY --chown=root:root --chmod=100 ./entrypoint.sh /root

EXPOSE 3434

ENTRYPOINT ["socat", "-t", "300", "-T", "300", "TCP-LISTEN:3434,reuseaddr,nodelay,fork", "EXEC:bash /root/entrypoint.sh"]