FROM ubuntu:latest

# ENV variables
ENV DEBIAN_FRONTEND=noninteractive

# Install utils
RUN apt update
RUN apt install -y \
    apt-transport-https \
    software-properties-common \
    ca-certificates \
    wget

# Install xpra
RUN wget -O "/usr/share/keyrings/xpra.asc" https://xpra.org/xpra.asc
RUN wget -O "/etc/apt/sources.list.d/xpra.sources" https://raw.githubusercontent.com/Xpra-org/xpra/master/packaging/repos/noble/xpra.sources
RUN apt update
RUN apt install -y xpra

# Install Snes9x package
RUN apt-get install -y \
    libglibmm-2.4-1t64 \
    libjack-dev \
    libsdl2-dev

# Clean apt
RUN apt-get clean && rm -rf /var/lib/apt/lists/*

# Create user
RUN useradd -m userchall
WORKDIR /home/userchall/

# Setup xpra
ENV XDG_RUNTIME_DIR="/run/user/1001/xpra"
RUN mkdir -p /run/user/1001/xpra
RUN chown userchall /run/user/1001/xpra
RUN chmod 700 /run/user/1001/xpra
RUN mkdir -p /run/xpra
RUN chown userchall /run/xpra
RUN chmod 775 /run/xpra

# Setup Snes9x
COPY --chown=root:userchall --chmod=050 snes9x.AppImage /home/userchall/
COPY --chown=root:userchall --chmod=040 snes9x.conf /home/userchall/.config/snes9x/
COPY --chown=root:userchall --chmod=040 breakout.sfc /home/userchall/
RUN ./snes9x.AppImage --appimage-extract

# Entrypoint
COPY --chown=root:userchall --chmod=040 entrypoint.sh /home/userchall/
EXPOSE 10000
USER userchall
ENTRYPOINT [ "bash", "/home/userchall/entrypoint.sh" ]
