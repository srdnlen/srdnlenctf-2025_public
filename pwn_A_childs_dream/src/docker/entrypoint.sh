
timeout 5m xpra start :100 \
    --bind-tcp=0.0.0.0:10000 \
    --start-child-after-connect="/home/userchall/squashfs-root/AppRun /home/userchall/breakout.sfc" \
    --exit-with-children=yes \
    --tray=no \
    --lock=yes \
    --sharing=no \
    --daemon=no \
    --html=on \
    --clipboard=no \
    --clipboard-direction=disabled \
    --file-transfer=off \
    --open-files=off \
    --notifications=no \
    --bell=no \
    --webcam=no \
    --speaker=disabled \
    --microphone=disabled \
    --start-new-commands=no \
    --pulseaudio=no \
    --mdns=no \
    --dbus-launch=no \
    --dbus-control=no \
    --socket-dir="/run/user/1001/xpra" \
