# Create new user
user=jail_${RANDOM}${RANDOM}${RANDOM}
if ! useradd -m -d /home/jail -s /bin/bash ${user}; then
    exit 1
fi

# Handle cleanup
cleanup() {
    echo remove... >&2
    userdel -r ${user}
}
trap cleanup EXIT

# Create chall directory for user
mkdir -p /home/${user}/chall
cd /home/${user}/chall

# Copy chall file
cp /root/chall.py .

# Change permissions
chown ${user}:${user} .
chown ${user}:${user} ./chall.py
chmod 700 .
chmod 700 ./chall.py

# Run chall
su ${user} -c "python3 ./chall.py"