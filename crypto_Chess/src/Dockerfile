# Dockerfile for the challenge
FROM python:3.12.7-slim

# Set the working directory
WORKDIR /app

# Copy the current directory contents into the container at /wrkdir
COPY . /app

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

RUN apt update && apt install -y socat && apt clean && rm -rf /var/lib/apt/lists/*

# Define environment variable
ENV FLAG="srdnlen{D4mn_I_R3aLly_L1k3_Ch3s5_sTuFf_4D616E2049206C6F766520426F6F6273}"

# Make port 4012 available to the world outside this container
EXPOSE 4012

CMD socat -d TCP-LISTEN:4012,reuseaddr,fork EXEC:"python3 ./main.py"

#! docker compose up --build -d
#! nc 0.0.0.0 4012
#! docker compose down -v


