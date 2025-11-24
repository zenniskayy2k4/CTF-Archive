# Dockerfile for misc - Pair Baking
FROM golang:1.24.2-alpine3.21

# Install no-net deps
RUN apk add --no-cache musl-dev libseccomp-dev gcc git

# Install landrun
RUN go install github.com/victor4x/landrun/cmd/landrun@1923a96
    
# Install chall deps
RUN apk add --no-cache python3

WORKDIR /chall

# Compile no-net
COPY no-net.c .
RUN gcc -o no-net ./no-net.c -lseccomp

# Start challenge
COPY flag.txt .
COPY server.py .

RUN chmod +x server.py

EXPOSE 5000

CMD ["python3", "-u", "/chall/server.py"]
