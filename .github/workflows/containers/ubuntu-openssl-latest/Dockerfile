FROM ubuntu:latest

RUN apt-get update && \
    apt-get install -y \
    git \
    build-essential \
    cmake \
    openssl \ 
    libssl-dev && \
    apt-get clean
    

WORKDIR /workspace
