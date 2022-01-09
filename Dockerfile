FROM ubuntu:latest

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update
RUN apt-get install -y git wget
RUN wget https://go.dev/dl/go1.17.6.linux-amd64.tar.gz && mv go1.17.6.linux-amd64.tar.gz /usr/local && \
cd /usr/local && tar -xzf go1.17.6.linux-amd64.tar.gz
ENV PATH=$PATH:/usr/local/go/bin
WORKDIR /root
RUN git clone https://github.com/gohugoio/hugo.git
WORKDIR /root/hugo
RUN go build -o /bin/hugo
WORKDIR /root
RUN hugo new site website
WORKDIR /root/website
RUN git init
RUN git submodule add https://github.com/vimux/binario themes/binario
RUN echo theme = \"binario\" >> config.toml
RUN hugo new posts/intro.md

# to create static page: hugo -D
