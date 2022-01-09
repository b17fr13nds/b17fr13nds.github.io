FROM ubuntu:20.04

RUN apt-get update
RUN apt-get install -y golang git
WORKDIR /root
RUN git clone https://github.com/gohugoio/hugo.git
WORKDIR /root/hugo
RUN go install -o /bin/hugo
WORKDIR /root
RUN hugo new site website
WORKDIR /root/website
RUN git init
RUN git submodule add https://github.com/alexandrevicenzi/soho.git themes/soho
RUN echo theme = \"soho\" >> config.toml
RUN hugo new posts/intro.md

# to create static page: hugo -D
