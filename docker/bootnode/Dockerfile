# prepare
# 1st: make bootnode, cp bin/cmd/bootnode docker/bootnode
# 2nd: cd docker/bootnode
FROM ubuntu:18.04
COPY bootnode /usr/local/bin/
COPY ./entrypoint-bootnode.sh /
RUN chmod +x /entrypoint-bootnode.sh
ENTRYPOINT ["/entrypoint-bootnode.sh"]

# 1st: make bootnode, cp bin/cmd/bootnode docker/bootnode
#FROM golang:1.13.5 AS builder
#WORKDIR /build
#COPY . .
#RUN make
#
#FROM ubuntu:18.04
#COPY bin/cmd/bootnode /usr/local/bin/
#COPY ./entrypoint-bootnode.sh /
#RUN chmod +x /entrypoint-bootnode.sh
#ENTRYPOINT ["/entrypoint-bootnode.sh"]

