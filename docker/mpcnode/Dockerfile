# prepare
# 1st: make mpcnode; cp bin/cmd/mpcnode docker/mpcnode
# 2nd: cd docker/mpcnode
FROM ubuntu:18.04
COPY mpcnode mpcnode-client /usr/local/bin/
COPY ./entrypoint-mpcnode.sh /
RUN chmod +x /entrypoint-mpcnode.sh
ENTRYPOINT ["/entrypoint-mpcnode.sh"]

##include 1st and 2nd
#FROM golang:1.13.5 AS builder
#WORKDIR /build
#COPY . .
#RUN make
#
#FROM ubuntu:18.04
#COPY mpcnode mpcnode-client /usr/local/bin/
#COPY ./entrypoint-mpcnode.sh /
#RUN chmod +x /entrypoint-mpcnode.sh
#ENTRYPOINT ["/entrypoint-mpcnode.sh"]
