# prepare
# 1st: cd dcrm6; make gdcrm; cp bin/cmd/gdcrm docker/gdcrm
# 2nd: cd docker/gdcrm
FROM ubuntu:18.04
COPY gdcrm gdcrm-client /usr/local/bin/
COPY ./entrypoint-gdcrm.sh /
RUN chmod +x /entrypoint-gdcrm.sh
ENTRYPOINT ["/entrypoint-gdcrm.sh"]

##include 1st and 2nd
##cp Dockerfile dcrm6; cd dcrm6
#FROM golang:1.13.5 AS builder
#WORKDIR /build
#COPY . .
#RUN make
#
#FROM ubuntu:18.04
#COPY bin/cmd/gdcrm /usr/local/bin/
#COPY ./entrypoint-gdcrm.sh /
#RUN chmod +x /entrypoint-gdcrm.sh
#ENTRYPOINT ["/entrypoint-gdcrm.sh"]

