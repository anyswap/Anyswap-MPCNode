docker run -d --name gdcrm --network host --restart always -v /var/lib/docker/gdcrm:/gdcrm anyswap/gdcrm --bootnodes "enode://ip@port" --port 12345 --rpcport 23456
