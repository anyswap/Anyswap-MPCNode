### add support for new cryptocurrency 
#### 1. 
Build a package in `src/go`, and write your code in it. You are supposed to define a struct that implements the interface CryptocoinHandler. You can find the interface definition in `src/go/api.go`. Configuration constants such as the urls of gateways should be defined in package `src/go/config`.
#### 2. 
Append a key-value pair of the cryptocoin name and its reg address/accouont pattern into RegExpmap in validAddress.go.
#### 3.  
Register new transaction handler in `src/go/api.go`. Insert the constructor of your transaction handler in the switch-case statement.
