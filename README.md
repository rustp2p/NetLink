NetLink is a decentralized networking tool built on the [rustp2p](https://crates.io/crates/rustp2p) library.

```
Usage: netLink.exe [OPTIONS] --local <LOCAL IP> --group-code <GROUP CODE>

Options:
  -p, --peer <PEER>              Peer node address. e.g.: -p tcp://192.168.10.13:23333 -p udp://192.168.10.23:23333
  -l, --local <LOCAL IP>         Local node IP and mask. e.g.: -l 10.26.0.2/24
  -g, --group-code <GROUP CODE>  Nodes with the same group_code can form a network (Maximum length 16)
  -P, --port <PORT>              Listen local port
  -b, --bind-dev <DEVICE NAME>   Bind the outgoing network interface (using the interface name). e.g.: -b eth0
  -e, --encrypt <PASSWORD>       Enable data encryption. e.g.: -e "password"
      --threads <THREADS>        Set the number of threads, default to 2
      --pcrypt                   This is a test. Parallel encryption and decryption
      --exit-node <EXIT_NODE>    Global exit node,please use it together with '--bind-dev'
 ```


### Free community nodes

- --peer tcp://198.46.149.74:23333