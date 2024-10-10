NetLink is a decentralized networking tool built on the [rustp2p](https://crates.io/crates/rustp2p) library.

使用方法 ./NetLink -l 10.26.0.2/24 -g netlink123 --peer tcp://192.168.10.13:23333

使用说明 ./NetLink -l <虚拟ip> -g <组名称> --peer <服务器地址>

参数介绍：
  -p, --peer <PEER>              对端节点地址。例子: --peer tcp://192.168.10.13:23333 --peer udp://192.168.10.23:23333
  -l, --local <LOCAL>            本地节点IP和掩码。例子: --local 10.26.0.2/24
  -g, --group-code <GROUP_CODE>  具有相同group_comde的节点可以组成一个网络
  -P, --port <PORT>              监听本地端口
  -h, --help                     打印帮助信息
  -V, --version                  打印版本信息
