
<p align="center">
  <a href="./README.zh-CN.md">简体中文</a> |
  <a href="./README.md">English</a>
</p>

`NetLink` 是建立在[rustp2p](https://crates.io/crates/rustp2p)库基础上的去中心化的网络工具.

## 使用
```
管理员权限命令行输入: netLink.exe [OPTIONS] --local <LOCAL IP> --group-code <GROUP CODE>

Commands:
  cmd   Backend command
  help  打印帮助信息

Options:
  -p, --peer <PEER>              远端节点地址(需可直接访问). 如: -p tcp://192.168.10.13:23333 或 -p udp://192.168.10.23:23333
  -l, --local <LOCAL IP>         设定本地节点地址 CIDR格式. 如: -l 10.26.0.2/24
  -g, --group-code <GROUP CODE>  节点所在组的名称(最大长度16),只有同一组的节点才能进行数据访问
  -P, --port <PORT>              本地监听地址
  -b, --bind-dev <DEVICE NAME>   指定流量出口网卡名. 如: -b eth0
      --threads <THREADS>        设置使用线程数, 默认两个线程
  -e, --encrypt <PASSWORD>       设定秘钥并开启加密. 如: -e "password"
  -a, --algorithm <ALGORITHM>    设定加密算法. 可选择算法: aes-gcm/chacha20-poly1305/xor, 默认是：chacha20-poly1305
      --exit-node <EXIT_NODE>    网关节点，请配合'--bind-dev'使用
      --tun-name <TUN_NAME>      设定本地tun的名称
 ```

## 特性

| Features           |   |
|--------------------|---| 
| **Decentralized**  | ✅ |
| **Cross-platform** | ✅ |
| **NAT traversal**  | ✅ | 
| **Subnet route**   | ✅ | 
| **Encryption**     | ✅ | 
| **Efficient**      | ✅ | 
| **IPv6/Ipv4**      | ✅ | 
| **UDP/TCP**        | ✅ | 

## 快速上手

```mermaid
flowchart LR
    subgraph Node-A 8.210.54.141
        node_a[10.26.1.2/24]
    end
    subgraph Node-B
        node_b[10.26.1.3/24]
    end

    subgraph Node-C
        node_c[10.26.1.4/24]
    end

    node_a <-----> node_b
    node_c <-----> node_b
    node_a <-----> node_c
```

1. Node-A
    ```
    ./netLink --group-code 123 --local 10.26.1.2/24
    ```
2. Node-B
    ```
    ./netLink --group-code 123 --local 10.26.1.3/24 --peer 8.210.54.141:23333
    ```
3. Node-C
    ```
    ./netLink --group-code 123 --local 10.26.1.4/24 --peer 8.210.54.141:23333
    ```
4. 节点 A, B, and C 可以互相访问

## 多节点

```mermaid
flowchart LR
    subgraph Node-A 8.210.54.141
        node_a[10.26.1.2/24]
    end
    subgraph Node-B
        node_b[10.26.1.3/24]
    end

    subgraph Node-C 192.168.1.2
        node_c[10.26.1.4/24]
    end
    subgraph Node-D
        node_d[10.26.1.5/24]
    end
    node_b -----> node_a
    node_c -----> node_a
    node_d -----> node_c
```

```
Node-A: ./netLink --group-code 123 --local 10.26.1.2/24
Node-B: ./netLink --group-code 123 --local 10.26.1.3/24 --peer 8.210.54.141:23333
Node-C: ./netLink --group-code 123 --local 10.26.1.4/24 --peer 8.210.54.141:23333
Node-D: ./netLink --group-code 123 --local 10.26.1.4/24 --peer 192.168.1.2:23333
```

所有已连接的节点可以互相访问

而且, 多节点也可以通过'-peer'连接.  
example：

```
Node-A: ./netLink --group-code 123 --local 10.26.1.2/24
Node-B: ./netLink --group-code 123 --local 10.26.1.3/24 --peer 8.210.54.141:23333
Node-C: ./netLink --group-code 123 --local 10.26.1.4/24 --peer 8.210.54.141:23333
Node-D: ./netLink --group-code 123 --local 10.26.1.4/24 --peer 192.168.1.2:23333 --peer 8.210.54.141:23333
```

## 子网路由

```
Public Node-S: 8.210.54.141

Subnet 1: 192.168.10.0/24
      Node-A: 192.168.10.2
      Node-B: 192.168.10.3
      
Other subnet:   
      Node-C

Node-S: ./netLink --group-code xxxx --local 10.26.1.1
Node-A: ./netLink --group-code 123 --local 10.26.1.3/24 --peer 8.210.54.141:23333
Node-C: ./netLink --group-code 123 --local 10.26.1.4/24 --peer 8.210.54.141:23333

Node-C <--> Node-A(192.168.10.2) <--> Node-B(192.168.10.3)
```

1. **第一步 : 节点Node-A配置转发网卡**
  > 转发所有来源地址在网段10.26.1.0/24下的流量到指定网卡

   **Linux**
   ```
   sudo sysctl -w net.ipv4.ip_forward=1
   sudo iptables -t nat -A POSTROUTING  -o eth0 -s 10.26.1.0/24 -j MASQUERADE
   ```
   **Windows**
   ```
   New-NetNat -Name testSubnet -InternalIPInterfaceAddressPrefix 10.26.1.0/24
   ```
   **Macos**
   ```
   sudo sysctl -w net.ipv4.ip_forward=1
   echo "nat on en0 from 10.26.1.0/24 to any -> (en0)" | sudo tee -a /etc/pf.conf
   sudo pfctl -f /etc/pf.conf -e
   ```
2. **第二步 : 节点Node-C的路由设置**
  > 将目标地址在网段192.168.10.0/24下的流量通过路由代理到本地tun并且发送到网关10.26.1.3(即 节点Node-A的虚拟地址)

   **Linux**
   ```
   sudo ip route add 192.168.10.0/24 via 10.26.1.3 dev <netLink_tun_name>
   ```
   **Windows**
   ```
   route add 192.168.10.0 mask 255.255.255.0 10.26.1.3 if <netLink_tun_index>
   ```
   **Macos**
   ```
   sudo route -n add 192.168.10.0/24 10.26.1.3 -interface <netLink_tun_name>
   ```

此时, Node-C可以通过Node-A访问Node_B, 就像Node-C和Node-B是直连的一样

## 联系

- TG: https://t.me/+hdMW5gWNNBphZDI1
- QQ群: 211072783

## 免费社区节点

- --peer tcp://198.46.149.74:23333
