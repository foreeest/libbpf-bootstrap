# note of fastudp development #

we can see more detail [here](https://github.com/HJPFHMATRIX/Project266/blob/main/src/programming.md)   

## related to dragonboat ##

- the port are set to 12345    
- magic number is 0x AE 7D  
- only raftType now, didn't handle snapshotType   
- max nodehost number is set to 64
- need the IPv6 addr

## how to debug ##

- using [bpftool](https://github.com/HJPFHMATRIX/Project266/blob/main/src/programming.md)
- using [wireshark and tcpdump](https://xiaolincoding.com/network/3_tcp/tcp_tcpdump.html#%E6%98%BE%E5%BD%A2-%E4%B8%8D%E5%8F%AF%E8%A7%81-%E7%9A%84%E7%BD%91%E7%BB%9C%E5%8C%85)
- using [bpftrace](https://github.com/bpftrace/bpftrace)

## run the code ##

```shell
$ cd ./src/myBPF/kern/code
$ make fastudp
$ sudo ./fastudp
$ sudo bpftool map lookup pinned /sys/fs/bpf/configure key 0x1 0x0 0x0 0x0
```

code | decription
---- | -----------
fastudp | need at least 3 nodehosts
fastudpL| L means local, need 3 terminals

## details ##

### develop Local version ###  

> eth according to `ifconfig`   
> ipv4 is 10.211.55.4:6300x

### shit,it suddenly appear some warning ###
this means I fail to compile before  
shit, I doubt this  