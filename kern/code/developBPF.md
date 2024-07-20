# note of fastudp development #

we can see more detail [here](https://github.com/HJPFHMATRIX/Project266/blob/main/src/programming.md)   

## related to dragonboat ##

- the port are set to 12345    
- magic number is 0x AE 7D  
- only raftType now, didn't handle snapshotType   
- max nodehost number is set to 64
- need the IPv6 addr


## run the code ##
```shell
$ cd src/myBPF/kern/code 
$ make fastudp
$ sudo ./fastudp
```
