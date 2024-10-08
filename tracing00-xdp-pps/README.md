# Install packages.
```
$ apt install clang llvm libelf-dev libpcap-dev build-essential automake git
```
# Compile xdp tutorial,
```
$ git clone https://github.com/danieldin95/xdp-tutorial.git
$ git checkout just-pps
$ ./configre
$ make 
```

# Load xdp-pps program.
```
$ cd tracing00-xdp-pass
$ ./xdp_sample_pkts_user -d enp1s0

pkt len: 98    bytes. hdr: fa 16 3e a4 6f ad fa 16 3e d9 75 65 08 00 45 00 00 54 71 85 00 00 40 01 f3 d9 0a 0a 00 89 0a 0a 00 ae 00 00 45 05 00 04 4f 17 85 d2 eb 66 00 00 00 00 34 d3 07 00 00 00 00 00 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35 36 37
pkt len: 98    bytes. hdr: fa 16 3e a4 6f ad fa 16 3e d9 75 65 08 00 45 00 00 54 71 d2 00 00 40 01 f3 8c 0a 0a 00 89 0a 0a 00 ae 00 00 80 a6 00 04 4f 18 86 d2 eb 66 00 00 00 00 f7 30 08 00 00 00 00 00 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35 36 37
pkt len: 98    bytes. hdr: fa 16 3e a4 6f ad fa 16 3e d9 75 65 08 00 45 00 00 54 71 d3 00 00 40 01 f3 8b 0a 0a 00 89 0a 0a 00 ae 00 00 9d 47 00 04 4f 19 87 d2 eb 66 00 00 00 00 d9 8e 08 00 00 00 00 00 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35 36 37
pkt len: 98    bytes. hdr: fa 16 3e a4 6f ad fa 16 3e d9 75 65 08 00 45 00 00 54 72 2c 00 00 40 01 f3 32 0a 0a 00 89 0a 0a 00 ae
```

# Watch packets per seconds.

```
$ sar -n DEV 2 3600

Linux 5.15.0-118-generic (daniel-tt-2) 	09/19/24 	_aarch64_	(4 CPU)

15:29:02        IFACE   rxpck/s   txpck/s    rxkB/s    txkB/s   rxcmp/s   txcmp/s  rxmcst/s   %ifutil
15:29:04           lo      1.50      1.50      0.16      0.16      0.00      0.00      0.00      0.00
15:29:04       enp1s0 6198533.50      2.00 387408.38      0.14      0.00      0.00      0.00      0.00
15:29:04       enp9s0      3.00      1.50      0.18      0.49      0.00      0.00      0.00      0.00
15:29:04    ovs-system      0.00      0.00      0.00      0.00      0.00      0.00      0.00      0.00
15:29:04      br-eth0      1.00      2.00      0.08      0.14      0.00      0.00      0.00      0.00

15:29:04        IFACE   rxpck/s   txpck/s    rxkB/s    txkB/s   rxcmp/s   txcmp/s  rxmcst/s   %ifutil
15:29:06           lo      0.00      0.00      0.00      0.00      0.00      0.00      0.00      0.00
15:29:06       enp1s0 6198079.50      2.00 387380.00      0.14      0.00      0.00      0.00      0.00
15:29:06       enp9s0      2.50      1.50      0.15      1.01      0.00      0.00      0.00      0.00
```