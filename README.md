![port-mirroring logo](icon.png "port-mirroring") port-mirroring [![Build Status](https://travis-ci.org/mmaraya/port-mirroring.svg?branch=master)](https://travis-ci.org/mmaraya/port-mirroring) [![Coverity Scan Build Status](https://scan.coverity.com/projects/6700/badge.svg)](https://scan.coverity.com/projects/mmaraya-port-mirroring)
==============

port-mirroring is an [OpenWrt](https://openwrt.org) package that sends copies of network packets from your OpenWrt router to another device on your network or beyond, giving you the ability to monitor and analyze network traffic without additional hardware. Intrusion detection systems, network application debugging, and network performance monitoring are common use cases. This is a continuation of the work started by Bruce Geng at https://code.google.com/p/port-mirroring/.

Supported Platforms
-------------------

port-mirroring runs on all hardware platforms [supported](http://wiki.openwrt.org/toh/start) by OpenWrt. 

Download
--------
port-mirroring v1.4.2 has been tested against OpenWrt Chaos Calmer 15.05 and is available for the the following platform(s):
* Atheros AR71xx/AR724x/AR913x/AR9344 or "ar71xx" platform: [port-mirroring_1.4.2_ar71xx.ipk] (https://github.com/mmaraya/port-mirroring/releases/download/v1.4.2/port-mirroring_1.4.2_ar71xx.ipk). 

If you need binaries for your router architecture, please submit a [request](https://github.com/mmaraya/port-mirroring/issues). 


Usage
-----
These instructions will only work on routers that use the Atheros AR71xx/AR724x/913x or "ar71xx" platform. If your router does not use the ar71xx platform, please submit a [request](https://github.com/mmaraya/port-mirroring/issues).

The default wget in OpenWrt is provided by Busybox and does not support SSL. The following commands from the OpenWrt terminal will install the full wget with SSL support and root certificates:
```
root@OpenWrt:~# opkg update
root@OpenWrt:~# opkg install wget
root@OpenWrt:~# mkdir -p /etc/ssl/certs
root@OpenWrt:~# echo "export SSL_CERT_DIR=/etc/ssl/certs" >> /etc/profile
root@OpenWrt:~# source /etc/profile
root@OpenWrt:~# opkg install ca-certificates
```

From your OpenWrt terminal, run the following commands to install the precompiled package.
```
root@OpenWrt:~# cd /tmp
root@OpenWrt:~# wget https://github.com/mmaraya/port-mirroring/releases/download/v1.4.2/port-mirroring_1.4.2_ar71xx.ipk
root@OpenWrt:~# opkg install port-mirroring_1.4.2_ar71xx.ipk
```
The last command will install the package and start it as a background process using the default configuration file. The default settings will probably not work on your environment, so the program should exit right after starting. Modify the `/etc/config/port-mirroring` file to suit your environment.
```
config 'port-mirroring'
    option source_ports 'eth0,wlan0'    # interfaces (maximum of 4) to copy packets from
    option promiscuous  '1'             # put source interface(s) in promiscuous mode
    option target       '10.1.4.2'      # interface or IP address to send packets to
    option protocol     'TEE'           # 'TEE' iptables (default) or 'TZSP' TaZmen Sniffer Protocol 
    option filter       ''              # optional tcpdump/libpcap packet filter expressions
```
To start port-mirroring as a foreground process with debugging on:
```
root@OpenWrt:~# port-mirroring --debug
```
To start port-mirroring as a daemon:
```
root@OpenWrt:~# /etc/init.d/port_mirroring start
```
To read the port-mirroring system logs:
```
root@OpenWrt:~# logread | grep port-mirroring
```
To stop the port-mirroring daemon:
```
root@OpenWrt:~# /etc/init.d/port_mirroring stop
```
To uninstall the port-mirroring package:
```
root@OpenWrt:~# opkg remove port-mirroring
```

Build Prerequisites
-------------------

To compile the OpenWrt package, you will need the following:

   * [OpenWrt SDK](http://wiki.openwrt.org/doc/howto/obtain.firmware.sdk)
   * ccache
   * libpcap-dev

Build Instructions
------------------

1. Download [OpenWrt SDK](http://wiki.openwrt.org/doc/howto/obtain.firmware.sdk) and link/rename it openwrt-sdk
2. Create the directory openwrt-sdk/package/port-mirroring/
3. Create a link to port-mirroring/openwrt/Makefile in openwrt-sdk/package/port-mirroring/
4. Run the following commands from your openwrt-sdk directory:
   * rm dl/port-mirroring-1.4.2.tar.bz2
   * make -j1 V=s package/port-mirroring/clean
   * make -j1 V=s package/port-mirroring/compile
5. If everything works, you should find your package in openwrt-sdk/bin/ar71xx/packages/base/

License
-------

Please see the file named [LICENSE](https://github.com/mmaraya/port-mirroring/blob/master/LICENSE). 

Issues
------

Please submit questions, comments, bugs, enhancement requests at https://github.com/mmaraya/port-mirroring/issues.

Disclaimer
----------

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

