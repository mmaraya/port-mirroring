port-mirroring [![Build Status](https://travis-ci.org/mmaraya/port-mirroring.svg?branch=master)](https://travis-ci.org/mmaraya/port-mirroring) [![Coverity Scan Build Status](https://scan.coverity.com/projects/6700/badge.svg)](https://scan.coverity.com/projects/mmaraya-port-mirroring)
==============

port-mirroring sends copies of network packets from one or more network interfaces on your OpenWrt router to another device on the network. This is useful for applications that monitor network traffic such as intrusion detection systems, network application debugging, or network performance monitoring. This is a continuation of the work started by Bruce Geng at https://code.google.com/p/port-mirroring/.

Supported Platforms
-------------------

port-mirroring runs on all [hardware platforms supported by OpenWrt](http://wiki.openwrt.org/toh/start). 

Download
--------
port-mirroring v1.4.2 has been tested against OpenWrt Chaos Calmer 15.05 and is available for the the following platform(s):
* Atheros AR71xx/AR724x/913x or "ar71xx" platform: [port-mirroring_1.4.2_ar71xx.ipk] (https://github.com/mmaraya/port-mirroring/releases/download/v1.4.2/port-mirroring_1.4.2_ar71xx.ipk). 

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
    option source_ports 'eth0,wlan0'    # interface(s) to copy packets from
    option target       '10.1.4.2'      # interface or IP address to send packets to
    option protocol     'TEE'           # 'TEE' iptables or 'TZSP' TaZmen Sniffer Protocol 
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
To stop the port-mirroring daemon:
```
root@OpenWrt:~# /etc/init.d/port_mirroring stop
```
To uninstall the port-mirroring package
```
root@OpenWrt:~# opkg remove port-mirroring
```

Build Prerequisites
-------------------

To compile the OpenWrt package, you will need the following:

   * [OpenWrt SDK](http://wiki.openwrt.org/doc/howto/obtain.firmware.sdk)
   * ccache
   * libpcap-dev
   * cppcheck (optional)

License
-------

Please see the file named [LICENSE](https://github.com/mmaraya/port-mirroring/blob/master/LICENSE). 

Issues
------

Please submit questions, comments, bugs, enhancement requests at https://github.com/mmaraya/port-mirroring/issues.

Disclaimer
----------

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

