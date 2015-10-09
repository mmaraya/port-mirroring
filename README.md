port-mirroring
==============

port-mirroring sends copies of network packets from one network interface to another device on the network. This is useful for applications that monitor network traffic such as intrusion detection systems, network application debugging, or network performance monitoring. This is a continuation of the work started by Bruce Geng  at https://code.google.com/p/port-mirroring/ as that project does not appear to be actively maintained.

Supported Platforms
-------------------

port-mirroring runs on all [hardware platforms supported by OpenWrt](http://wiki.openwrt.org/toh/start). 

Download
--------
port-mirroring v1.4.0 has been tested against OpenWrt Designated Driver (Bleeding Edge, r47045) and is available for the the following platform(s):
* Atheros AR71xx/AR724x/913x or "ar71xx" platform: [port-mirroring_1.4_ar71xx.ipk] (https://github.com/mmaraya/port-mirroring/releases/download/v1.4.0/port-mirroring_1.4_ar71xx.ipk). 

If you need binaries for your router architecture, please submit a [request](https://github.com/mmaraya/port-mirroring/issues). 


Usage
-----
These instructions will only work on routers that use the Atheros AR71xx/AR724x/913x or "ar71xx" platform. You will need a different package if your router does not use the ar71xx platform.  If your does not use the ar71xx platform, please submit a [request](https://github.com/mmaraya/port-mirroring/issues).

From your OpenWrt terminal, run the following command to install the precompiled package:
```
root@OpenWrt:~# opkg install https://github.com/mmaraya/port-mirroring/releases/download/v1.4.0/port-mirroring_1.4_ar71xx.ipk
```
Modify the `/etc/config/port-mirroring` file to suit your environment.  
```
config 'port-mirroring'
	option 'target' '192.168.2.5'
	option 'source_ports' 'eth1'
	option 'filter' ''
	option 'protocol' 'TEE'
```
   * Set the `target` option to the IP address to copy packets to
   * Set the `source_ports` option to the network interface you want to copy packets from
   * Set the `filter` option to [pcap-filter](http://www.tcpdump.org/manpages/pcap-filter.7.html) expressions
   * Set the `protocol` to use either the `TEE` [iptables](http://ipset.netfilter.org/iptables-extensions.man.html)  or `TZSP` [TaZmen Sniffer Protocol](https://en.wikipedia.org/wiki/TZSP) formats

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

License
-------

Please see the file named [LICENSE](https://github.com/mmaraya/port-mirroring/blob/master/LICENSE). 

Issues
------

Please submit questions, comments, bugs, enhancement requests at https://github.com/mmaraya/port-mirroring/issues.

Disclaimer
----------

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

