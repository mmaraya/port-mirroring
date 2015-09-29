port-mirroring
==============

port-mirroring sends copies of network packets from one network interface to another device on the network. This is useful for applications that monitor network traffic such as intrusion detection systems, network application debugging, or network performance monitoring. This is a continuation of the work started by Bruce Geng  at https://code.google.com/p/port-mirroring/ as that project does not appear to be actively maintained.

Supported Platforms
-------------------

port-mirroring runs on all [hardware platforms supported by OpenWrt](http://wiki.openwrt.org/toh/start). 

Download
--------


Usage
-----


License
-------

Please see the file named LICENSE. 

Issues
------

Please submit questions, comments, bugs, enhancement requests at https://github.com/mmaraya/port-mirroring/issues.

Disclaimer
----------

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
This package contains:

Build Instructions
------------------
```
autoreconf --install --force
./configure
make
