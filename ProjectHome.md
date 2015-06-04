《西厢计划第二季》能突破GFW的 **IP封锁** 和 **URL关键词过滤** 。

它的实现原理是利用GFW的单向IP封锁特性，将 **发出** 的数据包通过国外的第三方服务器中转，而收到的数据包 **穿过GFW直接到达客户端** 。当用HTTP方式观看在线视频或下载大文件时，对中转服务器仅耗费 **极小的流量** 。

同时，由于GFW只能捕捉到单向的流量， ~~无法建立TCP状态机~~ 无法获取请求URL，关键词过滤也就失效了。


# 使用方法： #

## 下载与编译 ##

下载源代码：

svn checkout http://west-chamber-season-2.googlecode.com/svn/trunk/ west-chamber-season-2-read-only

安装libpcap库后进入目录后直接make

## 在中转服务器上执行： ##


./wcs2\_fwd 12345

## 在客户端上执行： ##

# 阻止路由器发来的“ttl exceeded”消息

sudo iptables -t filter -I INPUT -p icmp --icmp-type ttl-exceeded -j DROP

# 将发出数据的TTL设置为5，不会到达GFW

sudo iptables -t mangle -I OUTPUT -d 被封锁的IP地址 -j TTL --ttl-set 5

# 把包搞小一点，才能塞进一个UDP包

sudo ifconfig eth0 mtu 1300


./wcs2\_cli eth0 _客户端的公网IP地址_ _中转服务器的IP地址_ 12345


## 补充说明 ##

《西厢计划第二季》为独立的新项目，与原西厢计划没有关联，只是借用了一下品牌～～～。西厢计划第二季和西厢计划都是tech demo，发布出来不是给你用的，而是给你研究的。