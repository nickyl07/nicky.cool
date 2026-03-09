---
title: Mirai僵尸网络从样本分析到源码构造
description: ''
pubDate: 2024-07-02
lastModDate: ''
ogImage: true
toc: true
share: true
giscus: true
search: true
---
Mirai的主要通过利用弱口令策略感染物联网设备。再通过ssh和Telnet连接感染其他设备。被感染的设备被纳入由攻击者控制的botnet中，以供日后发起大规模的分布式拒绝服务（DDoS）攻击。

#### 僵尸网络的不同模型

##### 集中式僵尸网络

当恶意软件感染设备时，机器人发出定时信号通知 C&C 它已到位。此连接会话保持打开，直到 C&C 准备好命令机器人执行其指令。这种方式使得C&C 能够将命令直接传达给机器人。C&C的缺点是：如果它被关闭，僵尸网络也将失效。

##### 分层 C&C

划分多个层级，拥有多个 C&C。专门的服务器组指定用于特定目的，例如，将机器人组织到小组里来传送指定的内容。

##### 分散式僵尸网络

对等（P2P）僵尸网络是新一代僵尸网络。P2P 机器人不与集中式服务器通信，而是同时充当命令服务器和接收命令的客户端。这避免了集中式僵尸网络固有的单一故障点问题。由于 P2P 僵尸网络无需 C&C 即可运作，因此更难消灭。例如，Trojan.Peacomm 和 Stormnet 就是 P2P 僵尸网络幕后的恶意软件。

## 例样分析

### 样本基本信息

md5:0dee9e5fe04093a2e8724bac441c4d60

filetype: ELF32
arch: ARM
mode: 32
endianess: LE
type: EXEC
  compiler: gcc((GNU) 3.3.2 20031005 (Debian prerelease))[EXEC ARM-32]

tips:

ARM和X86架构最显著的差别是使用的指令集不同。

| 序号  | 架构 | 特点                                                         |
| :---- | :--- | :----------------------------------------------------------- |
| **1** | ARM  | 主要是面向`移动`、`低功耗领域`，因此在设计上更偏重`节能`、`能效`方面 |
| **2** | X86  | 主要面向`家用`、`商用`领域，在`性能`和`兼容性`方面做得更好   |

### 分析样本

（因为ida版本不同 可能导致arm样本不能反编译 实坑 ida8不能 ida7能）

sigemptyset（初始化一个自定义信号集，将其所有信号都清空）

sigaddset（增加一个信号至信号集）

sigprocmask（查询或设置信号遮罩）

signal（设置某一信号的对应动作）

主函数

![image-20240702142702165](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260309195302018.png)

anti_gdb_entry（）

![image-20240708222047786](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260309195304535.png)

resolve_cnc_addr 尝试连接恶意域名，失败则将C2设置为IP地址

resolv_lookup 查找

resolv_entries_free 返回释放

解密：table_unlock_val、table_retrieve_val、table_lock_val 

![image-20240701180908626](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260309195306590.png)

table_unlock_val 密钥变换

![image-20240702101754414](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260309195308642.png)

table_key 密钥

![image-20240702101943299](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260309195313452.png)

table_retrieve_val 数据变换

![image-20240702141202650](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260309195311062.png)

table_lock_val 解密

![image-20240702141818043](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260309195315483.png)

数据包

c2

![image-20240701181845629](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260309195317425.png)



含数据段的部分

所在的函数是attack_method_udphex(）

attack_get_opt_int  初始化命令行参数

rand_next 随机数

send 函数用于在连接的套接字上写入传出数据

![image-20240702100154601](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260309195319800.png)

bind函数作用：服务端用于将把用于通信的地址和端口绑定到 socket 上

![image-20240702100540434](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260309195322191.png)

## Mirai源码分析

![img](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260309195324859.png)

源码获取：[Mirai-Source-Code](https://github.com/nickyl07/Mirai-Source-Code/tree/main/Mirai-Source-Code)

![](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260309195328425.png)

Mirai的源码分为三部分

### dlr

- release目录：存放编译好的多平台dlr
- build.sh：存放gcc的各平台编译命令
- main.c：程序本身

![image-20230720180805182](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260309195331203.png)

### loader

- binary.c           将bins目录下的文件读取到内存中
- connection.c    loader和感染设备telnet交互
- main.c             主函数
- server.c            向感染设备上传payload文件
- telnet_info.c    自定义解析telnet信息
- util.c                一些常用的公共函数

loader的主要功能是向被感染设备上传相应架构的payload。

Loader中存放了针对各个平台编译后的可执行文件，功能是用于加载Mirai中的bot程序。在启动之初就会判断这个文件夹是否存在，然后启用一个epoll架构的简单服务器，一旦有新的连接就启动一个新的worker线程。

首先woker线程使用scanner提供的IP地址和账户密码信息登录IOT设备，执行`/bin/busybox ps`和`/bin/busybox cat /proc/mounts`命令查看设备挂载的分区。然后进行创建文件、使用`chmod`命令调整文件权限至777，之后使用`cpuinfo`命令判断设备运行平台，再使用`wget`、`tftp`或`echo`三种方式将对应版本的恶意可执行文件上传至IOT设备。

在完成装载之后，还会根据下载的类型，运行相应的程序，以上就是整个loader的工作。

### Mirai/bot

- attack模块：解析下发的命令，发起DoS攻击
- scanner模块：扫描telnet弱口令登录，上报给loader
- killer模块：占用端口，kill同类僵尸（排除异己）
- public模块： utils

main.c

阻止`gdb`和`watchdog`的调试，即关闭看门狗。

[^看门狗   ./dev/watchdog]: 通常在嵌入式设备中，固件会实现一种叫看门狗(watchdog)的功能，有一个进程会不断的向看门狗进程发送一个字节数据，这个过程叫喂狗。如果喂狗过程结束，那么设备就会重启，因此为了防止设备重启，Mirai关闭了看门狗功能。

确保只有一个实例的程序在运行，做法：绑定一个特定的端口48101。如果有进程已经占用了这个端口，就直接把它kill掉，这样每个同样的程序绑定这个端口的时候，就会被下一个启动的实例给kill掉。

初始化攻击，调用killer模块 。Killer模块主要是负责排除其他同类的病毒，以防止被抢走控制权。首先检测占用并杀死可能存在的进程，然后直接抢占 22/23/80 端口。这主要是为了排除异己，防止其他程序通过ssh/telnet/http的方式获得控制权。

在此后，他还会搜索特定的文件夹`/proc/$pid/exe`，在这个文件夹中包含了所有正在运行中的进程的程序链接，然后它通过链接直接看程序的真实名称是否含有`.anime`，一旦含有就直接杀死。

实际上这个程序在添加了其他逻辑之后，很快就能针对其他程序进行清除。这里大概只是用`anime`做了一个用法示例。Mirai还扫描了/proc/$pid/status文件，在这个文件中存着进程的一些信息，Killer模块也能根据这些信息对特定的进程进行杀死。

调用Scanner模块。Scanner即扫描器，他所做的是扫描网络中其它未被感染的主机，然后用弱口令尝试登陆，并将能登陆的主机的信息上报给loader，然后由loader对主机进行侵略。

进入bot的主循环，它会主动连接CNC节点并等待CNC节点的指令使用`attackparse`进行解析。在建立连接后，`bot`根据接收到的指令（目标数，IP地址，掩码），对目标进行攻击。

在`attack_app.c`、`attack_gre.c`、`attack_tcp.c`和`attack_udp.c`中分别定义了四大类的攻击类型，然后使用函数指针模拟多态地进行调用。其中攻击的方式大多是通过socket建立大量的SYN包，然后发给目标地址。

### Mirai/cnc

cnc目录主要提供用户管理的接口、处理攻击请求并下发攻击命令。这个目录要求在安装的主机中存在Mysql。它会将管理员和bot的数据，甚至可以使用的命令以及历史存放在数据库中。

- admin.go        处理用户登录、创建新用户以及进行攻击
- api.go             说明api的处理方式
- attack.go        说明如何进行攻击
- clientList.go   管理感染的bot节点
- database.go    数据库管理，包括用户登录验证、新建用户、白名单、验证用户的攻击请求
- main.go          程序入口，开启23端口和101端口的监听

`main.go`监听了23和101端口，分别调用了`initialHandler`和`apiHandler`两个函数。

首先跟随`initialHandler`，若接受数据长度为4，且分别为`00 00 00 x`(x>0)时，为bot监听，将对应的bot主机添加为新的bot。

否则，则判断是否是管理员并进行登录，如果成功登录，则可以通过命令发动攻击。而且如果是管理员账号，还可以通过命令执行管理员帐户添加`adduser`和查询bot数量`botcount`等。

参考：

[Mirai源码阅读 | Ciaran Chen 的博客](https://blog.ciaran.cn/2018/10/09/Mirai源码阅读/)

[cnc · GitBook (drootkit.github.io)](https://drootkit.github.io/MyArticles/Botnet/cnc.html)

[一个基于Mirai的僵尸网络分析 - 『病毒分析区』](https://www.52pojie.cn/thread-1537247-1-1.html)