---
title: WannaCry勒索病毒深度解构
description: '' 
pubDate: 2025-07-20
lastModDate: ''
ogImage: true
toc: true
share: true
giscus: true
search: true
---
本文针对 WannaCry 勒索病毒样本（SHA1: 5ff465afaabcbf0150d1a3ab2c2e74f3a4426467）进行深度行为分析。不同于传统潜伏型木马或破坏型病毒，该样本表现出典型的**“拒绝服务式勒索”**特征。本文将以病毒的完整生命周期（释放 -> 遍历 -> 加密 -> 勒索 -> 清理）为脉络，剖析其运作机制及技术特性。

## 样本概述与类型特征

SHA1: 5ff465afaabcbf0150d1a3ab2c2e74f3a4426467

![image-20240814171222677](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260221222105638.png)

**勒索病毒与传统恶意软件的行为差异对比**

| 特征维度         | 传统木马 (Trojan/RAT)  | 破坏性病毒 (Wiper)     | **勒索病毒 (WannaCry)**                      |
| ---------------- | ---------------------- | ---------------------- | -------------------------------------------- |
| **核心目的**     | 窃取数据、长期潜伏控制 | 彻底破坏系统、造成瘫痪 | **加密数据、勒索赎金**                       |
| **隐蔽性**       | 极高                   | 低                     | **先隐蔽 (加密前) -> 后高调 (勒索时)**       |
| **对数据的操作** | 读取、回传             | 删除、覆写 (不可逆)    | **加密 (理论可逆，需私钥)**                  |
| **系统稳定性**   | 极力维护系统正常运行   | 不在乎系统是否崩溃     | **刻意避开系统文件，确保OS能运行以支付赎金** |

## 第一阶段：Payload 释放与环境初始化

WannaCry 并非单兵作战，它携带了一个庞大的“军火库”。在样本运行初期，它的首要任务不是加密，而是将这些工具释放出来，表现为典型的 Dropper 行为。

### 1. 资源解压与组件释放

样本通过硬编码密码 `WNcry@2ol7` 解密自身的资源段，并释放以下关键组件至运行目录。

![image-20240814174017725](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260221222109086.png)

解压资源文件 释放资源 解压密码为 Str='WNcry@2ol7'

![image-20240911155645377](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260221222118553.png)

解压后，我们在系统目录中会看到以下关键组件，它们分工明确：

![image-20240816170327025](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260221222120845.png)

- **核心加载器 (`tasksche.exe`)**：负责维持病毒运行状态。
- **加密引擎 (`t.wnry`)**：核心 Payload，以 DLL 形式存在，负责文件遍历与加密操作。
- **交互界面 (`u.wnry` / `@WanaDecryptor@.exe`)**：负责展示勒索信、倒计时及解密演示。
- **匿名通信 (`s.wnry`)**：包含 Tor 客户端组件，用于建立隐蔽的 C2 通信通道。

### 2. 反多重实例与权限提升

- **互斥体 (Mutex)**：样本调用 `CreateMutexA` 创建名为 `MsWinZonesCacheCounterMutexA` 的互斥体。防止同一台机器上运行多个加密进程，避免造成资源竞争或文件被重复加密（导致无法解密）。

  *互斥体检查在t.wnry解密后。

  ![image-20240918144017432](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260221222124140.png)

- **环境隐蔽**：通过 `attrib +h` 将工作目录设为隐藏，并使用 `icacls . /grant Everyone:F` 授予全员读写权限，确保加密模块在遍历文件时不会因权限问题被中断。

  ![image-20240819105247980](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260221222125959.png)

### 3. 匿名通信网络的建立

  勒索软件最大的痛点是如何安全地收钱。WannaCry 集成了 Tor（洋葱路由） 组件。

  它会读取 c.wnry 配置文件，其中存储了暗网的连接节点。通过 s.wnry 释放的Tor程序，病毒建立了一条无法被追踪的加密隧道，用于上传受害者密钥和获取勒索信内容。

  c.wnry内容：服务器链接和Tor下载链接

  ![image-20240909162233256](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260221222129378.png)

  s.wnry内容：压缩文件，打包的是Tor相关组件

  ![image-20240909170252831](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260221222131435.png)

  在三个比特币交易地址中随机选择一个，写入c.wnry

  ![image-20240904152306306](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260221222245123.png)

## 第二阶段：高价值资产甄别

这是勒索病毒区别于其他破坏性病毒最显著的特征之一。 它的目标不是为了破坏操作系统，而是为了“绑架”用户数据。因此，它内置了一套精密的文件过滤机制。

![image-20240919154433777](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260221222242338.png)

### 1. 避让关键系统目录

分析 `sub_100032C0` 等函数可知，病毒会显式跳过 `Windows`、`Program Files` 等系统目录。

- *战术意图*：如果加密了系统核心 DLL 或 EXE，系统将无法启动，用户也就无法看到勒索界面并支付赎金。**勒索病毒需要宿主“活着”才能收钱。**

### 2. 精确打击高价值数据

勒索病毒通常不会加密系统文件（如exe, dll），因为这会导致系统崩溃，用户无法支付赎金。WannaCry 内置了一份详细的**“高价值目标清单”**。

它会遍历磁盘文件，根据后缀名进行筛选：

跳过勒索病毒组件，@Please_Read_Me@.txt，@WanaDecryptor@.exe.lnk，@WanaDecryptor@.bmp，指定感染后缀WNCRYT，WNCYR，WNCRY。

加密以下后缀，办公文档、设计图纸、压缩包与镜像、开发代码。

```C++
“.doc”".docx”".xls”".xlsx”".ppt”".pptx”".pst”".ost”".msg”".eml”".vsd”".vsdx”

“.txt”".csv”".rtf”".123″”.wks”".wk1″”.pdf”".dwg”".onetoc2″”.snt”".jpeg”".jpg”
```

```C++
“.docb”".docm”".dot”".dotm”".dotx”".xlsm”".xlsb”".xlw”".xlt”".xlm”".xlc”".xltx”".xltm”".pptm”".pot”".pps”".ppsm”".ppsx”".ppam”".potx”".potm”

“.edb”".hwp”".602″”.sxi”".sti”".sldx”".sldm”".sldm”".vdi”".vmdk”".vmx”".gpg”".aes”".ARC”".PAQ”".bz2″”.tbk”".bak”".tar”".tgz”".gz”".7z”".rar”

“.zip”".backup”".iso”".vcd”".bmp”".png”".gif”".raw”".cgm”".tif”".tiff”".nef”".psd”".ai”".svg”".djvu”".m4u”".m3u”".mid”".wma”".flv”".3g2″”.mkv”

“.3gp”".mp4″”.mov”".avi”".asf”".mpeg”".vob”".mpg”".wmv”".fla”".swf”".wav”".mp3″”.sh”".class”".jar”".java”".rb”".asp”".php”".jsp”".brd”".sch”

“.dch”".dip”".pl”".vb”".vbs”".ps1″”.bat”".cmd”".js”".asm”".h”".pas”".cpp”".c”".cs”".suo”".sln”".ldf”".mdf”".ibd”".myi”".myd”".frm”".odb”".dbf”

“.db”".mdb”".accdb”".sql”".sqlitedb”".sqlite3″”.asc”".lay6″”.lay”".mml”".sxm”".otg”".odg”".uop”".std”".sxd”".otp”".odp”".wb2″”.slk”".dif”".stc”

“.sxc”".ots”".ods”".3dm”".max”".3ds”".uot”".stw”".sxw”".ott”".odt”".pem”".p12″”.csr”".crt”".key”".pfx”".der”
```

## 第三阶段：混合加密机制实现

这是勒索病毒最核心的环节。WannaCry 的加密逻辑位于 `t.wnry` 这个伪装成文件的DLL中。

首先，t.wnry是加密文件，所以需要解密后再做分析。

![image-20240909174105447](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260221222237413.png)

在样本母体中存在对t.wnry文件解密的函数。

![image-20260115163509343](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260221222235713.png)

提取t.wnry文件，只需在病毒母体运行解密函数后，将文件从中剥离出来。

运行解密函数后，跳出做比较的位置，在这里可以直接看到完整的文件头。在EAX处右键—>在内存窗口转到 就到达程序入口。

![image-20240916170533363](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260221222233455.png)

t.wnry的大小

![image-20240916173122197](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260221222230676.png)

dump

![image-20240916173202210](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260221222228589.png)

这样就直接剥离出来啦

## t.wnry

### TaskStart

![image-20240918143423002](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260221222223893.png)

![image-20240918143509833](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260221222221678.png)

### 2. 密钥生成与管理架构

WannaCry 使用了 **AES + RSA** 的混合加密方式，这也是现代勒索病毒的标配：

1. **文件级加密**：使用 **AES算法** 加密文件内容。AES是对称加密，速度快，适合大文件。
2. **密钥级加密**：使用 **RSA算法** 加密刚才生成的AES密钥。RSA是非对称加密，只有攻击者手中的私钥才能解密。

这意味着，即使你提取出了内存中的AES密钥，由于它已经被公钥锁死，没有黑客的私钥，这些数据依然是废铁。

#### AES+RSA 混合加密

❶ 生成随机的 AES 密钥（WannaCry 为每个文件生成唯一的 AES 密钥，在`encryption_start_entry`的内存分配后执行）；

![image-20260116142639223](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260221222218285.png)

❷ 用 AES 密钥加密文件内容；

❸ 用 RSA 公钥加密 AES 密钥；

❹ 存储加密后的 AES 密钥。

![image-20260116165202509](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260221222216052.png)

### 3. 多线程并发

为了追求速度，病毒会根据文件大小采取不同策略。

- **小文件**：全量加密。
- **大文件**：采用部分加密策略。在保证文件结构被破坏（无法打开）的同时，极大地缩短了磁盘 I/O 时间，提高了攻击效率，减少了被行为防护软件拦截的窗口期。

![image-20260116182003903](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260221222213439.png)

标准化.WNCRY后缀 + 触发加密/删除逻辑

![image-20260116193225655](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260221222211150.png)

执行差异化加密的函数

![image-20260116195124740](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260221222208478.png)、

## 第四阶段：胁迫与持久化

当文件被锁死后，病毒转入“高调”模式。

### 1. 视觉冲击

修改注册表设置开机自启，并强制替换桌面壁纸为 `b.wnry`，并弹出 `@WanaDecryptor@.exe` 窗口。窗口设计包含了倒计时、支持多语言、以及“解密演示”功能，这些都是典型的社会工程学手段。

##### 设置勒索壁纸

![image-20260116195844986](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260221222206007.png)

##### 弹出`@WanaDecryptor@.exe` 窗口

运行 `@WanaDecryptor@.exe` (即 `u.wnry`)。这是一个封装完善的GUI程序，它不仅显示倒计时，还提供了“解密演示”功能，通过解密几个小文件来诱导用户相信支付赎金真的有效。

![image-20260116200629330](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260221222202937.png)

### 2.持久化驻留

##### 设置开机启动项

![image-20240919150840858](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260221222159016.png)

## 第五阶段：扫尾与反取证

为了防止用户通过数据恢复软件找回文件，WannaCry 最后会派出 `taskdl.exe`。

这个程序主要负责**清理战场**：

1. 监控并删除生成的临时文件 (`.WNCRYT`)。
2. **清空回收站**：确保用户无法找回被删除的原始文件。
3. 在很多变种中，还会调用 `vssadmin` 删除系统的**卷影副本（Shadow Copies）**，彻底断绝Windows自带的系统还原之路。

![image-20260116201446813](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260221222154186.png)

## 总结

WannaCry 是勒索病毒发展史上的分水岭。在 WannaCry 出现前（2017 年之前），勒索病毒的主流传播方式是**被动钓鱼**—— 通过恶意邮件附件、恶意链接诱导用户点击，传播范围有限，依赖受害者的主动操作。而 WannaCry 首次大规模利用 **NSA 泄露的 “永恒之蓝” 漏洞（MS17-010）**，实现了**主动扫描 + 自动传播**。从技术角度看，它展示了现代勒索软件的成熟形态：

1. **利用高危漏洞传播**（永恒之蓝 SMB 漏洞）。
2. **采用工业级加密体系**（AES+RSA），彻底断绝了暴力破解的可能。
3. **精细的资产定位**，只针对有价值数据，避开系统文件。
4. **完善的对抗机制**，包括反取证和反恢复。

**针对此类病毒的防御侧重点：**

- **边界防御**：修补 SMB 等高危服务漏洞（阻断传播）。
- **行为监测**：监控高频的文件重命名/写入操作，以及敏感指令（如 `vssadmin` 的调用）。
- **冷备份**：由于其加密机制不可逆，**离线备份**是数据恢复的唯一底牌。

------

## WNCRY的所有涉及文件

- msg 语言文件
- c.wnry 存储了比特币账户 Tor下载链接 跟勒索相关 
- t.wnry 隐藏了一个dll文件 dll的导出函数是病毒的核心代码 
- u.wnry 是@WanaDecryptor@.exe 解密器
- r.wrny 勒索文档
- s.wnry 压缩文件，打包的是Tor相关组件
- taskse.exe 提权
- taskdl.exe删除临时文件和回收站的.WNCRY文件
- 00000000.pky 公钥
- 00000000.eky 被加密的私钥 
- 00000000.res 八个字节的随机数和当前时间
- .bat为解密器创建快捷方式
