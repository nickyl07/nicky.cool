---
title: “银狐”变种：文件增肥与 PoolParty 注入的高级攻击链路剖析
description: ''
pubDate: 2025-03-31
lastModDate: ''
ogImage: true
toc: true
share: true
giscus: true
search: true
---

## 一、 概述

本报告针对近期捕获的一例“银狐”木马最新变种进行了深度分析 。在此次攻击活动中，攻击者展现了极高的防御规避意识，不仅利用 Themida 加壳与“文件增肥”（File Padding）技术对抗静态查杀，还广泛采用了“白加黑”侧载机制 。在载荷执行阶段，该变种运用了罕见且高级的 PoolParty 进程注入技术，通过劫持 Windows 线程池隐蔽地将恶意代码注入系统核心进程，最终实现对目标系统的深度控制与持久化 。

## 二、 核心威胁指标 (IoCs)

**UnityPlayer.dll** (第一阶段核心组件，209 MB) ：

SHA1: c00000f0feedc9528f96f6624f562459c037daaf 

**VBoxRT.dll** (第二阶段恶意载荷，232 MB) ：

SHA1: ceed164619b274410c1bac27b5f4d9b88fb8c4bf 

**blackdll.dll**：

SHA1: b3caf1a617681c0df30cae15f868ba2c42309f65 

## 三、 攻击链路解析

### **第一阶段：突破防线与隐蔽潜伏 **

- **启动与伪装：** 攻击行动从一个带有 Themida 保护壳的白文件 `Microsoft_Xtools.exe` 开始 。为了躲避安全软件的静态查杀，该程序启动后会侧载同目录下的恶意动态库 `UnityPlayer.dll` 。

- **体积膨胀规避扫描：** 攻击者运用了“文件增肥”（File Padding）技术，在 `UnityPlayer.dll` 的代码尾部追加了大量垃圾数据，使其体积暴增至 209 MB 。这一策略旨在突破部分杀毒引擎对大文件扫描的体积限制，实现免杀 。

### **第二阶段：武器库解包与环境部署**

- **释放加密武器库：** 潜伏成功后，木马会在受害者系统的 `C:\Users\用户名\AppData\Roaming\随机值\` 路径下释放一个名为 `NOT-UTG-Q-1000.dat` 的加密压缩包 。

  ![image-20260308221935248](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260308231626212.png)

- **明文解密获取组件：** 随后，木马直接使用内置的明文密码（如“Panzer0”）对该压缩包进行解密 。解压后，释出第二阶段攻击所需的核心组件，包括白文件 `kitty.exe`，以及 `VBoxRT.dll` 和 `blackdll.dll` 等恶意扩展模块 。

  ![image-20260308221951944](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260308231626213.png)

### **第三阶段：构建双重持久化网络**

为了确保系统重启后木马依然存活，攻击者在注册表中精心构建了一个用户特定的恶意配置目录 `HKEY_USERS\...\Software\DeepSer` ：

- **隐蔽存储路径：** 木马将关键文件的路径分散隐藏在注册表的不同键值中：`MyData` 存储载荷数据 `\\view.res` ；`OpenAi_Service` 存储白文件 `kitty.exe` 的路径 ；`Onload1` 则存储了初始程序 `Microsoft_Xtools.exe` 的路径 。

  ![image-20260308222204231](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260308231626214.png)

- **双重触发机制：** 

  1. **计划任务：** 木马读取注册表获取路径后，调用系统函数 `RegisterScheduledTaskWithPath` 隐蔽注册计划任务 。 

     ![image-20260308222435808](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260308231626215.png)

     ![image-20260308222509564](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260308231626216.png)

     ![image-20260308222517179](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260308231626217.png)

  2. **启动项篡改：** 设置白文件 `kitty.exe` 的自启，将其路径写入系统的 `Run` 注册表项中（命名为 `bfly`） 。恶意模块 `blackdll.dll` 也会辅助打开该注册表项并写入自启动项以确保其执行 。

     ![image-20260308222243094](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260308231626218.png)

### **第四阶段：深度探测与高级注入**

- **内存特征嗅探：** 木马创建进程快照 ，并遍历系统中的所有进程，扫描特定的内存区域，查找是否存在特定字符串 "Ven_sign" 。

  ![image-20260308222346958](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260308231626219.png)

- **PoolParty 线程池注入：** 随后，木马加载并解密出一个名为 `static.ini` 的资源文件，解码后得到真正的攻击载荷 `PoolParty.exe` 。该模块针对系统核心进程 `explorer.exe` 发起了高级的“PoolParty”攻击 。这是一种利用 Windows 线程池机制实现极高隐蔽性的进程注入技术 。

  ![image-20260308222541289](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260308231626220.png)

  ![image-20260308222628362](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260308231626221.png)

  ![image-20260308222639431](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260308231626222.png)

### **第五阶段：核心进程劫持与傀儡替换 **

- **二次进程派生：** 注入到 `explorer.exe` 后，恶意代码会 Dump 出内存中的 `jli.dll` 模块 。

  ![image-20260308222653895](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260308231626223.png)

- **傀儡进程执行：** 该模块的功能是启动一个新的 `explorer.exe` 进程，并将包含恶意指令的 shellcode 代码写入该新进程中执行，彻底完成对系统核心层面的劫持 。

  CommandLine='C:\Windows\explorer.exe'

  ![image-20260308222717164](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260308231626224.png)

### **第六阶段：第二阶段接力与持续远控 **

一旦系统重启或通过计划任务触发，攻击的第二阶段（备用唤醒/接力链）正式启动 ：

- **白加黑唤醒：** 系统启动白文件 `kitty.exe`，该程序随即侧载恶意的 `VBoxRT.dll` 。

  ![image-20260308222751600](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260308231626225.png)

- **持久化控制注入：** `VBoxRT.dll` 运行后，会从之前建立的注册表项 `Software\DeepSer\MyData` 中读取隐藏的 shellcode 代码，并将其注入到合法的 Windows 宿主进程 `rundll32.exe` 中 。

  ![image-20260308222802496](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260308231626226.png)

- **守护进程机制：** 同时，`blackdll.dll` 负责从注册表 `OpenAi_Service` 中读取并确保 `kitty.exe` 的执行 ，形成一个完整的闭环守护机制。

![image-20260308222828423](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260308231626227.png)

打开注册表键写入自启动项

![image-20260308222901397](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260308231626228.png)
