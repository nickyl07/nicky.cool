---
title: 从Qilin勒索到WSL防护指南
description: "" 
pubDate: 2026-04-18
lastModDate: ''
ogImage: true
toc: true
share: true
giscus: true
search: true
---

勒索软件的攻防博弈正在进入一个全新的阶段。现今，极具代表性的勒索攻击事件：Qilin 勒索软件开始在 Windows 系统中滥用 Windows Linux 子系统（WSL）执行 Linux 加密程序，以此完美规避传统安全工具的检测。

该勒索组织最初于 2022 年 8 月以“Agenda”的名义在暗网推出，随后在同年 9 月更名为 Qilin（麒麟），并一直以此名称高调运营至今，是目前全球最活跃的勒索团伙之一。

攻击者在获取 Windows 主机访问权限后，通过脚本或命令行工具，悄悄在受害主机上启用或安装了 WSL。随后，他们在这个“合法”的环境中部署了基于 Linux 的勒索载荷。这一招，让他们能够直接在 Windows 主机上执行跨平台的加密程序。

这种跨平台的规避策略，让许多专注于Windows常规行为的安全体系形同虚设。本文将深度拆解Qilin的感染链条，并为您提供针对性的防护指南。

## WSL是什么

WSL 是微软为了讨好开发者而在 Windows 系统中内置的一个功能。过去，如果你想在 Windows 电脑上运行 Linux 软件，必须安装虚拟机（如 VMware、VirtualBox）。而有了 WSL，你可以在 Windows 系统内部直接开启一个原生的 Linux 环境，无需双系统，也无需传统的虚拟机。

但恰恰是这个极度便利的功能，成了安全防御的巨大盲区：

首先是视线盲区。传统的 Windows 杀毒软件通常只盯着 Windows 格式的执行文件（PE 文件，如 `.exe` 或 `.dll`）。对于在WSL里运行的 Linux 格式文件（ELF 格式），许多杀毒软件根本“看不懂”也不去管。

与此同时，WSL的环境又并非完全隔离，它可以通过合法的系统通道直接读写外部（Windows 宿主机）的文件。这形成一个天然的漏洞利用通道，只要把勒索软件的ELF挪到WSL里运行，就可以无法无天了，再偷偷通过合法的挂载通道把毒运到windows，加密宿主机的文件，一切简直恰到好处。

## Qilin勒索的全生命周期感染链

了解了 WSL 的机制后，我们再来看 Qilin 的攻击全生命周期。

### 1. 入侵与初始落点

攻击者通常是通过地下黑市购买被盗凭据，直接登录企业暴露在公网且没有开启多因素认证（MFA）的 VPN 或 RDP（远程桌面）端口。“第一落点”，往往是企业内网中一台防备薄弱的普通终端或边缘服务器。

感染链分析：[Qilin EDR killer infection chain](https://blog.talosintelligence.com/qilin-edr-killer/)

### 2. 投放木马与EDR  killer

落地后，攻击者需要瘫痪这台机器乃至整个域内的安全监控。总之就是想方设法地kill杀软。

首先需要进入办公网络，并不被发现。采用合法程序和远程管理工具混合手段入侵网络，利用企业中常见的合法应用，如 AnyDesk、ScreenConnect 和 Splashtop 来建立最初的远程访问权限，把恶意流量伪装成正常的员工远程办公流量。

通过远程通道，将一个合法可执行文件和伪造的 `msimg32.dll` 放置在同一目录下。合法程序启动时，会“侧加载”唤醒恶意 DLL。

这个伪造的 DLL 在内存中运行后，首先切断系统的监控视线——静默压制 Windows 事件追踪（ETW）日志的生成。随后开始向内核层发起致命一击，实施 BYOVD（自带漏洞驱动）攻击。恶意载荷会向系统释放带有合法数字签名但存在已知漏洞的驱动程序（如 `eskle.sys`），并配合释放 `rwdrv.sys`（获取物理内存访问权）和 `hlpdrv.sys` 等特权驱动。借助这些驱动，攻击者获取了最高级别的内核控制权，从而能暴力终止绝大多数主流防病毒和 EDR 进程。

为了确保万无一失，攻击者还会进行多维度的“补刀”破坏：

他们会直接调用命令行触发 EDR 自身的卸载程序（`uninstall.exe`），或使用 `sc stop` 命令强行停止安全服务；同时，结合 `dark-kill` 和 `HRSword` 等开源对抗工具，彻底清理残余的安全组件并抹除自身活动的痕迹。

信息出处：[https://www.bleepingcomputer.com/news/security/qilin-ransomware-abuses-wsl-to-run-linux-encryptors-in-windows/](https://ti.dbappsecurity.com.cn/link?target=aHR0cHM6Ly93d3cuYmxlZXBpbmdjb21wdXRlci5jb20vbmV3cy9zZWN1cml0eS9xaWxpbi1yYW5zb213YXJlLWFidXNlcy13c2wtdG8tcnVuLWxpbnV4LWVuY3J5cHRvcnMtaW4td2luZG93cy8%3D)

### 3.全网域凭据收割

当他们拿下域控制器等核心权限后，攻击者会修改 Active Directory 的域策略，下发一个基于用户登录的组策略对象（GPO）。他们将包含恶意 PowerShell 脚本（如 `IPScanner.ps1`）和批处理文件（如 `logon.bat`）的组合，写入了 SYSVOL（即位于 Active Directory 域内每个域控制器上的共享 NTFS 目录）中。批处理文件（如logon.bat）负责在后台拉起 PowerShell 脚本，直指员工的 Chrome 浏览器。

只要企业员工登录自己的电脑，脚本就会在后台静默运行，瞬间扒空该员工保存在 Google Chrome 等浏览器里的所有账号密码。这意味着，即使企业扛过了勒索攻击，员工私人的网银、第三方云服务、其他业务系统的密码也已全部沦陷，引发灾难性的连环爆雷。

>**SYSVOL** 
>
>在 Windows 的 Active Directory (AD) 域环境中，域控制器 (Domain Controller, 简称 DC) 是整个内网的“最高指挥中心”。而 SYSVOL，就是设在指挥中心里的“中央广播站”和“公告栏”。
>
>物理形态： 它是存在于每一个域控制器硬盘上的一个特殊共享文件夹（默认路径通常是 C:\Windows\SYSVOL\sysvol）。
>
>核心功能： 它专门用来存放企业的公共策略文件和登录/注销脚本。
>
>同步机制： 如果企业有多个域控制器（比如北京机房一个，上海机房一个），SYSVOL 里的内容会自动在所有域控制器之间进行同步复制，确保全公司的策略高度一致。

信息出处：[Qilin ransomware caught stealing credentials stored in Google Chrome | SOPHOS](https://www.sophos.com/zh-cn/blog/qilin-ransomware-caught-stealing-credentials-stored-in-google-chrome)

### 4.核心机密打包与外流

在收割完密码后，动手打包数据前，为了不触发行为监控告警，攻击者会使用 Windows 系统最不起眼的内置工具——如 记事本 (notepad.exe) 和 微软画图(mspaint.exe) ——来人工打开并检查文档，确认数据中是否包含核心机密（如财务报表、源代码、客户数据）。

确认目标后，他们使用 WinRAR 将海量数据打包压缩。并通过 Cyberduck 等合法文件传输工具，将数据神不知鬼不觉地上传到公共云盘（如 Mega）。这批数据将成为他们日后敲诈勒索（不给钱就泄露数据）的核心筹码。

信息出处：[Exposing Data Exfiltration | Huntress](https://www.huntress.com/blog/exposing-data-exfiltration-lolbin-ttp-binaries)

### 5.引入 WSL 实施加密 

当所有值钱的数据和密码都被安全偷走后，攻击者才会真正开始执行勒索。此时，如果直接运行 Windows 勒索病毒，仍有可能被残存的底层机制拦截。

因此，攻击者通过脚本偷偷在目标主机上开启或安装 Windows Linux 子系统（WSL）功能。接着，他们利用WinSCP把专为 Linux 编写的 ELF 格式加密器传入这个“WSL 密室”中，随后通过 Windows 内的 Splashtop 远程管理软件组件（SRManager.exe），结合 `wsl.exe -e` 命令跨界引爆该程序。

这个 ELF 加密器最初是设计用来加密 VMware ESXi 虚拟机和 Linux 服务器的，本身无法在 Windows 上原生运行。但在 WSL 环境的加持下，它如同获得了特许通行证，通过系统挂载通道畅通无阻地加密宿主机文件（甚至包括针对 VMware ESXi 虚拟机的毁灭性加密），完成了对Windows防线的彻底降维打击。

信息出处：[麒麟勒索软件利用WSL在Windows中运行Linux加密器](https://www.bleepingcomputer.com/news/security/qilin-ransomware-abuses-wsl-to-run-linux-encryptors-in-windows/)

>Linux ELF加密器 
>
>ELF 可执行文件 
>
>sha1：5aec6cb027eee95f7ab9055b9fdd261d51d92aec

## WSL防护指南

从Qilin勒索的生命周期中可以知道，传统的"防毒"思路已经失效了。防守方必须从系统底层机制和身份边界入手，实施多维度的收敛与监控。针对此次攻击链，总结出的防护指南如下：

**1. 严格管控并监控 WSL**

WSL 是此次“降维打击”的核心通道。

- **策略禁用：** 对于大多数没有Linux开发需求的普通员工终端和生产服务器，应通过组策略（GPO）或系统配置彻底禁用并卸载 WSL 功能。
- **行为监控：** 如果部分业务确实需要保留 WSL，必须在EDR中配置专门的检测规则，监控 `wsl.exe` 或 `bash.exe` 的异常执行行为。特别是当这些进程由Splashtop、AnyDesk等远程管理工具软件拉起的，或在WSL环境中尝试高频读写Windows挂载盘文件时，应当触发高危告警并阻断隔离。

**2. 防范 BYOVD 攻击与内核驱动滥用**

- **强制驱动拦截：** 在 Windows Defender 或企业终端安全软件中启用“攻击面减少（ASR）”规则，并严格强制实施微软的 易受攻击的驱动程序阻止列表，从根本上卡死漏洞驱动的加载。

- **动态更新威胁情报：** 将安全社区披露的恶意驱动哈希（如本次事件中的 `eskle.sys`、`rwdrv.sys`、`hlpdrv.sys`）及时添加到企业端点防护的全局黑名单中。

- **开启防篡改保护：** 确保所有 EDR 和杀毒软件的自我保护机制处于最高级别，严防恶意软件利用 `sc stop` 命令或直接调用 `uninstall.exe` 破坏安全服务。

**3. 强化远程访问与凭据管理**

攻击者之所以能轻易投放木马，源于被盗凭据和泛滥的远程工具。

- **工具白名单：** 企业内部应统一远程管理工具（如禁止私自安装AnyDesk、TeamViewer等），对允许使用的工具实施严格的进程白名单管理。

- **MFA与权限控制：** 强制所有远程访问入口（VPN、RDP、业务系统门户）使用多因素身份验证（MFA），防止凭据泄露导致的初始突破。

**4.保护 AD 域控**

  鉴于 Qilin 已经开始利用 GPO 下发脚本收割全网浏览器密码，内网的纵深防御必须升级。

- **SYSVOL 监控与 GPO 审计：** 严格限制对域控制器 SYSVOL 共享目录的写入权限。任何非计划内、非常规账号对 GPO 策略的修改（尤其是添加登录/注销脚本如 `logon.bat` 或 PowerShell），必须触发严重安全事件告警。

**5. 提升针对高级规避技术（EDR规避）的检测能力**

- **监控DLL侧加载：** 留意关键业务目录或非系统默认路径下，进程对 `msimg32.dll` 等常见被劫持系统DLL的异常加载行为。
- **异常行为捕捉：** 安全团队应关注进程对ETW的异常修补行为、硬件断点异常（利用VEH进行执行流劫持），以及针对安全产品自身组件（试图运行 `uninstall.exe` 或使用 `sc stop` 命令）的破坏尝试。
