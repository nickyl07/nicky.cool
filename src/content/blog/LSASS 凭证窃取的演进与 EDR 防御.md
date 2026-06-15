---
title: LSASS凭证窃取的演进与EDR防御
description: "LSASS凭证窃取的相关调研" 
pubDate: 2024-03-05
lastModDate: ''
ogImage: true
toc: true
share: true
giscus: true
search: true
---

## 引言

在 Windows 系统的攻防中，`lsass.exe`（本地安全机构子系统服务）负责处理本地安全和登录策略，内存中驻留着极其关键的明文密码、哈希值和身份验证数据包。对于攻击者而言，一旦获取高权限并成功访问 LSASS 进程内存进行转储（Dump），就等于拿到了横向移动和权限提升的“万能钥匙”。

本文将从安全研究的视角，梳理 LSASS 转储技术从“合法工具滥用”到“底层系统调用”，再到“句柄克隆”的演进路线，并探讨现代 EDR 该如何应对这些高级威胁。

依据工作中写的安全调研内容整理而来。

##  合法签名工具滥用

早期的防御机制主要依赖于黑名单和文件特征查杀。为了规避杀软，攻击者转向了“离地攻击”，即利用系统自带或带有微软官方合法签名的二进制文件来完成内存转储。

- **ProcDump**：作为微软 Sysinternals 套件中的合法调试工具，攻击者常通过 `Procdump64.exe -accepteula -ma lsass.exe lsass.dmp` 这类命令，以管理员权限直接导出完整的内存转储文件。

![image-20240304230410137](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260507221731640.png)
得到转储文件 `lsass.dmp` 后，将其拷贝到 Mimikatz 同目录下执行：

```bat
mimikatz # sekurlsa::minidump lsass.dmp

Switch to MINIDUMP

mimikatz # sekurlsa::logonPasswords full
```

即可获取目标机器的凭证信息 。

通常密码在输入后，经过 wdigest 和 tspkg 模块调用，会使用可逆算法加密存储在内存中，而 Mimikatz 正是通过逆算获取明文密码 。

![image-20240305135759138](https://raw.githubusercontent.com/nickyl07/image/PicGo/202403110941832.png)

- **SQLDumper**：这是包含在 Microsoft SQL 和 Office 中的合法组件。攻击者通过查询 LSASS 的 PID 后，使用 `Sqldumper.exe ProcessID 0 0x01100` 即可导出 mdmp 文件。

![image-20240305141420847](https://raw.githubusercontent.com/nickyl07/image/PicGo/202403110941431.png)

**防御思考：** 这类手法的核心在于“信任滥用”。现代 EDR 已经不能仅靠数字签名来放行文件，必须引入**命令行参数审计**（如监控 `-ma lsass.exe`）和**父子进程调用链分析**。

## 底层 Syscall 与特征剥离

当 EDR 厂商开始在用户态的 Windows API（如 `MiniDumpWriteDump`）挂钩（Hook）进行监控时，传统的转储工具便会立刻触发告警。以 **nanodump** 为代表的现代工具开辟了新的战场：

- **直接系统调用：nanodump 配合 SysWhispers2，直接通过 ntdll 地址调用底层的 Syscall，完美绕过了应用层的系统调用检测钩子。

  ![image-20240313173700241](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260507221655663.png)

- **极致的隐蔽性**：它不仅不调用 dbghelp 等常见库（所有转储逻辑内部实现），还支持无文件落地（不触碰磁盘下载转储文件），甚至默认生成带有无效签名的 MiniDump 文件来规避基于静态特征的检测。后续攻击者只需使用 pypykatz 库即可解析该转储文件 。 

## 句柄克隆与位置无关代码（PIC）

EDR除了Hook API，还会密切监控针对 LSASS 进程的 `ProcessAccess`（进程访问）事件。为了在不触发访问告警的情况下窃取数据，攻击者引入了更底层的混淆手法：

- **HandleKatz 的克隆机制**：该工具另辟蹊径，使用 LSASS 的克隆句柄来执行操作。这意味着它不需要直接打开 LSASS，从而在源头上避免了被 EDR 观察到 ProcessAccess 事件。

- **Shellcode 混淆执行**：HandleKatz 会被编译为完全与位置无关的代码（PIC），这意味着它可以被当作一段 Shellcode 直接加载到内存中运行，并通过系统调用将高度混淆的转储文件写入磁盘，极大地增加了分析和拦截的难度。

  主要生成三个文件

  bin/HandleKatzPIC.exe     bin/HandleKatz.bin      bin/loader.exe 

  **bin/HandleKatzPIC.exe**  它编译为完全存在于其文本段中的可执行文件。因此，PE 文件提取的 .text 段是完全与位置无关的代码 （=PIC），这意味着它可以像对待任何 shellcode 一样对待。

  **bin/HandleKatz.bin**  是bin/HandleKatzPIC.exe  pe--->shellcode

  **bin/loader.exe** 加载 bin/HandleKatz.bin

>位置无关代码（PIC）： 位置无关代码是一种编程技术，它使得代码不依赖于特定的内存地址。这意味着无论在内存中的哪个位置加载共享库，它都可以正常工作。这是通过使用相对寻址和基址寄存器等技术来实现的。PIC的使用使得多个进程可以共享同一库的单一副本，从而减少内存占用，并减少重复的代码加载。这对于系统中有多个进程需要使用相同库的情况非常有用。

![image-20240313180555951](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260507221654332.png)

HandleKatz现在没办法克隆句柄了，被守护进程保护了，所以这个工具失效了。

## 防线迭代

尽管攻击手法不断迭代，但防御体系也在不断进化。

- **LSA 保护（PPL）**：微软引入的 LSA 保护策略，直接在内核层面对 `lsass.exe` 进行保护，防止非受信任的代码注入。虽然攻击者曾开发出 mimidrv.sys 等驱动程序试图绕过，但这无疑大幅拉高了攻击门槛。
- **句柄防护的胜利**：在近期的实战防御验证中，我们发现曾经风光无限的 **HandleKatz 实际上已经失效**。现代的高级守护进程保护机制加强了对 `DuplicateHandle` 等句柄克隆行为的底层监控，导致其克隆句柄的核心能力被彻底阻断。