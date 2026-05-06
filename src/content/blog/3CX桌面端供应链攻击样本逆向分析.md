---
title: 3CX桌面端供应链攻击样本逆向分析
description: “信任滥用”与“防御逃逸”
pubDate: 2024-03-04
lastModDate: ''
ogImage: true
toc: true
share: true
giscus: true
search: true
---

本文对2023年著名的3CX供应链攻击事件中的恶意样本进行了全链路逆向分析。攻击者通过篡改合法的 `ffmpeg.dll` 进行DLL侧载，利用 CVE-2013-3900 漏洞在微软签名的 `d3dcompiler_47.dll` 尾部隐藏加密Shellcode，并结合 GitHub 图标隐写术获取C2配置，最终窃取受害者浏览器敏感数据。本文详细记录了从样本提取、去混淆、Shellcode调试到核心逻辑还原的完整过程。

## 攻击链

整个攻击流程设计极为隐蔽，采用了多层加载机制：

1. **初始触发**：用户运行合法的 `3CXDesktopApp.exe`。
2. **白加黑（DLL侧载）**：程序加载恶意的 `ffmpeg.dll`。
3. **签名绕过加载**：`ffmpeg.dll` 读取并解密 `d3dcompiler_47.dll` 尾部的Shellcode（利用签名验证漏洞）。
4. **环境检测与持久化**：检查Manifest时间戳，实现潜伏期控制。
5. **C2隐蔽通信**：访问 GitHub 仓库下载 `.ico` 图标，利用隐写术解析出加密的C2地址。
6. **最终行为**：下载后续 InfoStealer 载荷，窃取浏览器（Chrome/Edge/Firefox）历史记录与凭据。

## 样本基础信息

本次分析主要围绕 MSI 安装包及其释放的关键 DLL 文件展开。

| 文件名                          | 类型      | 说明                    | MD5                                |
| ------------------------------- | --------- | ----------------------- | ---------------------------------- |
| **3CXDesktopApp-18.12.416.msi** | Installer | 恶意安装包              | `0eeb1c0133eb4d571178b2d9d14ce3e9` |
| **ffmpeg.dll**                  | DLL       | 被篡改的加载器 (Loader) | `74bc2d0b6680faa1a5a76b27e5479cbc` |
| **d3dcompiler_47.dll**          | DLL       | 携带Shellcode的白文件   | `82187ad3f0c6c225e2fba0c867280cc9` |

## 逆向分析

### 初始触发与加载：Loader分析 (ffmpeg.dll)

安装并运行 `3CXDesktopApp.exe` 后，程序会自动加载目录下的 `ffmpeg.dll`。这本是一个用于音视频处理的开源库，但攻击者对其进行了恶意修改。

![image-20240304104113994](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260221221607493.png)

**单实例互斥机制：** 在 `DllMain` 或初始化函数中，恶意代码首先创建一个名为 `AVMonitorRefreshEvent` 的事件对象。如果创建失败，说明程序已在运行，随即退出。这是恶意软件常见的防多开与反沙箱对抗手段。

![image-20240317213412769](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260221221612554.png)

*ffmpeg.dll 创建事件以保证单实例运行*

### 签名绕过加载：Payload 提取与内存执行 (d3dcompiler_47.dll)

`ffmpeg.dll` 的核心任务是加载同目录下的 `d3dcompiler_47.dll`。

**[CVE-2013-3900 签名验证漏洞利用](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2013-3900)：** 查看 `d3dcompiler_47.dll` 的属性，发现其拥有有效的微软数字签名。然而，攻击者利用了 WinVerifyTrust 的一个已知机制（CVE-2013-3900）：在经过签名的PE文件尾部追加数据，不会破坏签名的有效性。

![image-20240304105015276](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260221221610434.png)

*文件具备有效的微软数字签名*

![image-20240317214032067](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260221221617554.png)

![image-20240304105434737](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260221221619666.png)

在十六进制编辑器中查看文件末尾，可以清晰地看到在正常的PE数据之后，附加了大量看似杂乱的数据。

**Shellcode 定位与解密：** 通过逆向分析 Loader 代码，发现其会在内存中搜索特征码 `0xFE 0xED 0xFA 0xCE`（Feed Face），以此作为加密数据的起始标记。

![image-20240317214210988](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260221221624739.png)

![image-20240315182920144](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260221221622066.png)

找到数据块后，Loader 使用 **RC4算法** 进行解密。解密后的数据是一段可执行的 Shellcode。

![image-20240317220536940](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260221221627957.png)

**标准的无文件落地内存加载：** 解密完成后，代码调用 `VirtualProtect` 将该内存区域属性修改为 `PAGE_EXECUTE_READWRITE` (RWX)，随后通过 `call` 指令跳转执行，正式进入下一阶段。

![image-20240317221345962](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260221221629708.png)

### 环境检测与隐蔽通信：“7天+”潜伏与C2获取 (Icon隐写术)

Shellcode 运行后，首先展现出了持久化与潜伏特性。它会读取配置文件（Manifest），检查时间戳。如果未达到预设时间，它会写入当前时间并休眠 **7天+**，这种设计极大地增加了沙箱检测的难度。

这里的“预设时间”，是一个“基础休眠 + 随机抖动”的动态时间戳。

Preset Time = Current Time + 604800 + (rand() mod1800000)

动态时间戳 = 当前时间 + 604800 秒（7 天）+ rand() % 1800000 秒（一个随机数）

写进 `manifest` 文件里的“预设时间”，是当前时间往后推 7 天 到 28 天 之间的一个“随机未来时间点”。

![image-20240320152803816](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260221221633156.png)

**GitHub 图标隐写 (Steganography)：** 这是该样本最显著的特征。恶意代码并不直接连接硬编码的C2 IP，而是访问 GitHub 上的一个仓库： URL结构：`https://raw.githubusercontent.com/IconStorages/images/main/icon%d.ico`

![image-20240320163245194](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260221221636356.png)

![image](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260221221638080.jpeg)

表面上看这是普通的图标文件，但分析下载的 `.ico` 文件，发现其文件尾部被附加了 Base64 编码的字符串。

![image-20240325182353056](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260221221640023.png)

**C2 解析流程：**

**识别特征**：寻找以 `$` 符号开头的 Base64 数据段。

![image-20240325182617974](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260221221641418.png)

**解密算法**：使用 **AES-GCM** 算法对 Base64 解码后的数据进行解密。

![image-20240325183011132](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260221221643926.png)

**获取C2**：解密结果即为真实的命令控制服务器（C2）地址。

![img](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260221221645378.jpeg)

最终解密出的C2地址如下所示，Shellcode 将连接此地址下载最终的窃密组件。

### 最终行为：窃密行为分析 (InfoStealer)

最终下发的 Payload 是一个专门的信息窃取模块。分析其字符串和API调用，可以确认其主要目标是主流浏览器的用户数据。

**目标浏览器：**

- Google Chrome
- Microsoft Edge
- Brave
- Mozilla Firefox

![image-20240401144824765](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260221221648803.png)

**窃取内容：** 恶意代码会遍历用户数据目录，重点寻找 `History` (Chromium系) 和 `places.sqlite` (Firefox) 数据库文件。

![image-20240401145118924](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260221221650202.png)

通过SQL查询语句，它会提取最近的浏览记录（样本中限制为500条），这些信息可能包含内网入口、云服务凭证等高价值情报，符合APT攻击的侦察特征。

![image-20240401143013981](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260221221652234.png)

## 结论

3CX供应链攻击展示了高级威胁组织（APT）的高超技艺。通过污染开发环境，攻击者实现了对下游大量企业的无感渗透。技术层面上，**利用微软签名漏洞隐藏Shellcode** 以及 **利用GitHub进行隐写通信**，使得常规的安全检测手段（如文件签名校验、流量信誉检测）极易失效。

### IOC

**Hash (MD5):**

- `0eeb1c0133eb4d571178b2d9d14ce3e9` (MSI Installer)
- `74bc2d0b6680faa1a5a76b27e5479cbc` (Malicious ffmpeg.dll)
- `82187ad3f0c6c225e2fba0c867280cc9` (d3dcompiler_47.dll with Shellcode)

**Signature:**

- Shellcode Magic Bytes: `FE ED FA CE`
- Icon Steganography Marker: `$`

本文分析过程参考了 FreeBuf 及知乎相关安全研究人员的公开报告，并在独立复现中进行了验证。

参考：

[3CXDesktopApp遭遇APT组织供应链攻击分析报告 - FreeBuf网络安全行业门户](https://www.freebuf.com/articles/system/362686.html)

[针对3CX供应链攻击样本的深度分析 - 知乎 (zhihu.com)](https://zhuanlan.zhihu.com/p/638839053)