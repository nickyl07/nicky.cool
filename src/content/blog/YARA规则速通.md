---
title: YARA规则速通
description: "" 
pubDate: 2026-05-11
lastModDate: ""
ogImage: true
toc: true
share: true
giscus: true
search: true
---

# YARA规则速通

之前从事的工作中，有过编写拦截规则、防误报添加白特征的经验。基本上是有所用当即学，学完马上进行实践。学习就是从模仿开始，上手和上线都没什么坎坷，很顺利。跟规则组的同事交流，他也说前司使用的规则是比YARA更简单些的。现在有求职需求，所以想要稍微系统的对YARA规则进行一下速通。

------

## 一、 宏观认知：运行逻辑与实战方法

### 核心组件

YARA 的核心组件与“杀毒引擎逻辑”对照：

| **组件名称**           |      | **杀毒引擎逻辑** | **功能描述**                                                 |
| ---------------------- | ---- | ---------------- | ------------------------------------------------------------ |
| **YARA 规则 (`.yar`)** |      | **病毒库**       | 定义了“坏人”的静态特征。维护规则库 = 维护杀软公司的私有病毒库。 |
| **YARA 引擎 (Engine)** |      | **扫描引擎**     | 它是干活的程序。静态扫描 = 引擎加载规则对文件执行匹配的过程。 |
| **扫描目标 (Target)**  |      | **待检样本**     | 规则比对的对象，可以是磁盘文件、文件夹或内存镜像。           |

把**规则**喂给**引擎**，告诉引擎去扫描**目标**。引擎经过对比后，输出**结果**（命中或没命中）。

### 实战落地场景

YARA 规则本身是静态文本，只有依托不同平台的 YARA 引擎才能发挥作用：

#### VT实践：

VT 的后台有成百上千台服务器，这些服务器上都安装了**YARA 引擎**。

- **常规扫描**：当用户上传一个文件（比如 `test.exe`）到 VT 时，VT 会自动调用它的 YARA 引擎，加载各大安全厂商和社区开源的**海量 YARA 规则库**，对着 `test.exe` 扫一遍。如果命中了，网页上就会显示“匹配到了某某 YARA 规则”。
- **高级玩法（VT Livehunt / 实时狩猎）**：这是高级安全专员常用的功能。你可以把**你自己写的 YARA 规则**上传到 VT 平台保存。从这一刻起，全球任何一个人只要上传了新文件到 VT，VT 的引擎就会顺便用你的规则扫一下。如果命中了，VT 就会给你发一封邮件：“嘿！有人刚刚上传了你正在追踪的那个病毒！”
- **高级玩法（VT Retrohunt / 回溯狩猎）**：你写了一条新规则，VT 用它的引擎，拿着你的规则，去扫描 VT 过去 10 年里收集的所有历史病毒库。这就是大海捞针，用来做威胁情报溯源。

#### 本地实践：

面试时如果要求你实操，通常是这种形式：

1. 你在电脑上下载了官方的 YARA 程序（比如 `yara.exe`）。
2. 你新建了一个文本文件 `my_rule.yar`，写好你的规则。
3. 你怀疑 D 盘的 `Downloads` 文件夹里有病毒。
4. 你打开命令行（CMD），输入命令： `yara.exe my_rule.yar D:\Downloads\`
5. **引擎**立刻启动，读取规则，扫遍整个文件夹。如果发现病毒，就会在屏幕上打印出来：`Catch_Simple_Trojan D:\Downloads\bad_file.exe`。

------

## 二、 基础语法：规则的三大核心结构

一个Yara规则由三部分组成，规则名称和元数据、字符串部分以及条件部分。

**规则名称和元数据：**

- 每个YARA规则都有一个唯一的名称。
- 元数据部分包含作者、规则描述、日期等信息，通常用来记录规则的背景和用途。

**字符串部分：**

- 定义需要匹配的字符串，可以是文本字符串、十六进制字符串或正则表达式。
- 支持各种字符串修饰符，如nocase（忽略大小写）、wide（宽字符）和ascii（ASCII字符）。

**条件部分：**

- 指定匹配条件，定义字符串或模式出现的条件。
- 支持布尔逻辑、位置匹配和计数等条件。

示例

```c
rule MaliciousFile
{
    meta:
        author = "Jane Doe"
        description = "Detects files containing the malicious string"
        date = "2024-07-29"

    strings:
        $malicious_string = "malicious"
        $malicious_hex = { 6D 61 6C 69 63 69 6F 75 73 }
        $malicious_regex = /malicious/i

    condition:
        $malicious_string or $malicious_hex or $malicious_regex
}
```

------

## 三、 进阶理论：规则类型与特征提取策略

基于[《50 Shades of YARA》](https://www.nextron-systems.com/2019/01/02/50-shades-of-yara/)的方法论，安全专家在编写规则时应具备“目标导向”思维。

### 规则的三大类型

| **规则类型**                    | **细分场景**                    | **核心理念**                                                 |
| ------------------------------- | ------------------------------- | ------------------------------------------------------------ |
| **常规规则 (Regular)**          | **威胁检测 (Threat Detection)** | **宁漏杀绝不误报**。条件极其严格（如需命中 6 个特征），常用于杀软自动清理。 |
|                                 | **威胁狩猎 (Threat Hunting)**   | **宁误报不漏杀**。条件宽松（命中 2-3 个特征即可），交由分析师人工研判。 |
| **威胁情报追踪 (TI Tracking)**  | 追踪黑客基础设施                | 提取特定攻击者的 C2 域名、邮箱等，长期追踪组织动向。         |
| **方法检测 (Method Detection)** | 抓异常行为/规避手法             | 不纠结样本名称，专抓伪装手法（如可疑文件大小、嵌套执行）。误报极低。 |

### 提取特征字符串的 4 种策略

- **高度特征化 (Specific)**：极其独特（如奇葩的互斥体或 PDB 路径），命中一个即告警。
- **可疑字符串 (Suspicious)**：单独使用易误报（如 `cmd.exe`），需组合使用。
- **C2 服务器追踪 (TI Tracking)**：硬编码的网络请求地址。
- **通用规则 (Generic)**：提取不同恶意家族共用的代码特征。

------

## 四、 实战模板库

### 模板一：常规二进制查杀（侧重 Hex 与精准特征）

**核心场景**：针对编译型的木马、勒索软件、后门程序（通常是 Windows PE 文件）。 

**实战逻辑**：锁定文件类型 -> 锁定文件大小 -> 命中高保真特征（Hex 机器码、奇葩路径、C2 域名）。

代码段

```c#
rule Template_Binary_Malware {
    meta:
        description = "常规二进制查杀：检测特定木马程序"
        author = "Your Name"
        score = 80
        
    strings:
        // 1. 高度特征化文本 (Specific String)：硬编码路径、互斥体
        $mutex = "Global\\EvilMutex_12345" fullword ascii wide
        
        // 2. C2 服务器追踪 (TI Tracking)：网络外联特征
        $c2 = "http://malicious-c2-domain.com/api/v1/update" ascii
        
        // 3. 十六进制特征码 (Hex Pattern)：核心恶意汇编逻辑，带通配符防免杀
        $hex_pattern = { 8B 45 FC 05 ?? ?? ?? ?? 50 } 

    condition:
        // 性能优化门槛：必须是 Windows 可执行文件 (MZ头)，且限制大小
        uint16(0) == 0x5A4D and filesize > 10KB and filesize < 3MB and 
        // 命中逻辑：满足任意高保真特征
        ( $mutex or $c2 or $hex_pattern )
}
```

### 模板二：纯文本脚本查杀与防误报兜底（侧重字符串与调优）

**核心场景**：针对 PHP、JSP、脚本文件，或极易产生误报的系统原生命令检测。

**实战逻辑**：抓取高危执行函数 -> 抓取混淆特征 -> **使用 `and not` 强制排除已知合法业务**。

代码段

```c#
rule Template_Script_and_Tuning {
    meta:
        description = "文本查杀与调优：检测高危执行并排除已知业务误报"
        author = "Your Name"

    strings:
        // 1. 可疑字符串 (Suspicious)：高危函数或系统命令，利用 fullword 防止词缀误伤
        $sus_func1 = "Runtime.getRuntime().exec" ascii
        $sus_func2 = "shell_exec" fullword ascii
        
        // 2. 混淆特征：攻击者常用来隐藏代码的手段
        $obfuscation = "base64_decode" nocase ascii
        
        // 3. 白名单特征 (False Positives)：公司内部合法的运维脚本标识
        $fp_monitor_script = "Author: Internal_IT_Ops" ascii
        $fp_known_framework = "Zend Framework" ascii

    condition:
        // 限制文件大小，通常脚本文件不会太大
        filesize < 500KB and
        
        // 命中逻辑：包含高危函数或混淆
        ( any of ($sus_func*) or $obfuscation ) 
        
        // 核心排误逻辑：绝对不能包含合法的业务白特征
        and not ( $fp_monitor_script or $fp_known_framework )
}
```

### 模板三：异常方法与结构检测（侧重逻辑矛盾）

**核心场景**：应对每天变种的未知病毒、钓鱼邮件附件（如恶意 PDF、Office 文档）。 

**实战逻辑**：不找具体的病毒特征，专抓“文件结构上的违和感”。比如一个正常的文档里，绝不该出现可执行程序的标志。

代码段

```
rule Template_Method_Anomaly_Detection {
    meta:
        description = "异常方法检测：发现内部嵌有 PE 文件的恶意 PDF 文档"
        author = "Your Name"
        score = 70

    strings:
        // 1. 结构矛盾点：这是 Windows PE 可执行文件的标志性提示语
        $pe_stub = "This program cannot be run in DOS mode" ascii
        
        // 2. 辅助验证点：PDF 中用于触发执行动作的关键字
        $pdf_action = "/Launch" ascii

    condition:
        // 确认物理文件类型是一个 PDF
        uint32be(0) == 0x25504446 and 
        filesize < 5MB and
        
        // 抓取逻辑矛盾：PDF 躯壳里包藏着 EXE 的灵魂，外加执行动作
        $pe_stub and $pdf_action
}
```

------

## 五、 “如何编写检测规则？”

**展现系统化的“IoC + IoA”立体防御思维及工程化调优能力。**

> “在接到检测需求或拿到恶意样本时，我不会单一地去看某个文件，而是会建立一个**‘静态 IoC + 动态 IoA’**的立体检测视角。
>
> **首先，我会编写基于 IoC 的静态规则（主攻 YARA）：** 我会重点关注代码结构、加解密逻辑和元数据。提取特征时，我优先抓取高保真的信息，如独有的 Mutex 名称、硬编码的 C2 域名或特殊的 PDB 路径。如果是复杂的二进制木马，我会提取核心加解密逻辑的 **Hex 操作码**。在组装条件时，我非常注重**性能优化**，一定会通过 `uint16(0) == 0x5A4D`（MZ头）和 `filesize` 来大幅过滤无关文件。
>
> **其次，为了防范静态免杀，我一定会结合基于 IoA 的行为规则进行纵深防御：** 我会重点监控系统内的异常动作，比如进程层面的白加黑（异常调用 PowerShell/cmd），或是系统配置的突变（如修改注册表实现持久化、创建隐藏服务等）。
>
> **最后是测试调优（防误报兜底）：** 结合我过去处理误报的经验，规则上线前必须经过内部业务样本库的测试。我会把命中合法业务的特征提取出来，写进 YARA 的 `and not` 逻辑中作为白名单兜底。
>
> **总结来说**，静态 IoC 抓已知载荷，动态 IoA 兜底未知手法，并配合严格的性能与误报控制，这样产出的规则才真正贴合生产环境。”

------

## 六、 学习路径与核心资源库

**学习路径：** `找经典规则拆解 -> 去靶场找同类样本 -> 提取特征仿写 -> 测试误报与漏报`

**优质资源推荐（ [awesome-yara](https://github.com/InQuest/awesome-yara/blob/master/README_CN.md)）：**

- **规则参考库**：
  - `Florian Roth / signature-base`：高标准、严谨的检测与方法规则库（必读）。
  - `Yara-Rules / rules`：老牌开源库，按木马、勒索等详细分类。
- **开发辅助工具**：
  - `yarGen`：**自动化工具神器**。输入样本，可自动提取特征字符串并自动剔除易误报的合法系统白特征。
  - `yara-python`：支持批量扫描和引擎调用的开发包。
