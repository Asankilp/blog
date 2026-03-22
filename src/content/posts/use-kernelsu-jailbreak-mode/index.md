---
title: 使用 KernelSU 越狱模式
published: 2026-03-11
description: '在有漏洞的小米设备等设备上使用 KernelSU 越狱模式'
image: ''
tags: [Android]
category: 'Android'
draft: false 
lang: ''
---


# 🚨**免责声明 | Disclaimer**🚨

- 本文仅对已公开披露的历史漏洞进行整理说明，目的在于安全研究与教育。依据本文操作所产生的一切后果（含数据丢失、设备损坏等）须由读者**自行承担**，作者不提供任何明示或暗示的保证。
- This article documents previously disclosed vulnerabilities solely for security research and educational purposes. You **assume full responsibility for any outcomes** (including data loss or device damage) that arise from attempting the described root procedure; the author offers no warranty of any kind.

:::warning
此文章尚不完善，可能存在错误，请谨慎操作。
:::

:::note
上一次更新时间：2026-03-22
:::

[上一篇文章](../xiaomi-root-privilege-escalation-exploit-with-shizuku/)中说明了利用小米设备的漏洞将 root 权限授予 Shizuku 的方法，近期 [KernelSU](https://kernelsu.org/) 对未解锁 bl 而获取 root 权限的“越狱”提供了官方支持，本文章将说明如何在这种设备上使用 KernelSU。

# 笔者的环境
- 设备： Redmi K70
- HyperOS 版本： 3.0.9.0.WNKCNXM
- Android 安全更新： 2026-02-01
- KernelSU 内核版本： 32348

:::warning
不保证所有机型，所有系统版本均适用此方法。
:::

# 设置 SELinux 宽容模式

按照上一篇文章所述，将 SELinux 设置为宽容模式。

# 激活 KernelSU 
首先获取内核版本 32348 及以上的 KernelSU 管理器 apk。  
可以在[此处](https://github.com/tiann/KernelSU/actions/runs/23055483890)下载 32348 版本的构建。

在手机上安装管理器并打开。
![ksu w-50%](Screenshot_2026-03-14-00-26-55-583_me.weishu.kern.jpg)
可以看见有一个蓝色的“越狱”按钮，该按钮仅在满足了越狱所需条件后才会显示。点击此按钮并等待几秒钟。
![ksu w-50%](Screenshot_2026-03-14-00-37-34-086_me.weishu.kern.jpg)
KernelSU 已经激活。
:::note
激活 KernelSU 后，SELinux 会被自动设为严格模式。
:::

:::important
每一次重启设备都需要执行上述步骤来恢复 KernelSU 环境。
:::

# 安装模块
:::caution
KernelSU 拥有极高的权限，安装危险模块（如直接操作 `/system` 等分区的模块）以及恶意模块很可能会使设备**变砖**。

**安装模块应三思而后行！！安装危险模块极有可能变砖，且在未解锁 bl 的情况下极难救砖！！**  

**安装模块应三思而后行！！安装危险模块极有可能变砖，且在未解锁 bl 的情况下极难救砖！！**  

**安装模块应三思而后行！！安装危险模块极有可能变砖，且在未解锁 bl 的情况下极难救砖！！**  
:::

## 安装 LSPosed
在 KernelSU 安装 Zygisk Next 及 LSPosed IT，并重启设备生效。  
~~若 LSPosed 管理器仍提示“未安装”，则需要以下仓库里的 `fix_lspd.sh` 来修复。~~
:::note
2026-03-22 补充：在 KernelSU 内核版本 32376(提交 `7e568dd`) 以上的环境，不再需要执行该脚本，只需点击 KernelSU 管理器的“软重启”选项即可激活 LSPosed。
:::
::github{repo="xunchahaha/mi_nobl_root"}
~~以 root 权限运行该脚本，会使 `zygote64` 被杀死， **所有运行中的应用会被关闭。** 若修复完成，LSPosed 应该可以使用。~~
![module w-50%](Screenshot_2026-03-11-20-42-53-778_me.weishu.kern.jpg)
![lsp w-50%](Screenshot_2026-03-11-20-40-45-625_org.lsposed.ma.jpg)
:::important
每一次重启设备都需要执行上述步骤来恢复 Zygisk + LSPosed 环境。
:::