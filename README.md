# AI Anchor · P0 原型

让 ChatGPT、Claude 等 AI 程序走一个**出口固定**的专用通道。通道不可用时，这些程序**断网而不是直连**；本机其他程序的网络保持原样。

这是设计文档里 P0 阶段的命令行原型：先在一台 Windows 电脑上做到“AI 程序走固定出口且不泄露”。图形界面（Tauri）、后台服务和持续体检放在后续阶段。

## 它怎么工作

```
AI 程序 ──显式代理──▶ 127.0.0.1:17890（sing-box mixed 入站）
                         │
                         ▼
                      exit（固定出口，AI 服务看到的 IP）
                         │ detour
                         ▼
                      lines（urltest 自动选线 / selector 手动）
                       ├─ line-a
                       └─ line-b
```

- **线路和出口分层**：线路可以自动切换，出口始终是同一个，所以 IP 不变。切换时不打断已建立的连接（`interrupt_exist_connections: false`）。
- **线路看门狗**：sing-box 的 urltest 只在定时检测时换线，当前线路断开后新连接会一直失败到下一轮检测。`anchor up` 每隔 `watch_interval`（默认 3 秒）探测当前线路，失败就立即让 sing-box 重新选线，实测 2 秒内恢复。所有线路都不可用时只报告一次，有线路恢复后自动切回。
- **守卫兜底**：每个 AI 程序一条持久化的 Windows 防火墙阻断规则。它只能连 `127.0.0.0/8` 和 `::1`，其他地址一律阻断。内核没启动、开机抢跑、代理参数没生效时，AI 程序都连不上外网。
- **启动前检查**：`anchor launch` / `anchor run` / `anchor browser` 先确认内核在运行、出口 IP 与登记的基线一致，不一致就不启动。
- **只编排，不自研协议**：sing-box（GPL-3.0）作为独立子进程运行，不链接其代码。

## 与 VPN / 其他 TUN 共存

AI Anchor P0 不建 TUN，也不改路由和系统代理，只开一个本机端口，所以可以和必须常开的公司 VPN 或其他 TUN 同时使用。

- **流量路径**：sing-box 连线路和出口时走系统路由，开着全量 VPN 时就经过 VPN。AI 服务看到的仍是固定出口 IP，VPN 只是底层网络。
- **守卫照常有效**：防火墙规则在程序发起连接时按目标地址判断，早于流量进入 VPN 网卡。
- **守卫默认只放行回环地址**：VPN 和代理软件的 TUN 常用 `198.18.0.0/15` 一带。`[guard] allow_fakeip` 默认关闭；打开后如果与本机任何网卡网段重叠，`anchor guard` 会拒绝执行，以免 AI 程序绕过通道访问 VPN 网段。
- **体检识别隧道**：`anchor check` 和 `anchor status` 会显示默认流量是否经 VPN / TUN 网卡、是否已连接。所有线路同时失败时，归因会提示先检查 VPN 是否在重连。经 VPN 时，TCP 握手可能由 VPN 客户端在本地应答，所以只测 TCP 的结果仅供参考。
- **不能再叠一层 TUN**：AI Anchor 自己的 TUN 兜底（P1）会和全量 VPN 抢默认路由，这类电脑上只用显式代理，也就是 `anchor launch` 或快捷方式。
- **VPN 本身能稳定出境时**：可以不写 `[[lines]]`，出口直接经 VPN 连接，少一层故障点。

## 快速开始

1. 构建：`cargo build --release`，得到 `target\release\anchor.exe`。
2. 下载 [sing-box](https://github.com/SagerNet/sing-box/releases) Windows 版（1.12 或更高），把 `sing-box.exe` 放到 `%LOCALAPPDATA%\AIAnchor\bin\`。
3. 生成配置并填入你自己的出口和线路：

   ```
   anchor init
   notepad %LOCALAPPDATA%\AIAnchor\anchor.toml
   anchor gen
   ```

4. 启动内核（前台运行，Ctrl+C 停止）：`anchor up`
5. 另开一个终端，登记出口基线并体检：

   ```
   anchor baseline
   anchor check
   ```

6. 在**以管理员身份运行**的终端里写入守卫规则：先 `anchor guard plan` 预览，再 `anchor guard install`。
7. 通过 AI Anchor 启动程序：

   ```
   anchor run claude
   anchor launch claude-desktop
   anchor browser
   anchor shortcut claude-desktop
   ```

   - `anchor run claude`：Claude Code 等命令行工具，注入 `HTTPS_PROXY`。
   - `anchor launch claude-desktop`：桌面客户端，带 `--proxy-server` 启动。
   - `anchor browser`：AI 专用浏览器，独立配置目录。
   - `anchor shortcut claude-desktop`：在桌面创建“Claude 桌面版 - AI Anchor”快捷方式。

## 命令

| 命令 | 作用 |
|---|---|
| `anchor init` | 生成示例配置 `anchor.toml` |
| `anchor gen` | 生成 sing-box 配置；找得到 sing-box 时顺带运行 `sing-box check` |
| `anchor up` | 运行并守护内核，意外退出后按 1→30 秒退避重启；同时运行线路看门狗 |
| `anchor status` | 显示内核、当前线路、最近探测延迟、守卫覆盖情况 |
| `anchor check [--json]` | 一次性体检并归因，结果追加到 `logs\checks.jsonl`；有 FAIL 时退出码为 2 |
| `anchor baseline` | 经通道测出口，写入 `[expect]` 的 ip / timezone / country（保留注释） |
| `anchor scan` | 扫描本机 AI 程序，标出能否按程序守卫及原因 |
| `anchor guard plan / install / status / remove / pause / resume` | 防火墙守卫；除 `plan`、`status` 外都需要管理员 |
| `anchor run <程序> [参数…]` | 检查通过后注入代理环境变量运行，退出码透传 |
| `anchor launch <应用>` | 检查通过后带代理参数启动桌面客户端；应用已在运行时拒绝（单实例会丢弃新参数） |
| `anchor browser [网址]` | 打开 AI 专用浏览器（Edge / Chrome） |
| `anchor shortcut <应用或 browser>` | 创建“应用名 - AI Anchor”快捷方式 |
| `anchor rules --format singbox\|mihomo\|list` | 输出 AI 域名规则集，供插件模式使用 |

所有命令都接受 `--home <目录>`（或环境变量 `ANCHOR_HOME`）。不指定时，数据目录是 `%LOCALAPPDATA%\AIAnchor`。

AI 专用浏览器的启动参数如下。它是一个独立实例，用户日常的浏览器窗口不受影响。

- `--user-data-dir=<数据目录>\browser\ai-anchor`
- `--proxy-server=http://127.0.0.1:17890`
- `--disable-quic`
- `--force-webrtc-ip-handling-policy=disable_non_proxied_udp`
- `--lang=<expect.language>`

## 体检与归因

| 段 | 怎么测 |
|---|---|
| 本地网络 | 不经代理访问 `msftconnecttest.com`；识别默认流量是否经 VPN / TUN 隧道、隧道是否已连接 |
| 内核 | AI 代理端口是否在监听 |
| 线路 | 经 Clash API 让每条线路单独请求探测地址；内核没运行时只测 TCP（仅供参考） |
| 出口 | 经通道访问 `ipinfo.io`，与基线比对；同时测整条链的延迟 |
| AI 服务 | Anthropic / OpenAI 状态页，以及 `api.anthropic.com`、`claude.ai`、`api.openai.com`、`chatgpt.com` 的可达性；识别“地区不受支持”的响应 |
| 一致性 | 出口时区、国家与 `[expect]` 是否一致，并显示系统时区 |
| 守卫 | 规则是否覆盖配置里的全部程序、是否被暂停、是否因应用更新而失效 |

归因顺序与设计文档一致：本地 → 内核 → 线路 → 出口 → 服务端。

## 已知限制（P0）

- **MSIX / Squirrel 应用更新后路径会变**，旧的守卫规则会失效。目前靠 `anchor check` 和 `anchor guard status` 提示，用户需要重新运行 `anchor guard install`。P1 由后台服务自动刷新。
- **npm 安装的 Claude Code 是 node 进程**，无法按程序守卫，只能靠 `anchor run` 注入代理。原生安装的 `claude.exe` 可以守卫。mise 等版本管理器的 shim 也不能守卫。
- **Claude 桌面版内置的 Claude Code** 不读启动参数，默认不纳入守卫。需要在 `~/.claude/settings.json` 的 `env` 里设置 `HTTPS_PROXY`。
- **TUN 兜底未实现**。不认显式代理的程序，在 P0 里只会被守卫断网。开着全量 VPN 的电脑以后也不适合用 TUN 兜底。
- DNS / WebRTC 泄露检测、IP 类型多库判断、SQLite 时间线、Windows 服务都在 P1。
- **时区**：Chromium 在 Windows 上读取系统时区，P0 只做提示，不修改系统时区。
- **线路看门狗是轮询的**：当前线路断开后，最坏要等一个 `watch_interval` 加一次探测超时（默认约 3～5.5 秒）才换线。每次轮询经当前线路请求一次 `probe_url`，流量很小。手动模式下看门狗只报告，不切换。
- 项目所在路径过长时，MSVC 链接器可能报 `LNK1104`（超过 260 字符）。把项目放到短路径，或设置 `CARGO_TARGET_DIR`。

## 测试状态

- `cargo test`：33 个单元测试覆盖以下内容：
  - 配置校验
  - sing-box 配置结构
  - 守卫地址补集、FakeIP 与 VPN 网段重叠检测
  - VPN / TUN 网卡识别
  - 程序分类
  - 浏览器参数
  - 归因顺序
  - 基线写回
  - 看门狗的判断（换线、偶发失败、全部不可用）和 `watch_interval` 校验
- 已在本机实测以下命令：
  - `init`、`gen`、`scan`、`guard plan`、`guard status`、`status`、`check`
  - `run`、`launch`、`browser` 的拒绝路径
  - `shortcut`
  - 在开着全量 VPN（Wintun）的电脑上：`status`、`check` 识别出隧道；`allow_fakeip = true` 时 `guard plan` 因网段重叠拒绝执行
- 用 sing-box 1.14.4（官方 release，校验过 SHA-256）实测：
  - 三种生成配置（单线路自动、无线路、双线路手动 + trojan/TLS）都通过 `sing-box check`，内核日志里没有弃用警告。
  - 端到端：本机起三个 sing-box 分别充当出口（socks）和两条线路（Shadowsocks 2022），`anchor up` 跑通“线路 → 出口 → 目标”。`baseline`、`check`、`status` 全部正常；`anchor run` 正确注入代理环境变量并透传退出码；基线 IP 不符时拒绝启动。
  - 线路故障，没有看门狗时：停掉当前线路后约 9 秒才切到另一条（urltest 周期 10 秒），出口 IP 全程不变。
  - 线路故障，有看门狗时（urltest 周期故意设成 5 分钟）：
    - 停掉当前线路，2.0 秒恢复。
    - 两条线路都停掉，只报告一次“所有线路都不可用”。
    - 恢复其中一条，5.3 秒后自动切回。
  - 内核崩溃：强制结束 sing-box 后，`anchor up` 2.4 秒内重启，请求恢复。
- 尚未实测：
  - 用真实的远程线路和出口跑（上面的端到端测试里，线路和出口都在本机）
  - 用管理员身份运行 `guard install`，以及装上守卫后的断网行为
