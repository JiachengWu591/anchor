# AI Anchor · P1a

让 ChatGPT、Claude 等 AI 程序走一个**出口固定**的专用通道。通道不可用时，这些程序**断网而不是直连**；本机其他程序的网络保持原样。

P0 是命令行原型：在一台 Windows 电脑上做到“AI 程序走固定出口且不泄露”。P1a 把它变成常驻后台：

- 开机登录后自动运行，不需要手动启动任何东西。
- 内核崩溃自动恢复，每次都记进本机时间线。
- 应用更新后，守卫规则自动覆盖新版本。

线路控制器、出口锁定和断联归因在 P1b，插件模式和一致性检测在 P1c。

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
- **线路看门狗**：sing-box 的 urltest 只在定时检测时换线，当前线路断开后新连接会一直失败到下一轮检测。用户代理（或前台的 `anchor up`）每隔 `watch_interval`（默认 3 秒）探测当前线路，失败就立即让 sing-box 重新选线，实测 2 秒内恢复。所有线路都不可用时只报告一次，有线路恢复后自动切回。
- **守卫兜底**：每个 AI 程序一条持久化的 Windows 防火墙阻断规则。它只能连 `127.0.0.0/8` 和 `::1`，其他地址一律阻断。内核没启动、开机抢跑、代理参数没生效时，AI 程序都连不上外网。
- **启动前检查**：`anchor launch` / `anchor run` / `anchor browser` 先确认内核在运行、出口 IP 与登记的基线一致，不一致就不启动。
- **只编排，不自研协议**：sing-box（GPL-3.0）作为独立子进程运行，不链接其代码。

### 三个进程

| 进程 | 身份 | 负责 | 不负责 |
|---|---|---|---|
| `anchor-agent`（用户代理） | 当前用户，登录时自启，托盘常驻 | 守护 sing-box；线路看门狗；时间线（SQLite）；托盘和系统通知 | 不改防火墙 |
| `anchor-svc`（特权服务） | Windows 服务，LocalSystem，开机自启 | 写入、刷新、暂停守卫规则；应用安装和更新后自动刷新 | 不运行内核，不联网，不执行配置里的任何程序路径 |
| `anchor`（命令行） | 按需运行 | 查状态、看时间线、管理上面两个进程；P0 的命令都保留 | — |

- **本机接口**：命名管道，一行一个 JSON，带协议版本号。
  - `\\.\pipe\ai-anchor-agent`：只允许当前用户。
  - `\\.\pipe\ai-anchor-svc`：只允许安装时登记的用户、管理员和 SYSTEM，而且登记用户只能读写，不能创建同名管道冒充服务。
  - 客户端以“仅识别”级别连接，服务端无法冒用调用者身份。
- **服务不信任用户可写的东西**：
  - 程序装在 `%ProgramFiles%\AI Anchor`，状态写在 `%ProgramData%\AIAnchor`（重设为只有管理员可写）。
  - 要守卫的程序由服务自己查：本机应用包仓库（HKLM）和登记用户的安装目录。用户配置只决定守卫哪些程序。
  - `extra_programs` 只用来生成阻断规则。Windows 目录里的系统程序、浏览器、shell 一律拒绝。
- **内核随用户代理退出**：sing-box 放在“关闭即结束”的作业对象里。用户代理被强制结束时，内核一起退出，不会留下占着端口的孤儿进程。
- **守卫自动维护**：
  - 什么时候刷新：服务启动时；HKLM 应用包仓库变化时（应用安装或更新，几秒内）；每 5 分钟；`anchor launch` 启动程序前。
  - 刷新只删两类规则：文件已不存在的、阻断地址集合已变的。某次扫描漏了程序，也不会删掉仍然有效的规则。
  - 发现被停用的规则会重新启用。
  - 暂停有时限，到时自动恢复；服务重启后也会恢复。

## 与 VPN / 其他 TUN 共存

AI Anchor P0 不建 TUN，也不改路由和系统代理，只开一个本机端口，所以可以和必须常开的公司 VPN 或其他 TUN 同时使用。

- **流量路径**：sing-box 连线路和出口时走系统路由，开着全量 VPN 时就经过 VPN。AI 服务看到的仍是固定出口 IP，VPN 只是底层网络。
- **守卫照常有效**：防火墙规则在程序发起连接时按目标地址判断，早于流量进入 VPN 网卡。
- **守卫默认只放行回环地址**：VPN 和代理软件的 TUN 常用 `198.18.0.0/15` 一带。`[guard] allow_fakeip` 默认关闭；打开后如果与本机任何网卡网段重叠，`anchor guard` 会拒绝执行，以免 AI 程序绕过通道访问 VPN 网段。
- **体检识别隧道**：`anchor check` 和 `anchor status` 会显示默认流量是否经 VPN / TUN 网卡、是否已连接。所有线路同时失败时，归因会提示先检查 VPN 是否在重连。经 VPN 时，TCP 握手可能由 VPN 客户端在本地应答，所以只测 TCP 的结果仅供参考。
- **不能再叠一层 TUN**：AI Anchor 自己的 TUN 兜底（P1）会和全量 VPN 抢默认路由，这类电脑上只用显式代理，也就是 `anchor launch` 或快捷方式。
- **VPN 本身能稳定出境时**：可以不写 `[[lines]]`，出口直接经 VPN 连接，少一层故障点。

## 快速开始

1. 构建：`cargo build --release`。`target\release\` 下会生成三个程序：`anchor.exe`、`anchor-agent.exe`、`anchor-svc.exe`。三个程序要放在同一目录。
2. 下载 [sing-box](https://github.com/SagerNet/sing-box/releases) Windows 版（1.12 或更高），把 `sing-box.exe` 放到 `%LOCALAPPDATA%\AIAnchor\bin\`。
3. 生成配置并填入你自己的出口和线路：

   ```
   anchor init
   notepad %LOCALAPPDATA%\AIAnchor\anchor.toml
   anchor gen
   ```

4. 设置登录自启并立即启动用户代理（托盘里会出现 AI Anchor 图标）：`anchor agent install`
5. 登记出口基线并体检：

   ```
   anchor baseline
   anchor check
   ```

6. 安装特权服务：`anchor service install`。会弹出管理员确认，之后服务立即写入守卫规则，并持续维护。先用 `anchor guard plan` 预览会守卫哪些程序。
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
| `anchor agent install / uninstall` | 设置或取消登录后自动启动用户代理（`HKCU\…\Run`），并立即启动或退出 |
| `anchor agent start / stop / reload / status` | 启动、退出用户代理；`reload` 重新读取配置并重启内核 |
| `anchor service install / uninstall / status` | 安装或卸载特权服务（弹出管理员确认）；卸载后守卫规则保留 |
| `anchor timeline [--since 24h] [--kind …] [--probes] [--json]` | 按时间顺序列出事件（内核重启、线路切换、线路全断与恢复、守卫刷新、启动应用……）和探测汇总 |
| `anchor up` | 前台运行并守护内核（调试用）；用户代理在运行时拒绝执行 |
| `anchor status` | 显示后台进程、内核、当前线路、最近探测延迟、守卫覆盖情况 |
| `anchor check [--json]` | 一次性体检并归因，结果追加到 `logs\checks.jsonl`；有 FAIL 时退出码为 2 |
| `anchor baseline` | 经通道测出口，写入 `[expect]` 的 ip / timezone / country（保留注释） |
| `anchor scan` | 扫描本机 AI 程序，标出能否按程序守卫及原因 |
| `anchor guard plan / install / status / remove / pause / resume` | 防火墙守卫。装了特权服务时经服务执行，不需要管理员；`pause` 默认 10 分钟后自动恢复（`--minutes`）。没装服务时除 `plan`、`status` 外都需要管理员 |
| `anchor run <程序> [参数…]` | 检查通过后注入代理环境变量运行，退出码透传 |
| `anchor launch <应用>` | 检查通过后带代理参数启动桌面客户端；应用已在运行时拒绝（单实例会丢弃新参数） |
| `anchor browser [网址]` | 打开 AI 专用浏览器（Edge / Chrome） |
| `anchor shortcut <应用或 browser>` | 创建“应用名 - AI Anchor”快捷方式 |
| `anchor rules --format singbox\|mihomo\|list` | 输出 AI 域名规则集，供插件模式使用 |
| `anchor repair` | 把被 Claude 桌面版等 MSIX 应用重定向到其私有目录的数据目录副本合并回原位置（不覆盖原位置已有的文件） |

所有命令都接受 `--home <目录>`（或环境变量 `ANCHOR_HOME`）。不指定时，数据目录是 `%LOCALAPPDATA%\AIAnchor`。

托盘菜单的功能：
- 显示当前状态。图标分三档：正常、注意、故障。
- 查看最近 24 小时的时间线。
- 运行体检。
- 打开数据目录。
- 重新加载配置。
- 退出。

以下情况会弹出系统通知：
- 所有线路都不可用，以及之后的恢复。
- 内核连续退出 3 次。
- 配置有误。
- 特权服务没有运行。

### 时间线

用户代理把下面两类数据写进 `<数据目录>\timeline.db`（SQLite，WAL 模式）。命令行只读。
- 状态变化：`events` 表，保留 90 天。
- 探测：`probes` 表，明细保留 7 天。

| 事件 | 什么时候记 |
|---|---|
| `agent_start` / `agent_stop` | 用户代理启动、退出（附原因） |
| `kernel_start` / `kernel_restart` / `kernel_error` | 内核启动；意外退出后恢复（附退出码、运行时长、中断时长）；无法启动或反复退出 |
| `line_switch` / `line_down` / `all_lines_down` / `line_recovered` | 看门狗换线（附原因和延迟）；手动模式当前线路故障；全部不可用；恢复 |
| `guard_refresh` / `guard_pause` / `guard_resume` | 特权服务改了守卫规则（附新增和移除的程序路径）；暂停、恢复 |
| `app_launch` | 经 `anchor launch` / `anchor browser` 启动 AI 程序 |
| `config_error` | `anchor.toml` 读不了或有误 |

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

## 已知限制

- **应用更新后的空窗**：
  - MSIX 应用（Claude、ChatGPT 桌面版）：包登记一变，服务几秒内就刷新守卫。
  - Squirrel 应用和 Claude 桌面版内置的 Claude Code：靠 5 分钟轮询。
  - 两种情况的空窗里，直接点原图标启动新版本都可能直连。经 `anchor launch` 或快捷方式启动时，会先刷新守卫再启动。
- **没装特权服务时**，应用更新后要手动重新运行 `anchor guard install`（需要管理员），和 P0 一样。
- **托盘是最小实现**：图标用系统自带的三种（信息、警告、错误），通知用托盘气泡，没有面板（P2）。
- **用户代理的管道名是全机唯一的**：同一台电脑上多个用户同时登录时，只有第一个用户的用户代理能运行。
- **不要在 Claude 桌面版等 MSIX 应用的终端里初始化或启动 AI Anchor**：
  - 原因：从这类应用里启动的进程（例如 Claude 桌面版的终端面板和其中的 Claude Code）写到 `%LOCALAPPDATA%` 的新文件，会被 Windows 重定向到该应用的私有目录 `%LOCALAPPDATA%\Packages\<应用>\LocalCache\Local\`。特权服务、登录自启的用户代理和普通终端都看不到这些文件。
  - 实测：这类进程不一定有应用包身份，所以 `anchor` 不靠包身份判断，而是写一个临时文件，看它是否落进某个应用的私有目录。
  - 在这种环境里，`anchor` 会拒绝 `init`、`gen`、`up`、`baseline`、`launch`、`browser`、`agent start / install / uninstall`，并给出要在普通终端里运行的完整命令。`anchor-agent` 也拒绝启动。
  - `check` 照常运行，但不写体检记录。其他查看类命令照常运行。
  - 已经发生过重定向时，`anchor` 的每条命令都会提示私有副本的位置，并让你在普通终端里运行 `anchor repair`。
  - `anchor repair` 合并副本时不覆盖原位置已有的文件：
    - `anchor.toml`：原位置没有就搬过来。两边不同时保留原位置的，副本里的另存为 `anchor.toml.<应用包>`。
    - `bin` 里的程序：只搬原位置没有的。
    - 运行文件、日志、时间线：不搬，原位置会重新生成。
    - 合并完删除副本；用户代理在运行时自动重新加载配置。
- **npm 安装的 Claude Code 是 node 进程**，无法按程序守卫，只能靠 `anchor run` 注入代理。原生安装的 `claude.exe` 可以守卫。mise 等版本管理器的 shim 也不能守卫。
- **Claude 桌面版内置的 Claude Code** 不读启动参数，默认不纳入守卫。需要在 `~/.claude/settings.json` 的 `env` 里设置 `HTTPS_PROXY`。
- **TUN 兜底未实现**。不认显式代理的程序，在 P0 里只会被守卫断网。开着全量 VPN 的电脑以后也不适合用 TUN 兜底。
- 线路控制器（评分、迟滞、手动固定）、出口核对与锁定、断联采集与归因、`anchor report` 在 P1b；DNS / WebRTC 泄露检测、IP 类型多库判断、插件模式在 P1c。
- **时区**：Chromium 在 Windows 上读取系统时区，P0 只做提示，不修改系统时区。
- **线路看门狗是轮询的**：当前线路断开后，最坏要等一个 `watch_interval` 加一次探测超时（默认约 3～5.5 秒）才换线。每次轮询经当前线路请求一次 `probe_url`，流量很小。手动模式下看门狗只报告，不切换。
- 项目所在路径过长时，MSVC 链接器可能报 `LNK1104`（超过 260 字符）。把项目放到短路径，或设置 `CARGO_TARGET_DIR`。

## 代码结构

Cargo workspace，四个 crate：

| crate | 产物 | 内容 |
|---|---|---|
| `crates/core`（anchor-core） | 库 | 配置、sing-box 配置生成、网络探测、守卫计算与增量刷新、程序发现、命名管道、时间线（`timeline` 特性）、Windows 系统调用封装 |
| `crates/agent`（anchor-agent） | `anchor-agent.exe` | 会话（内核 + 看门狗）、托盘、本机接口、向服务同步守卫变化 |
| `crates/svc`（anchor-svc） | `anchor-svc.exe` | 服务注册与安装、守卫维护循环、注册表变更监视 |
| `crates/cli`（anchor-cli） | `anchor.exe` | P0 的全部命令，加上 `agent`、`service`、`timeline` |

## 测试状态

### P1a

- `cargo test --workspace`：57 个单元测试。P1a 新增的覆盖：
  - 真实命名管道上的请求和响应，以及单实例锁
  - 管道访问控制里客户端没有“创建实例”权限
  - 时间线：写入、查询、过滤、条数上限、清理、只读打开、重新打开
  - 守卫增量刷新：新版本加入、旧版本移除、指纹变化时重建、重复规则、只在要求时清理配置之外的规则
  - 暂停时新规则以停用状态写入
  - 按给定的用户配置文件目录发现程序
  - 托盘状态分级
  - 登录自启命令行的引号处理
  - 识别 MSIX 应用私有目录里的数据目录副本（大小写、斜杠不同也能识别；不在 AppData 下的目录不误报）
  - `anchor repair` 合并副本：不覆盖原位置的文件，配置冲突时另存，不搬时间线，合并后删除副本
  - `anchor check` 的提示：官方状态页报告故障只算提示，不把故障归到通道上；Cloudflare 人机验证单独说明；守卫一项按 `[apps]` 是否为空、特权服务是否在运行给出对应的处理办法
- 在 Claude 桌面版的终端里实测：`init`、`agent start` 被拒绝，且没有创建任何文件；`anchor-agent` 拒绝启动；`status` 提示当前在 Claude 里，并指出已有的私有副本；探测用的临时文件没有残留。在普通终端里不拒绝，这一点要靠你在开始菜单打开的终端里验证。
- 端到端测试：本机三个 sing-box 充当出口和两条线路。用户代理以 `--no-tray` 前台运行，特权服务以 `console --dry-run` 运行（演练，不写防火墙）。
  - **T7 内核崩溃**：强制结束 sing-box 后，AI 端口 1.9 秒恢复，时间线记了一条 `kernel_restart`，含退出码、运行时长和中断 1.5 秒。第二次实测中断 1.7 秒。
  - **线路故障**：停掉当前线路，下一次看门狗探测（3 秒内）就换线，记 `line_switch`。两条都停，`all_lines_down` 只记一次、通知一次。恢复一条后切回，记 `line_recovered`，并通知“线路已恢复”。
  - **不误报**：用户代理退出、内核被强制结束时，都不会再记出“线路全断”。修复前会误记。
  - **reload / stop**：`anchor agent reload` 按新配置重启内核。`anchor agent stop` 后端口关闭，没有残留的 sing-box。
  - **作业对象**：强制结束用户代理进程，sing-box 随之退出，端口关闭。
  - **守卫维护（演练）**：
    - 服务按本机包仓库找到 Claude 桌面版的两个版本：当前登记的 5.11492.0.0，和已下载、还没登记给用户的 5.11492.2.0。也找到了 ChatGPT 桌面版和伪造配置文件目录里的 Claude Code。
    - 在伪造目录里“安装” Cursor 后，下一次轮询就把它列入新增。
    - `anchor guard status` / `install` 经服务执行，不需要管理员。
    - 用户代理把服务的两次变化按服务记录的时间同步进时间线（`guard_refresh`）。
  - `anchor up` 前台模式、`cargo build --release` 正常。
- 尚未实测，需要你在自己的电脑上做：
  - **`anchor service install`**：真正注册服务、写入防火墙规则，需要管理员确认。还有重启电脑后服务先于登录生效。
  - **`anchor agent install`**：登录自启；重新登录后不手动启动任何东西就能用。
  - **T6 应用更新**：真实更新 Claude 桌面版后，新路径 1 分钟内纳入守卫。
  - **托盘**：图标和气泡通知的实际显示。日志确认托盘已就绪，但没有截图核对。
  - **`anchor launch`**：经用户代理记录 `app_launch`。这次没有真的启动桌面客户端。

### P0

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

## 许可证

本项目以 [MIT 许可证](LICENSE) 发布。

sing-box 采用 GPL-3.0。AI Anchor 只把它当作独立程序调用，不链接它的代码，也不随本项目分发；用户需要自行从官方 release 下载。
