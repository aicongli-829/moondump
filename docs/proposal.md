# moondump 项目申报说明（2026 MoonBit 黑客松 · 11 月赛季）

**题目**：moondump —— Windows minidump（`.dmp`）崩溃转储解析库 + 命令行工具
**作者 / GitHub ID**：aicongli-829（用于打款与入群）
**团队人数**：1
**许可**：Apache-2.0（并在源码头注释与 README 中标注移植/参考来源）

---

## 1. 选题理由：自己用得到 + 别的生态已有成熟方案

我的日常工作平台是 Windows，方向是逆向与恶意样本分析。崩溃转储（minidump）是这个场景里
出现频率最高的一类文件：程序崩溃、样本运行炸了、WER 自动生成的报告，都落在 `.dmp` 里。
现在的处理链完全绑死在 Windows + WinDbg/DbgHelp 上，而我想在 MoonBit 里做样本 triage 工具时，
没有任何一个库能把 `.dmp` 读出结构。

这个题目不是靠头脑风暴造出来的需求，判据是硬的：

- **格式有公开、确定的规范**：Microsoft `MINIDUMP_HEADER` / `MINIDUMP_STREAM_TYPE`
  （minidumpapiset）、Google Crashpad 的 `doc/minidump_file_format.md`、Breakpad 的
  `minidump_format.h`。每个流的字段偏移、大小、对齐都写死在文档里，不靠猜。
- **其它生态有成熟的同类实现**：`rust-minidump`（Mozilla 生产环境在用，含 `minidump-stackwalk`）、
  Google Breakpad、Crashpad、`pyminidump` / `minidump` crate。也就是说"做完是什么样"
  有现成的东西可以参照 —— 不过"参照"具体到什么程度，取决于我能不能真的把它跑起来，
  这一点我在第 3 节末尾和第 4 节里说清楚。
- **验收可以客观化**：每个字段的偏移、宽度、语义都有唯一正确答案，断言写得出「流目录
  条目数=多少、模块名=什么、异常码=什么」这种句子，不用自己定义"什么叫做完了"。
  申报时我打算把 `minidump-stackwalk --json` 当作逐字段的对照表，实际做法有修正，
  见第 3 节末尾和第 4 节。

这跟"某种格式的更新审计工具"那类题目的区别正在于此：后者的规则要靠我自己发明，
最后往往退化成字符串匹配；而 minidump 的规则是别人定好的，我要做的是把它在 MoonBit 里
正确、安全地实现出来。

## 2. 移植/参考来源声明

- 格式规范：Microsoft Learn `MINIDUMP_HEADER`、Crashpad `minidump_file_format.md`，
  以及本机 Windows SDK `10.0.26100.0\um\minidumpapiset.h`（字段偏移的最终依据，
  源码注释里逐条标了行号）。
- 行为参照与边界情况处理：`rust-minidump`（**MIT 许可**，非双许可），
  特别是它对畸形 RVA、越界流、Memory64List 重叠区间的容忍策略；Breakpad 的
  `minidump_format.h` 与符号文件（`.sym`）格式文档用于流编号与符号规则核对。
- 测试语料：`rust-minidump/testdata`（MIT，许可证全文随附）。本机 WER 生成的真实转储
  含进程内存与用户名路径，**只用于本地对拍，不进仓库**。
- 上述来源在各源文件头部注释与 README 的 Acknowledgement 一节逐条列出。

## 3. 一个月内交付范围（每周里程碑）

| 周 | 交付 |
| --- | --- |
| W1 | header / 流目录 / RVA 边界检查 / MINIDUMP_STRING(UTF-16LE)；CLI 打印概览与流表；合成 + 真实转储冒烟 |
| W2 | SystemInfo / ModuleList(+VS_FIXEDFILEINFO) / MiscInfo / CommentStream；统一 MemoryReader（MemoryList 与 Memory64List，优先后者，越界裁剪） |
| W3 | ThreadList / ThreadExList / ExceptionStream（异常码命名、访问违例读写地址、上下文按架构长度）/ MemoryInfoList / UnloadedModuleList；CLI `--json` 输出，字段名对齐 `minidump-stackwalk --json` |
| W4 | 长尾流补齐（UnloadedModuleList / HandleData / FunctionTable / ThreadInfoList / ThreadNames）、Breakpad `.sym` 符号表 + 栈回溯、真实语料回归测试（逐个 dmp 断言关键字段）、README + 可运行示例、`moon info`/`moon fmt`/覆盖率清理、错误信息中文化、发布 tag |

**明确不做**（避免范围失控）：PDB 解析与符号服务器下载（`.pdb`/`msdl.microsoft.com` 都不碰，
符号只走 Breakpad 文本 `.sym`）、CPU 上下文寄存器级模拟、流内容之外的任何"分析判断"。

**计划里被我自己改掉的一条**：W3 那行写的"字段名对齐 `minidump-stackwalk --json`"没有按原样执行。
原因很具体：这台机器上跑 `minidump-stackwalk` 需要联网装 crate 或下载预编译二进制，
离线环境拿不到它，我也没有第二个能逐字节比对的渠道。在这种情况下把 schema 称作"对齐 X"
就是一句无法验证也无人能验证的话，而它一旦写进 README，就是在替别人已经定好的格式造假。
所以 `--json` 交付的是 **moondump 自己的 schema**（`moondump/v1`，17 个顶层键固定顺序、
缺失即 `null`、地址一律 `0x…` 字符串），文档里明写"这不是 `minidump-stackwalk` 的输出格式"。
格式规范层面该对齐的仍然对齐：字段偏移、流类型编号、枚举取值全部按 SDK/Crashpad 文档来，
那些是有公开文档可以逐条核对的。

**计划里被我自己改掉的第二条**：W4 那行写的"错误信息中文化"最终没有执行——项目进入
收尾阶段时改成了全部英文。原因：这个库面向的是公开仓库和潜在的非中文使用者，错误消息、
CLI 输出、README 摘录、代码注释统一用英文后，可检索性（报错文本直接搜得到）和
跨团队可读性都更好，而中文表述原本也只是我单方面的默认，并非申报要求。`docs/proposal.md`
本身保留中文，因为它是组委会的申报文档。

## 4. 验收标准（可判定）

1. `moon test` 全绿；对语料里每个 `.dmp` 断言：流目录条目数、SystemInfo 的架构/处理器数/OS 版本、
   ModuleList 的模块名与数量、ExceptionStream 的异常码与线程 ID、内存流的区间与长度。
   判定依据是**格式文档规定的字节布局**加上从原始字节独立抽出来的值（独立脚本按头文件
   偏移生成，不是从本实现的输出生成，见本节末尾的"验证方法"），
   **不声称与 `minidump-stackwalk` 的字段兼容**——这台机器上拿不到那个二进制。
2. **畸形输入不 panic**：截断、RVA 越界、目录条目数造假、UTF-16 孤立代理项、
   Memory64List 与文件末尾重叠，全部收敛为 `ParseError` 的具名分支，并有对应测试。
3. 大文件可用：15MB 级真实转储在 CLI 上完整解析，内存读取走懒解析路径（不把整份内存复制出来）。
4. CLI 有 `text` 与 `--json` 两种输出，README 里有 `moon run cmd/main -- <file.dmp>` 的可复制示例；
   两种输出的字段取值必须同源（同一帧的 `kind`/地址/槽位/模块归属一致），
   且 `--json` 的文本要经过 `stringify → JSON.parse` 读回来再断言，只查内存里的 `Json` 值不算数。
5. 仓库公开、持续提交、Issue/PR 记录完整，README 顶部写明移植与参考来源。
6. 栈回溯：除上下文帧（崩溃现场那条帧本来就是上下文给的）外，每一帧的
   `(栈槽地址, 指令地址)` 必须在一支独立脚本按 SDK 的 `MINIDUMP_THREAD` /
   `CONTEXT` 布局硬读出来的原始槽位表里原样出现；模块归属由脚本按模块表区间
   独立重算一遍再比。这一条把"回溯器自己骗自己"排除了出去。
   本次实测：`test.dmp` 对上 80 帧、`invalid-parameter.dmp` 对上 135 帧，`bad` 都是 0。

**验证方法**（在没有可对照工具的环境下怎么保证正确）：三层。
第一层是格式文档 —— 偏移、宽度、枚举值逐条抄自 `minidumpapiset.h` / Crashpad 文档，
并有一支测试钉住流类型编号，防止抄错也防止将来改错。第二层是独立抽取脚本 ——
`testdata/oracle/stack_oracle.js` 按头文件布局直接从字节里读帧指针链与原始栈槽表，
不做任何启发式判断，`stack_crosscheck.js` 拿它的输出和 CLI 的输出逐帧对拍；
脚本与 MoonBit 实现零共享代码，用法写在脚本头部注释里。第三层是自洽性检查 ——
当一份真实文件与文档声明矛盾时（第 7 节的函数表流），不猜、不选边，
把两个候选排布都按证据跑一遍，让结论和"结论是否可信"一起进输出。

## 5. 当前进度（W1–W4 全部完成）

格式层在申报前就通了，不是纸面计划：

- `open_dump` 校验签名、读 header；流目录 12 字节/项；`Rva = UInt64` 统一承载，
  所有读取走带边界检查的 `offset()`，越界报 `Truncated`，超大 RVA 报 `RvaTooLarge`。
- `MINIDUMP_STRING`（UTF-16LE，长度不含 NUL）解码，代理项配对校验，
  孤立代理项按 `InvalidUtf16` 拒绝，不做静默替换。
- 流类型常量与 Microsoft/crashpad 对齐（MemoryList=5、Exception=6、SystemInfo=7、
  ThreadEx=8、Memory64List=9、CommentW=11、HandleData=12、FunctionTable=13、
  UnloadedModuleList=14、MiscInfo=15、MemoryInfoList=16、ThreadInfoList=17、Token=19、
  SystemMemoryInfo=21、ProcessVmCounters=22、IptTrace=23、ThreadNames=24 等），
  并有对照测试钉住，防止抄错。
- 101 个测试全部通过（wasm 与 native 两个后端各跑一遍）；CLI 已在**本机真实 WER
  崩溃转储（15,759,507 字节，15 条流，113 张函数表、47 个线程名、8 条已卸载模块）**上
  跑通：正确识别 ThreadList/ModuleList/UnloadedModuleList/FunctionTable/MemoryList/
  Exception/SystemInfo/MiscInfo/SystemMemoryInfo/ProcessVmCounters/ThreadNames 各流，
  并把 header.flags 的 0x200121 拆成
  `WithDataSegs | WithUnloadedModules | WithProcessThreadData | WithAvxXStateContext`。
  每一段的字段级取值都用独立的 Node 抽取脚本对拍过，golden 不是从本实现输出生成的。

W4 的三块（长尾流、栈回溯 + 符号、`--json`）也都落地并测过：

- **长尾流**：ThreadNames / UnloadedModuleList / HandleData / FunctionTable / ThreadInfoList，
  每条偏移来自本机 SDK（`10.0.26100.0\um\minidumpapiset.h`），行号写在各处注释里。
  SDK 没有给出结构的流 —— CommentStreamA/W(10/11)、HandleOperationList(18) 的
  `AVRF_HANDLE_OPERATION`、SystemMemoryInfo(21)、ProcessVmCounters(22)、以及
  Breakpad/Crashpad 的 `0x4767…`/`0x4350…`/`0x4d7a…` 系列 —— 一律不做猜测解析，
  只在流目录里如实列出编号和长度。猜错偏移比不解析更糟：它会给出看起来很合理的错数据。
  步长这类事仍然靠实测：ThreadNames 的 C 结构按 8 字节对齐会 padding 到 16，
  而实测一条 568 字节的流 `(568-4)/12 = 47` 条整、`/16` 除不尽，所以按紧凑排布读。
- **栈回溯**：三种帧来源在结果里用 `kind` 分列，绝不混成一类 ——
  `context`（上下文给的指令指针，永远第一帧，它不是从栈上读出来的）、
  `fp`（帧指针链，x86 读 `[EBP+4]`、amd64 读 `[RBP+8]`、arm64 读 `[X29+8]`）、
  `scan`（按指针宽度扫栈窗口，捞回断链之后的帧，代价是局部变量里残留的旧值也会被算进来，
  所以调用方必须按 `kind` 区别对待；连续同值的槽只出一帧，合并了几个写进 notes）。
  没做的那一条同样重要：不解释 x64 `UNWIND_INFO`、不解释 `.sym` 里的
  `STACK CFI`/`STACK WIN`，因此这不是精确展开；这两套规则离线没有可核对的权威来源，
  按"没有权威就不写解析器"的规矩，宁可近似并在输出里标注，不猜语义。
  函数表流只作旁证（这个地址有没有被登记过），不参与展开。
- **符号**：Breakpad 文本 `.sym`（`MODULE`/`FILE`/`FUNC`/行记录/`PUBLIC`），
  匹配顺序是 debug id → pdb 名 → 模块名，`matched_by` 说清是哪一条命中的；
  `SymbolTarget.status` 用六种取值把"为什么没有符号"讲明白
  （`ok`/`unresolved`/`ambiguous`/`no_module`/`no_symbol_file`/`empty_store`）；
  没有有效 `MODULE` 行的文件进 `rejected` 列表，不静默丢弃。
- **`--json`**：自己的 schema `moondump/v1`，17 个顶层键固定顺序，缺失即 `null`，
  地址一律 `0x…` 字符串，64 位长度一律十进制字符串（JSON number 只在 2^53 内精确）。
  这套工具链没有 stderr 通道，所以参数错误、读文件失败、签名不合法统统写成文档里的
  `error` 字段 —— 调用方拿到的要么是能 `JSON.parse` 的报告，要么是失败的报告，
  不会是混着日志的文本。
- **语料回归**：`testdata/` 七份 rust-minidump 公开转储（MIT，许可证全文随附，含两份畸形）
  每份跑全字段摘要并钉 golden；畸形转储也必须出一份完整文档，而不是失败退出。
  JSON 那份走完整链路：`report_json → stringify → @json.parse` 把文本**读回来**再断言相等 ——
  只查内存里的 `Json` 值证明不了"这份文本是合法 JSON、字段名和层级真是这样"，
  而上游脚本拿到的就是文本。

## 6. 交付物形态

- MoonBit 库 `moondump`（`mooncakes.io` 可发布）+ `cmd/main` CLI + `examples/` 可运行示例。
- 文档化的公开 API：`Dump` / `Header` / `StreamEntry` / `SystemInfo` / `Module` /
  `UnloadedModule` / `MiscInfo` / `Exception` / `Thread` / `ThreadName` / `Handle` /
  `FunctionTable` / `ThreadInfo` / `Context` / `MemoryMap` / `MemoryRegion` /
  `StackFrame` / `StackWalk` / `StackWalkOptions` / `SymbolStore` / `SymbolFile` /
  `SymbolTarget` / `JsonOptions` / `Json` / `ParseError`。
  接口签名由 `moon info` 生成的 `pkg.generated.mbti` 钉住，对外接口一变就能看到 diff。
- JSON 报告：`dump.report_json(opts)` 出 `Json` 值，`json_report_text` 打印，
  失败文档 `json_failure(kind, message)`。
- 文档：README（用法、flag 表、真实输出摘录、schema 规则、实测发现、语料与参考来源、
  明确列出没做的事）、`docs/proposal.md`（本文件）、`testdata/README.md`（逐文件覆盖点）、
  最小 CI（`.github/workflows/ci.yml`，只跑本地已验证的 `moon fmt --check` /
  `moon check --deny-warn` / `moon test`）。

## 7. 格式层实测发现：FunctionTableStream 与 SDK 声明的排布不一致

这条是本地真实转储打出来的，公开语料里没有这一号流（WER 才写），值得单列，
因为它说明「只看头文件写解析器」会直接产出乱码：

- SDK（`minidumpapiset.h`）声明 `MINIDUMP_FUNCTION_TABLE_STREAM` 头 24 字节、
  描述符 `MINIDUMP_FUNCTION_TABLE_DESCRIPTOR` 32 字节，照这个步长读，
  描述符数组应当紧接在头后面。
- 真实 WER x64 转储里这条流 21,268 字节，头六个 u32 是 `24,32,136,12,113,4`
  （SizeOfHeader / SizeOfDescriptor / SizeOfNativeDescriptor / SizeOfFunctionEntry /
  NumberOfDescriptors / SizeOfAlignPad）。按 32 字节步长读，113 张表只有 6 张自洽，
  剩下的地址区间全是垃圾。
- 对起始偏移 ∈ [24,40]（步长 4）× 记录宽 ∈ [32,400]（步长 4）做一次全扫，
  **只有 (28, 184) 这一组让全部 113 条记录自洽**：描述符数组从
  `SizeOfHeader + SizeOfAlignPad` 开始，每条记录宽
  `SizeOfDescriptor + SizeOfNativeDescriptor + SizeOfFunctionEntry + SizeOfAlignPad`
  = 184 字节，即「描述符 + 原生描述符 + **内联的函数项** + 填充」。
  内联函数项落在 `记录 + SizeOfDescriptor + SizeOfNativeDescriptor`（偏移 168），
  正好是 x64 的 `IMAGE_FUNCTION_ENTRY` 三元组（Start/End/RVA of UNWIND_INFO），
  例如 `(0x0, 0x280, 0x298)`；这批转储里每条记录 `EntryCount` 都是 1。
  记录区之后还剩 448 个零字节。

实现的处理办法：不选边站，两个候选排布都按证据判——先按声明步长验，再按内联记录宽验，
谁自洽用谁；两个都不自洽时回落声明步长并在输出里明写「两种排布都不自洽，结果不可信」，
`layout_ok` 字段让调用方能程序化地拿到这个判断。函数项只在项宽恰为 12 字节
（x64 `IMAGE_FUNCTION_ENTRY`）时才摊成三元组，其它架构不猜结构。

## 8. 第二个实测发现：崩溃线程有两份上下文，而且它们停在完全不同的地方

这条来自公开语料 `testdata/test.dmp`（x86、崩溃线程 3060）：

- 异常流里那份 CONTEXT 的指令指针是 `0x40429e`，落在 `c:\test_app.exe+0x429e`，
  这就是崩溃那一刻的现场，展开 5 帧。
- 线程表里同一条线程的 CONTEXT 的指令指针是 `0x7c90eb94`，落在
  `C:\WINDOWS\system32\ntdll.dll+0xeb94`，也就是写转储的那一刻它已经不在崩溃现场了，
  展开 13 帧。

两份上下文回答的是两个不同的问题：只走线程表那份就永远看不到崩溃点，
只走异常那份就看不到这条线程当前卡在哪个系统调用里。所以两条都给，并且把顺序按
读者区别对待 —— **CLI 给人看**：先摆线程表上下文，再补一句「下面这条才是崩溃那一刻」，
把结论写在人眼前而不是藏在排序里；**JSON 给机器读**：`items[0]` 直接就是崩溃现场那条，
`source` 字段标明 `exception_context` / `thread_table_context`，两条都在，一条不少。
其余线程按线程表顺序跟在后面。判定条件是二者的指令指针不同；相同就只给一条，不重复。

这条也暴露过一个真实的数据丢失 bug：`--json` 那一路最初只走线程表上下文，
崩溃现场那条栈在机器可读的输出里整条不见了 —— 文本 CLI 有，JSON 没有，
两个通道同一份数据却不同源。是 corpus 的 golden 断言把 `walked` 从 2 顶到 3 时发现的
（这份文件 `threads=2` 而 `stacks.walked=3`，正因为崩溃线程贡献了两条栈）。
由此定了两条纪律写进测试：`walked` 统计的是**栈的条数**，`skipped_threads` 才是按线程算的；
JSON 必须经 `stringify → @json.parse` 读回来再断言，这样"少了一条"会在字段层面暴露，
而不是只在内存里的 `Json` 值上自我一致。

## 9. 已知局限（明写，不用"计划中"糊过去）

- 不做 PDB 解析、不接符号服务器；`.sym` 只读文本，不解释 `STACK CFI`/`STACK WIN`，
  x64 也不读 `UNWIND_INFO` —— 所以断链处给的是扫描近似，帧的 `kind` 会如实标出来。
- arm64 的帧指针链按同样形状实现，但离线没有真实 arm64 转储可证；走不通时输出里有
  对应 note，不会静默给出一条错的调用链。
- 公开语料里没有 WOW64（32 位进程跑在 64 位系统上）样本，所以"异常上下文与线程表
  上下文分属不同指针宽度"这种情况是按格式规则处理并有合成测试，**不是实测结论**。
- 不声称与 `minidump-stackwalk --json` 的字段兼容：这台机器上拿不到那个二进制，
  离线也没有可逐字节比对的渠道。参照物只在格式文档层面使用。
- 本地真实 WER 转储含进程内存与用户名路径，**不进仓库**（`.gitignore` 拦
  `*.dmp`/`testdata/local/`/`_scratch/`），只用于本地对拍，结论写进本文件。
- 仓库还没有首次提交：提交、公开仓库地址、`moon.mod` 的 `repository` 字段、本文件
  第 4 行的 GitHub 昵称和 W4 计划里的"发布 tag"是同一件事，都等真实昵称与推送授权确认后
  一并处理。代码、测试、文档、CI 配置在本地已全部就绪且可复跑。
