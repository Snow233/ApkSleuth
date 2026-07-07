# ApkSleuth

**语言:** [English](README.md) | 简体中文

ApkSleuth 是一个本地优先的 Android APK 静态分析工具，面向应用安全审计、逆向学习、Android 开发自检和应用风险排查。

它可以提取 APK 基础信息、Manifest 配置、权限、导出组件、URL、IP、邮箱、疑似密钥、证书、Native 库、SDK 指纹、加固/混淆线索和安全风险项，并生成 JSON、Markdown、HTML、简报、结构化简报 JSON、批量扫描索引和 APK Diff 报告。

APK 默认只在本地分析。ApkSleuth 不上传 APK，不依赖云端服务，也不需要账号。

## 功能亮点

- 本地 APK 静态分析，无外部服务依赖。
- 纯 Python Manifest 解析，支持 Android Binary XML。
- `resources.arsc` 字符串解析，可还原常见 Manifest 资源引用。
- 权限分级和高危权限检测。
- Activity、Service、Receiver、Provider、Deep Link、受权限保护组件、媒体组件和 Launcher 入口的导出组件分析。
- Manifest 安全配置检查，包括 `debuggable`、`allowBackup`、`usesCleartextTraffic` 和网络安全配置线索。
- URL、IP、邮箱、JWT、Base64、疑似硬编码密钥提取，并对许可证、文档、Schema、SVG 元数据、字体、证书包等常见噪声做过滤。
- V1 / V2 / V3 APK 签名方案检测，可选解析 X.509 证书详情。
- Native 库 ABI、大小和 Hash 摘要。
- SDK 指纹和加固/混淆指纹识别。
- CLI 支持 `json`、`markdown`、`html`、`summary`、`summary-json` 报告格式。
- HTML 报告支持风险搜索、等级筛选、匹配计数和折叠区块。
- 本地 Web UI 支持 APK 上传、多文件批量上传、后台任务、状态轮询、报告历史、搜索、风险排序、删除清理和报告详情页。
- 批量扫描支持风险排行和机器可读索引输出。
- APK Diff 支持版本、权限、组件、URL、SDK、Native 库和签名方案变化对比。

## 项目状态

ApkSleuth 仍处于早期阶段。内置规则偏保守，输出应被理解为静态分析信号，而不是漏洞定论。

建议把报告作为人工复核前的风险分流层使用。

## 安装

需要 Python 3.10 或更高版本。

```bash
python -m pip install -e .
```

如需解析证书主体、颁发者、有效期和指纹等 X.509 详情，可以安装可选依赖：

```bash
python -m pip install -e ".[certificates]"
```

开发依赖：

```bash
python -m pip install -e ".[dev]"
```

## CLI 使用

查看帮助：

```bash
python -m apksleuth --help
python -m apksleuth scan --help
```

生成适合人工快速查看的简报：

```bash
python -m apksleuth scan path/to/app.apk --format summary --output report.summary.md
```

生成单文件 HTML 报告：

```bash
python -m apksleuth scan path/to/app.apk --format html --output report.html
```

生成完整机器可读 JSON：

```bash
python -m apksleuth scan path/to/app.apk --format json --output report.json
```

生成结构化简报 JSON，适合 Web UI、批量扫描和自动化处理：

```bash
python -m apksleuth scan path/to/app.apk --format summary-json --output report.summary.json
```

大 APK 扫描时显示进度：

```bash
python -m apksleuth scan path/to/app.apk --format summary --output report.summary.md --progress
```

CLI 执行子命令时会把 ApkSleuth Logo 输出到 `stderr`。报告内容仍保留在 `stdout` 或输出文件中，因此不会污染 JSON 等机器可读输出。

## 批量扫描

扫描目录中的所有 APK 并生成索引：

```bash
python -m apksleuth batch path/to/apks --output reports --format summary-json --lang zh --progress
```

递归扫描：

```bash
python -m apksleuth batch path/to/apks --output reports --recursive
```

批量扫描输出包括：

- 每个 APK 的独立报告。
- `index.md`：人工可读的总览和风险排行。
- `index.json`：适合自动化和下游工具的结构化索引。

## APK Diff

对比两个 APK 版本：

```bash
python -m apksleuth diff path/to/old.apk path/to/new.apk --format summary --output diff.md --lang zh
```

生成结构化 Diff JSON：

```bash
python -m apksleuth diff path/to/old.apk path/to/new.apk --format summary-json --output diff.json
```

Diff 报告会对比：

- 版本和 APK 基础信息变化。
- 风险数量变化。
- 权限新增和移除。
- 组件新增和移除。
- URL 新增和移除。
- SDK 新增和移除。
- Native 库新增和移除。
- 签名方案变化。

## Web UI

启动本地 Web UI：

```bash
python -m apksleuth web --host 127.0.0.1 --port 8765 --open
```

Web UI 默认监听 `127.0.0.1`。上传文件和生成报告保存在 `.apksleuth-web/` 目录下。

Web UI 功能：

- 上传一个或多个 APK 文件。
- 输入一个或多个本机 APK 路径，每行一个。
- 后台分析任务和状态轮询。
- 首页查看当前活动任务。
- 浏览报告历史。
- 按应用名、包名、版本、SHA256 或风险关键字搜索历史记录。
- 按最新时间、综合风险、高危数量、中危数量、总风险数量或应用名排序。
- 删除历史记录并清理由 Web UI 管理的上传副本。
- 详情页支持风险搜索、等级筛选、导出组件样例、HTTP URL 样例、疑似密钥样例、SDK 指纹、加固/混淆线索、修复建议和解析说明。
- 下载 HTML、Markdown 简报、结构化简报 JSON 和完整 JSON 报告。

## 报告格式

- `summary`：简洁 Markdown 简报，适合人工快速查看。
- `summary-json`：结构化简报，适合 Web UI、批量扫描和自动化流程。
- `html`：单文件交互式 HTML 报告。
- `markdown`：完整 Markdown 报告。
- `json`：完整机器可读分析数据。

## 报告内容

报告可能包含：

- APK 概览和 Hash。
- 风险概览和总体判断。
- Manifest 安全检查。
- 权限分析。
- 导出组件分析。
- Deep Link 和 Provider 信号。
- 网络痕迹。
- 疑似密钥。
- 证书和签名方案信息。
- Native 库。
- SDK 指纹。
- 加固/混淆线索。
- 优先修复建议。
- 解析说明和局限性。

## 语言

默认报告语言是中文：

```bash
python -m apksleuth scan path/to/app.apk --format summary --output report.zh.md --lang zh
```

也支持英文报告：

```bash
python -m apksleuth scan path/to/app.apk --format summary --output report.en.md --lang en
python -m apksleuth scan path/to/app.apk --format html --output report.en.html --lang en
```

JSON 字段名保持英文，便于稳定解析。

## 仓库卫生

本仓库不会跟踪 APK 样本、生成报告、Web UI 工作目录、批量扫描输出或 Python 字节码。

已忽略的本地产物包括：

- `*.apk`、`*.aab`、`*.apks`
- `.apksleuth-web/`
- `.apksleuth-web-test/`
- `batch-reports/`
- 生成的 `report*`、`summary*` 和 `diff*` 文件
- `__pycache__/` 和 `*.pyc`

除非明确需要小型合成 fixture，否则不要把真实 APK 样本和报告输出提交到仓库。

## 开发

运行测试：

```bash
python -m unittest discover
```

运行语法编译检查：

```bash
python -m compileall apksleuth tests
```

提交前推荐本地验证：

```bash
python -m unittest discover
python -m compileall apksleuth tests
```

## 安全边界

ApkSleuth 仅用于授权测试、应用安全审计、逆向学习和防御性风险分析。

本项目不提供破解、盗版、绕过登录、绕过付费、绕过授权、绕过风控、绕过 SSL Pinning 或未授权动态 Hook 等能力。

静态分析存在天然局限。请结合应用上下文、业务逻辑、运行时行为和授权边界复核报告结论。

## 路线图

- 更精细的导出组件规则和 Android 框架组件建模。
- 更好的 Deep Link 报告，包含 scheme、host、path 和路由聚合。
- 更完整的 Android 生态 SDK 和加固指纹库。
- 通过 YAML 或 JSON 支持自定义规则。
- HTML Diff 报告。
- Web UI 历史趋势视图。
- 基于小型合成 APK fixture 的报告快照测试。
- 可选的 FastAPI Web UI 后端，用于更大的部署场景。

## 许可证

ApkSleuth 使用 MIT License 发布。详见 [LICENSE](LICENSE)。
