# iOS Capture

这是一个独立的越狱 iPhone 抓包项目。Android 的 ProxyPin + 算法助手 Pro + Hook JS 仅作为功能逻辑参考；本项目不属于 AppleLive，也不修改 AppleLive。

## 项目目标

面向已越狱 iPhone，提供尽量简单的 HTTP(S)/WebSocket 抓包流程：

1. ProxyPin 负责 VPN/代理、请求列表、重写与 HAR 导出。
2. 自有注入模块负责绕过目标 App 的 TLS 证书绑定，并按需观察应用层加解密。
3. 管理界面负责选择目标 App、自检、启停、状态和日志。
4. rootful 与 rootless 分别打包，由安装器按设备环境选择。

## 当前状态

v0.1.1 已完成编译和包体校验。包含目标 App 选择器、通用 TLS Hook、AFNetworking/TrustKit 兼容、可选 native TLS Hook，以及 rootless/rootful 构建流水线。

- iOS 15+、Dopamine/ElleKit：安装 `com.ioscapture_0.1.1_iphoneos-arm64.deb`。
- iOS 13、unc0ver/Substitute：安装 `com.ioscapture_0.1.1_iphoneos-arm.deb`。
- iOS 13 包内的 Hook 和管理 App 均包含 arm64 与 legacy arm64e，最低系统为 iOS 13.0。

- [架构与可行性](docs/ARCHITECTURE.md)
- [原型验证步骤](docs/PROTOTYPE_GUIDE.md)
- [兼容性计划](docs/COMPATIBILITY.md)
- [开发计划](PROJECT_PLAN.md)

## v0.1.1 功能

- 只对用户勾选的 App 启用 Hook。
- `SecTrustEvaluate`、`SecTrustEvaluateWithError` 和 `SecTrustGetTrustResult`。
- AFNetworking `AFSecurityPolicy`。
- TrustKit 验证与 challenge 处理。
- 可选 BoringSSL/OpenSSL 动态符号 Hook。
- 打开 ProxyPin、保存设置并结束目标 App。
- iOS 15+ rootless 和 iOS 13 rootful 独立 deb 构建。

## 构建

本项目使用 GitHub Actions 构建，不要求本地安装 Mac 或 Theos：

- `Build iOS Capture rootless`
- `Build iOS Capture iOS 13 rootful`

本地静态检查：

```powershell
python -m unittest discover -s tests -v
```

## 安装和使用

1. 先确认越狱环境已启用，并安装 ElleKit、Substitute 或 MobileSubstrate 中适合当前越狱的一项。
2. 用 Sileo、Zebra 或 Filza 安装与系统环境对应的 deb；安装完成后执行注销桌面或重启用户空间。
3. 安装并打开 ProxyPin。安装它生成的 CA 描述文件，再到“设置 -> 通用 -> 关于本机 -> 证书信任设置”中开启完全信任。
4. 打开 `iOS Capture`，勾选要测试的目标 App，保持“插件启用”和“TLS 兼容”开启，然后点“应用并重启”。
5. 在 ProxyPin 中启动 VPN 抓包，再打开目标 App 发起请求。
6. 普通 HTTPS 能看到、但特定接口仍失败时，再打开 `Native TLS` 后重新应用。该选项只建议按需开启。

管理 App 中“最近注入”出现目标 Bundle ID，说明 dylib 已进入目标进程。未出现时先确认选择已保存、目标 App 已完全结束，以及对应注入框架已启用。

## v0.1.1 边界

- 当前解决系统 TLS、AFNetworking、TrustKit，以及有动态导出符号的 BoringSSL/OpenSSL 校验。
- 目标 App 自定义 AES、RSA、签名参数或 protobuf 业务层加密，需要拿到具体 App 和接口后增加专用 Hook。
- 静态链接且无导出符号的 BoringSSL、Swift Trust 实现需要按目标 App 版本适配。
- HTTP/3/QUIC 回退尚未实现；遇到 UDP/443 流量时需要目标 App 支持回退到 HTTP/2。
- ProxyPin iOS 主工程面向 iOS 15+。iOS 13 可先使用电脑端代理；仅安装 TLS Hook 不会自动生成抓包列表。

## 已确认边界

- `Android(1).js` 主要绕过 SSL Pinning，不负责保存或展示流量。
- 算法助手 Pro 是 Android 的 Xposed/Frida 容器，不能直接移植到 iOS。
- iOS 需要用 ElleKit/Substrate dylib 重写 Hook 层。
- ProxyPin 官方项目包含 iOS `NEPacketTunnelProvider`，可先复用其抓包层。
- 当前 ProxyPin iOS 工程的主要 target 为 iOS 15.0；iOS 13/14 需要电脑代理或另行适配。
