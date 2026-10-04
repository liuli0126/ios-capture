# iOS Capture

这是一个独立的越狱 iPhone 抓包项目。Android 的 ProxyPin + 算法助手 Pro + Hook JS 仅作为功能逻辑参考；本项目不属于 AppleLive，也不修改 AppleLive。

## 项目目标

面向已越狱 iPhone，提供尽量简单的 HTTP(S)/WebSocket 抓包流程：

1. ProxyPin 负责 VPN/代理、请求列表、重写与 HAR 导出。
2. 自有注入模块负责绕过目标 App 的 TLS 证书绑定，并按需观察应用层加解密。
3. 管理界面负责选择目标 App、自检、启停、状态和日志。
4. rootful 与 rootless 分别打包，由安装器按设备环境选择。

## 当前状态

当前已经完成 v0.1.0 源码：包含目标 App 选择器、通用 TLS Hook、AFNetworking/TrustKit 兼容、可选 native TLS Hook，以及 rootless/rootful 构建流水线。安装包需要 GitHub Actions 首次编译通过后交付。

- [架构与可行性](docs/ARCHITECTURE.md)
- [原型验证步骤](docs/PROTOTYPE_GUIDE.md)
- [兼容性计划](docs/COMPATIBILITY.md)
- [开发计划](PROJECT_PLAN.md)

## v0.1.0 功能

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

## 已确认边界

- `Android(1).js` 主要绕过 SSL Pinning，不负责保存或展示流量。
- 算法助手 Pro 是 Android 的 Xposed/Frida 容器，不能直接移植到 iOS。
- iOS 需要用 ElleKit/Substrate dylib 重写 Hook 层。
- ProxyPin 官方项目包含 iOS `NEPacketTunnelProvider`，可先复用其抓包层。
- 当前 ProxyPin iOS 工程的主要 target 为 iOS 15.0；iOS 13/14 需要电脑代理或另行适配。
