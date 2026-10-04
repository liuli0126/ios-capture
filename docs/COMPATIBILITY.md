# 兼容性计划

以下是开发目标，不代表已经实机通过。

| 系统范围 | 越狱形态 | 注入包 | ProxyPin 建议 | 当前结论 |
|---|---|---|---|---|
| iOS 13.x | rootful / unc0ver + Substitute | `iphoneos-arm` deb | 电脑端 ProxyPin | 可做，需单独编译和实机验证 |
| iOS 14.x | rootful 或设备相关方案 | 单独 rootful 包 | 优先电脑端 ProxyPin | 可做，环境差异较大 |
| iOS 15.x | rootless / Dopamine + ElleKit | `iphoneos-arm64` deb | ProxyPin iOS 或电脑端 | 主开发与测试范围 |
| iOS 16.x | rootless / Dopamine 或 palera1n | `iphoneos-arm64` deb | ProxyPin iOS 或电脑端 | 可做，需按设备验证 |
| iOS 17+ | 取决于可用越狱和注入框架 | 未定 | 未定 | 不承诺 |
| TrollStore 但未越狱 | 无全局 tweak 注入 | 每 App 注入方案 | ProxyPin iOS | 只能作为后续独立分支，不能替代越狱主方案 |

## 架构与库覆盖

- 第一优先级：arm64/arm64e 的现代 iPhone。
- rootful 和 rootless 的文件路径、依赖和包架构不同，必须分开验收。
- Security.framework/NSURLSession 可做通用基线。
- TrustKit、AFNetworking、Alamofire、BoringSSL、Cronet/libcurl 需要分库验证。
- 目标 App 每次大版本升级后，自定义 native/Swift Hook 都可能需要更新。

## ProxyPin 事实基线

截至 2026-10-04，ProxyPin 官方仓库：

- README 声明支持 Windows、macOS、Android、iOS 和 Linux。
- v1.3.3 release 提供 `proxypin-ios-1.3.3.ipa`。
- iOS 源码包含 Packet Tunnel Network Extension。
- Xcode 工程主要 target 的 deployment target 为 iOS 15.0。
- 项目许可证为 Apache-2.0。

正式集成前还需要复核 ProxyPin 的商标、分发方式和版本依赖；第一版保持第三方应用独立安装。
