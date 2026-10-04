# 开发计划

## 交付形态

正式版本由三个部分组成：

1. `iOSCaptureManager.app`：选择目标 App、检查证书和注入状态、查看错误。
2. `iOSCaptureHook.dylib`：注入目标 App，处理 TLS Pinning、HTTP/3 回退和可选加解密观察。
3. 安装包：rootful 与 rootless 各一份 deb；批量安装工具自动选择正确包。

ProxyPin 作为独立抓包应用保留。第一版不复制其界面和代码，也不把第三方二进制塞入我们的 deb。

## 阶段

| 阶段 | 内容 | 验收条件 |
|---|---|---|
| 1. 基线 | 自有 HTTPS 测试 App、CA 信任、ProxyPin iOS/电脑代理链路 | 无 Pinning 请求可稳定解密并导出 HAR |
| 2. TLS Hook | Security.framework、NSURLSession challenge、TrustKit/AFNetworking 适配 | 启用 Pinning 的测试 App 可抓取 |
| 3. Native TLS | BoringSSL/libcurl/自定义校验适配，HTTP/3 回退 | 覆盖至少一款 native TLS 测试 App |
| 4. 管理界面 | App 选择、自检、启停、日志和故障说明 | 普通用户只需选择 App 并打开抓包 |
| 5. 多版本打包 | iOS 13 rootful 与 iOS 15+ rootless | 两类设备分别安装、卸载、升级通过 |
| 6. 批量部署 | 自动识别越狱类型和架构、安装对应包 | 新设备无需手工复制 dylib 或编辑 plist |

## 当前进度

| 项目 | 状态 |
|---|---|
| v0.1.0 管理 App 源码 | complete |
| 通用 TLS Hook 源码 | complete |
| rootless/rootful CI | ready_for_build |
| 实体机安装与 ProxyPin 联调 | pending |
| 应用层加密 Hook | pending |

## 第一版不承诺

- 非越狱手机对任意 App 的全局注入。
- QUIC/HTTP3、私有 UDP 协议和原生 RTMP/RTSP 的明文解析。
- 未知 App 自定义加密请求体的自动解密。
- 所有 iOS 版本使用同一个 dylib 或同一个 deb。
