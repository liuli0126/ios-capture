# 第一阶段原型验证步骤

当前文档用于验证技术路线。自有 `iOSCaptureHook.dylib` 尚未开发完成，因此这一阶段用现有工具建立基线。

## iOS 15 及以上

1. 在 iPhone 安装 ProxyPin 官方 iOS 版。
2. 在 ProxyPin 中安装其 CA 描述文件。
3. 打开“设置 -> 通用 -> 关于本机 -> 证书信任设置”，对该 CA 开启完全信任。
4. 启动 ProxyPin 抓包和 VPN。
5. 先打开一个没有 Pinning 的自有 HTTPS 测试 App，确认能看到 URL、请求头和响应体。
6. 再打开启用了 Pinning 的测试 App，记录失败现象，作为 Hook 前基线。
7. 在越狱环境中用 Frida/Objection 临时验证 `ios sslpinning disable` 后能否看到明文。
8. 把验证成功的 Hook 点移入自有 dylib，而不是让最终用户长期运行 Frida。

## iOS 13/14

当前 ProxyPin iOS 主工程 target 为 iOS 15.0。iOS 13/14 第一阶段改用电脑端 ProxyPin：

1. 手机与电脑连接同一局域网。
2. 在 iPhone 当前 Wi-Fi 中把 HTTP 代理设为手动，服务器填写电脑局域网 IP，端口填写 ProxyPin 监听端口。
3. 在手机安装并完全信任电脑端 ProxyPin 的 CA。
4. 用 rootful 注入模块处理目标 App Pinning。

## 验收记录

每台测试设备记录以下信息：

| 项目 | 内容 |
|---|---|
| iPhone 型号 / 芯片 | 例如 iPhone 11 / A13 |
| iOS 版本与构建号 | 例如 15.6 / 19G71 |
| 越狱与注入框架 | Dopamine + ElleKit 或 unc0ver + Substitute |
| ProxyPin 运行位置 | 手机或电脑 |
| 目标测试 App / 版本 | 仅填写已授权测试目标 |
| 普通 HTTPS | 成功或失败 |
| Pinning 绕过 | 成功或失败及命中 Hook |
| WebSocket | 成功或失败 |
| HTTP/3 回退 | 成功、失败或不适用 |
| HAR 导出 | 成功或失败 |
