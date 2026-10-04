# 可复用记录：Android unpinning 逻辑迁移到 iOS 抓包产品

## 模式

跨平台迁移抓包方案时，先把“流量转发/展示”“TLS Pinning 绕过”“应用层算法观察”拆成独立职责。Android 的 TrustManager/OkHttp Hook 不能直接移植到 iOS，但分层结构可以保留。

## 关键证据

- E-002：通用 Hook JS 解决证书校验，不承担代理和协议展示。
- E-003：iOS Packet Tunnel 可以承担设备流量导向代理。
- E-005：iOS 侧以 Security.framework、NSURLSession 和目标 App native TLS 为 Hook 入口。

## 可复用结论

产品化时应把研究阶段的 Frida/脚本 Hook 固化为受 Bundle ID 白名单控制的原生 dylib，并把 rootful/rootless 差异放到构建和安装层处理。
