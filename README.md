# pairwise-grpc-guard

内部服务从 REST 改成 gRPC 后，方法暴露和元数据伪造就放大了：reflection 在生产开启，所有方法可枚举；方法名没有白名单，内部调试接口能被调用；metadata 里的用户身份直接采信；streaming 方法不校验租户，能跨租户推送；deadline 没有上限，慢调用拖住连接池；消息大小不限制，单请求打满内存；TLS 只做单向认证，客户端身份不可信；拦截器顺序错误，鉴权在日志之后；peer 信息被代理头覆盖；错误详情回显堆栈和内部地址。security/grpc_guard.py 是核心，tests/test_grpc_guard.py 15个红。要修的是：关闭 reflection；方法白名单；metadata 签名校验；流式租户隔离；deadline 上限；消息大小限制；双向 TLS；拦截器顺序；peer 取真实连接；错误脱敏。

## 运行

```bash
python -m pytest tests -q
```

初始状态：15 个用例失败。修复实现使全部用例通过，不要修改 `tests/` 下的测试。

子方向：其他；任务类型：Bugfix；语言/框架：Python 3, pytest；环境可复现等级：无外部依赖。
