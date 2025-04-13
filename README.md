# deno-safeproxy
deno 安全代理脚本

使用说明

将上述代码保存为 deno.ts

修改 CONFIG 部分设置你的密码和其他配置，或设置相关的环境变量

运行命令：deno run --allow-net --allow-read deno.ts

功能说明
密码验证：

首次访问 / 会显示密码输入界面

输入正确密码后设置cookie并跳转到引导页

密码错误会显示错误信息

引导页面：

提供URL输入框，用户输入后跳转到 /proxy/URL

代理功能：

/proxy/URL - 需要验证cookie后进行代理

/apipath/URL - 直接代理，无需验证

支持HTTP/HTTPS/WS/WSS协议

自动处理重定向

过滤敏感headers

WebSocket支持：

自动检测并代理WebSocket连接

注意事项

请务必修改默认密码 your_secure_password

可以根据需要调整cookie的有效期和其他安全设置
