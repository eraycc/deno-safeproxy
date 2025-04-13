// proxy_server.ts
import { serve } from "https://deno.land/std@0.152.0/http/server.ts";
import { cookie } from "https://deno.land/std@0.152.0/http/cookie.ts";
import { load } from "https://deno.land/std@0.152.0/dotenv/mod.ts";

// 尝试加载.env文件
let envVars: Record<string, string> = {};
try {
  envVars = await load();
} catch (error) {
  console.log("No .env file found, using environment variables only");
}

// 配置项（从环境变量获取或使用默认值）
const CONFIG = {
  PASSWORD: Deno.env.get("PROXY_PASSWORD") || envVars.PROXY_PASSWORD || "your_secure_password",
  COOKIE_NAME: Deno.env.get("PROXY_COOKIE_NAME") || envVars.PROXY_COOKIE_NAME || "proxy_auth",
  PORT: parseInt(Deno.env.get("PROXY_PORT") || envVars.PROXY_PORT || "8000"),
  APIPATH: Deno.env.get("PROXY_APIPATH") || envVars.PROXY_APIPATH || "/apipath",
};

// 密码验证页面HTML
const passwordPage = (message = "") => `
<!DOCTYPE html>
<html>
<head>
  <title>Proxy Authentication</title>
  <style>
    body {
      font-family: Arial, sans-serif;
      background-color: #f5f5f5;
      display: flex;
      justify-content: center;
      align-items: center;
      height: 100vh;
      margin: 0;
    }
    .container {
      background: white;
      padding: 2rem;
      border-radius: 8px;
      box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
      width: 300px;
      text-align: center;
    }
    h1 {
      color: #333;
      margin-top: 0;
    }
    input {
      width: 100%;
      padding: 10px;
      margin: 10px 0;
      border: 1px solid #ddd;
      border-radius: 4px;
      box-sizing: border-box;
    }
    button {
      background-color: #4CAF50;
      color: white;
      padding: 10px 15px;
      border: none;
      border-radius: 4px;
      cursor: pointer;
      width: 100%;
    }
    button:hover {
      background-color: #45a049;
    }
    .message {
      color: #e74c3c;
      margin: 10px 0;
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>Proxy Authentication</h1>
    ${message ? `<div class="message">${message}</div>` : ""}
    <form method="POST" action="/auth">
      <input type="password" name="password" placeholder="Enter password" required>
      <button type="submit">Submit</button>
    </form>
  </div>
</body>
</html>
`;

// 引导页面HTML
const guidePage = `
<!DOCTYPE html>
<html>
<head>
  <title>Proxy Guide</title>
  <style>
    body {
      font-family: Arial, sans-serif;
      background-color: #f5f5f5;
      display: flex;
      justify-content: center;
      align-items: center;
      height: 100vh;
      margin: 0;
    }
    .container {
      background: white;
      padding: 2rem;
      border-radius: 8px;
      box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
      width: 500px;
      text-align: center;
    }
    h1 {
      color: #333;
      margin-top: 0;
    }
    input {
      width: 100%;
      padding: 10px;
      margin: 10px 0;
      border: 1px solid #ddd;
      border-radius: 4px;
      box-sizing: border-box;
    }
    button {
      background-color: #4CAF50;
      color: white;
      padding: 10px 15px;
      border: none;
      border-radius: 4px;
      cursor: pointer;
      width: 100%;
    }
    button:hover {
      background-color: #45a049;
    }
    .example {
      margin-top: 20px;
      color: #666;
      font-size: 0.9em;
      text-align: left;
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>Proxy Service</h1>
    <form id="proxyForm">
      <input type="text" id="url" name="url" placeholder="Enter URL to proxy (e.g., https://example.com)" required>
      <button type="submit">Visit</button>
    </form>
    <div class="example">
      <p>Examples:</p>
      <ul>
        <li>https://example.com</li>
        <li>http://httpbin.org/get</li>
        <li>ws://echo.websocket.org</li>
      </ul>
    </div>
  </div>
  <script>
    document.getElementById('proxyForm').addEventListener('submit', function(e) {
      e.preventDefault();
      const url = document.getElementById('url').value;
      if (url) {
        window.location.href = '/proxy/' + encodeURIComponent(url);
      }
    });
  </script>
</body>
</html>
`;

// 验证密码
function verifyPassword(cookies: Record<string, string>): boolean {
  return cookies[CONFIG.COOKIE_NAME] === CONFIG.PASSWORD;
}

// 处理代理请求
async function handleProxyRequest(urlStr: string, req: Request): Promise<Response> {
  try {
    // 过滤掉密码cookie和其他敏感headers
    const headers = new Headers(req.headers);
    headers.delete("cookie");
    headers.delete("host");

    // 处理WebSocket升级请求
    if (headers.get("upgrade")?.toLowerCase() === "websocket") {
      const { response, socket } = Deno.upgradeWebSocket(req);
      const targetUrl = new URL(urlStr);
      const targetSocket = new WebSocket(
        targetUrl.toString(),
        Array.from(headers.entries()).reduce((acc, [key, value]) => {
          acc[key] = value;
          return acc;
        }, {} as Record<string, string>)
      );

      socket.onopen = () => targetSocket.onopen = () => {};
      socket.onmessage = (e) => targetSocket.send(e.data);
      targetSocket.onmessage = (e) => socket.send(e.data);
      socket.onclose = () => targetSocket.close();
      targetSocket.onclose = () => socket.close();
      socket.onerror = (e) => console.error("Client WebSocket error:", e);
      targetSocket.onerror = (e) => console.error("Target WebSocket error:", e);

      return response;
    }

    // 普通HTTP/HTTPS请求
    const proxyReq = new Request(urlStr, {
      method: req.method,
      headers: headers,
      body: req.method !== "GET" && req.method !== "HEAD" ? req.body : undefined,
    });

    const proxyRes = await fetch(proxyReq);

    // 创建一个新的响应，复制所有headers
    const resHeaders = new Headers(proxyRes.headers);
    
    // 处理重定向
    if (proxyRes.status >= 300 && proxyRes.status < 400) {
      const location = proxyRes.headers.get("location");
      if (location) {
        // 如果是相对路径，转换为绝对路径
        try {
          new URL(location);
        } catch {
          const newLocation = new URL(location, urlStr).toString();
          resHeaders.set("location", `/proxy/${encodeURIComponent(newLocation)}`);
        }
      }
    }

    // 返回代理响应
    return new Response(proxyRes.body, {
      status: proxyRes.status,
      headers: resHeaders,
    });
  } catch (error) {
    console.error("Proxy error:", error);
    return new Response("Proxy error: " + error.message, { status: 500 });
  }
}

// 主请求处理器
async function handleRequest(req: Request): Promise<Response> {
  const url = new URL(req.url);
  const cookies = cookie.getCookies(req.headers);

  // 处理认证请求
  if (url.pathname === "/auth" && req.method === "POST") {
    const formData = await req.formData();
    const password = formData.get("password");
    
    if (password === CONFIG.PASSWORD) {
      const headers = new Headers();
      cookie.setCookie(headers, {
        name: CONFIG.COOKIE_NAME,
        value: CONFIG.PASSWORD,
        path: "/",
        httpOnly: true,
        maxAge: 86400, // 1天
      });
      headers.set("location", "/");
      return new Response(null, { status: 303, headers });
    } else {
      return new Response(passwordPage("Invalid password"), { status: 401 });
    }
  }

  // 处理API路径请求
  if (url.pathname.startsWith(CONFIG.APIPATH)) {
    const targetUrl = url.pathname.slice(CONFIG.APIPATH.length + 1);
    if (!targetUrl) {
      return new Response("Missing URL parameter", { status: 400 });
    }
    
    try {
      // 解码URL并验证格式
      const decodedUrl = decodeURIComponent(targetUrl);
      new URL(decodedUrl); // 验证URL格式
      return await handleProxyRequest(decodedUrl, req);
    } catch (error) {
      return new Response("Invalid URL: " + error.message, { status: 400 });
    }
  }

  // 处理代理请求
  if (url.pathname.startsWith("/proxy/")) {
    if (!verifyPassword(cookies)) {
      const headers = new Headers();
      headers.set("location", "/");
      return new Response(null, { status: 303, headers });
    }
    
    const targetUrl = url.pathname.slice("/proxy/".length);
    if (!targetUrl) {
      return new Response("Missing URL parameter", { status: 400 });
    }
    
    try {
      // 解码URL并验证格式
      const decodedUrl = decodeURIComponent(targetUrl);
      new URL(decodedUrl); // 验证URL格式
      return await handleProxyRequest(decodedUrl, req);
    } catch (error) {
      return new Response("Invalid URL: " + error.message, { status: 400 });
    }
  }

  // 处理根路径请求
  if (url.pathname === "/") {
    if (verifyPassword(cookies)) {
      return new Response(guidePage, {
        headers: { "content-type": "text/html" },
      });
    } else {
      return new Response(passwordPage(), {
        headers: { "content-type": "text/html" },
      });
    }
  }

  // 其他路径返回404
  return new Response("Not Found", { status: 404 });
}

// 启动服务器
console.log(`Proxy server running on http://localhost:${CONFIG.PORT}`);
serve(handleRequest, { port: CONFIG.PORT });
