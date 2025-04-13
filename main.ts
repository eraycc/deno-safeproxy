// proxy_server.ts
import { serve } from "https://deno.land/std@0.152.0/http/server.ts";
import { cookie } from "https://deno.land/std@0.152.0/http/cookie.ts";
import { load } from "https://deno.land/std@0.152.0/dotenv/mod.ts";

// 加载环境配置
async function loadConfig() {
  let envVars: Record<string, string> = {};
  try {
    envVars = await load();
  } catch {
    console.log("No .env file found, using environment variables only");
  }

  const config = {
    PASSWORD: Deno.env.get("PROXY_PASSWORD") || envVars.PROXY_PASSWORD || "your_secure_password",
    COOKIE_NAME: Deno.env.get("PROXY_COOKIE_NAME") || envVars.PROXY_COOKIE_NAME || "proxy_auth",
    PORT: parseInt(Deno.env.get("PROXY_PORT") || envVars.PROXY_PORT || "8000"),
    APIPATH: Deno.env.get("PROXY_APIPATH") || envVars.PROXY_APIPATH || "/apipath",
    COOKIE_MAX_AGE: Deno.env.get("COOKIE_EXPIRE_TIME") || envVars.COOKIE_EXPIRE_TIME || "604800" //7天
  };

  console.log("Proxy server configuration:");
  console.log(`- Password: ${config.PASSWORD ? "******" : "Not set"}`);
  console.log(`- Cookie name: ${config.COOKIE_NAME}`);
  console.log(`- Port: ${config.PORT}`);
  console.log(`- API path: ${config.APIPATH}`);

  if (config.PASSWORD === "your_secure_password") {
    console.warn("\nWARNING: Using default password! Please set PROXY_PASSWORD for security.\n");
  }

  return config;
}

const CONFIG = await loadConfig();

// HTML 模板
const HTML_TEMPLATES = {
  passwordPage: (message = "") => `
    <!DOCTYPE html>
    <html>
    <head>
      <title>Proxy Authentication</title>
      <style>
        body { font-family: Arial, sans-serif; background-color: #f5f5f5; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .container { background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1); width: 300px; text-align: center; }
        h1 { color: #333; margin-top: 0; }
        input { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
        button { background-color: #4CAF50; color: white; padding: 10px 15px; border: none; border-radius: 4px; cursor: pointer; width: 100%; }
        button:hover { background-color: #45a049; }
        .message { color: #e74c3c; margin: 10px 0; }
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
  `,

  guidePage: `
    <!DOCTYPE html>
    <html>
    <head>
      <title>Proxy Guide</title>
      <style>
        body { font-family: Arial, sans-serif; background-color: #f5f5f5; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .container { background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1); width: 500px; text-align: center; }
        h1 { color: #333; margin-top: 0; }
        input { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
        button { background-color: #4CAF50; color: white; padding: 10px 15px; border: none; border-radius: 4px; cursor: pointer; width: 100%; }
        button:hover { background-color: #45a049; }
        .example { margin-top: 20px; color: #666; font-size: 0.9em; text-align: left; }
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
  `
};

// 认证相关函数
function verifyAuth(cookies: Record<string, string>): boolean {
  return cookies[CONFIG.COOKIE_NAME] === CONFIG.PASSWORD;
}

function setAuthCookie(headers: Headers): void {
  cookie.setCookie(headers, {
    name: CONFIG.COOKIE_NAME,
    value: CONFIG.PASSWORD,
    path: "/",
    httpOnly: true,
    maxAge: CONFIG.COOKIE_MAX_AGE,
  });
}

// 提取并解码URL路径
function extractAndDecodeUrl(pathname: string, prefix: string): string | null {
  const rawUrl = pathname.slice(prefix.length);
  if (!rawUrl) return null;
  
  try {
    // 尝试直接解码（处理编码过的URL）
    const decodedUrl = decodeURIComponent(rawUrl);
    // 验证解码后的URL是否有效
    new URL(decodedUrl);
    return decodedUrl;
  } catch (decodeError) {
    try {
      // 如果解码失败，尝试直接使用原始URL（处理未编码的URL）
      new URL(rawUrl);
      return rawUrl;
    } catch (rawError) {
      console.error("URL解析失败:", { decodeError, rawError });
      return null;
    }
  }
}

// 代理请求处理器
async function handleProxyRequest(urlStr: string, req: Request): Promise<Response> {
  try {
    const targetUrl = new URL(urlStr);
    const headers = new Headers(req.headers);

    // 过滤掉密码cookie
    if (headers.has("cookie")) {
      const cookies = headers.get("cookie")!
        .split(';')
        .map(c => c.trim())
        .filter(c => !c.startsWith(`${CONFIG.COOKIE_NAME}=`));
      
      cookies.length > 0 
        ? headers.set("cookie", cookies.join('; ')) 
        : headers.delete("cookie");
    }

    // 必须删除host头
    headers.delete("host");

    // WebSocket 代理
    if (headers.get("upgrade")?.toLowerCase() === "websocket") {
      const { response, socket } = Deno.upgradeWebSocket(req);
      const targetSocket = new WebSocket(
        targetUrl.toString(),
        Array.from(headers.entries()).reduce((acc, [k, v]) => ({ ...acc, [k]: v }), {})
      );

      socket.onopen = () => targetSocket.onopen = () => {};
      socket.onmessage = (e) => targetSocket.send(e.data);
      targetSocket.onmessage = (e) => socket.send(e.data);
      socket.onclose = () => targetSocket.close();
      targetSocket.onclose = () => socket.close();
      socket.onerror = (e) => console.error("Client WS error:", e);
      targetSocket.onerror = (e) => console.error("Target WS error:", e);

      return response;
    }

    // HTTP/HTTPS 代理
    const proxyRes = await fetch(targetUrl.toString(), {
      method: req.method,
      headers: headers,
      body: req.body,
    });

    const resHeaders = new Headers(proxyRes.headers);
    
    // 处理重定向
    if ([301, 302, 303, 307, 308].includes(proxyRes.status)) {
      const location = proxyRes.headers.get("location");
      if (location) {
        try {
          new URL(location);
        } catch {
          const newLocation = new URL(location, targetUrl).toString();
          resHeaders.set("location", `/proxy/${encodeURIComponent(newLocation)}`);
        }
      }
    }

    return new Response(proxyRes.body, {
      status: proxyRes.status,
      headers: resHeaders,
    });
  } catch (error) {
    console.error("Proxy error:", error);
    return new Response(`Proxy error: ${error.message}`, { status: 500 });
  }
}

// 主请求路由器
async function handleRequest(req: Request): Promise<Response> {
  const url = new URL(req.url);
  const cookies = cookie.getCookies(req.headers);

  // 认证路由
  if (url.pathname === "/auth" && req.method === "POST") {
    const formData = await req.formData();
    const password = formData.get("password");
    
    if (password === CONFIG.PASSWORD) {
      const headers = new Headers();
      setAuthCookie(headers);
      headers.set("location", "/");
      return new Response(null, { status: 303, headers });
    }
    return new Response(HTML_TEMPLATES.passwordPage("Invalid password"), { 
      status: 401,
      headers: { "content-type": "text/html" },
    });
  }

  // API代理路由
  if (url.pathname.startsWith(CONFIG.APIPATH)) {
    const targetUrl = extractAndDecodeUrl(url.pathname, CONFIG.APIPATH + "/");
    if (!targetUrl) return badRequest("Missing or invalid URL parameter");
    
    try {
      return await handleProxyRequest(targetUrl, req);
    } catch (error) {
      return badRequest(`Invalid URL: ${error.message}`);
    }
  }

  // 普通代理路由
  if (url.pathname.startsWith("/proxy/")) {
    if (!verifyAuth(cookies)) {
      return redirectTo("/");
    }
    
    const targetUrl = extractAndDecodeUrl(url.pathname, "/proxy/");
    if (!targetUrl) return badRequest("Missing or invalid URL parameter");
    
    try {
      return await handleProxyRequest(targetUrl, req);
    } catch (error) {
      return badRequest(`Invalid URL: ${error.message}`);
    }
  }

  // 根路由
  if (url.pathname === "/") {
    return verifyAuth(cookies)
      ? htmlResponse(HTML_TEMPLATES.guidePage)
      : htmlResponse(HTML_TEMPLATES.passwordPage());
  }

  // 404处理
  return notFound();
}

// 辅助函数
function htmlResponse(html: string): Response {
  return new Response(html, {
    headers: { "content-type": "text/html" },
  });
}

function redirectTo(location: string): Response {
  const headers = new Headers();
  headers.set("location", location);
  return new Response(null, { status: 303, headers });
}

function badRequest(message: string): Response {
  return new Response(message, { status: 400 });
}

function notFound(): Response {
  return new Response("Not Found", { status: 404 });
}

// 启动服务器
console.log(`Proxy server running on http://localhost:${CONFIG.PORT}`);
serve(handleRequest, { port: CONFIG.PORT });
