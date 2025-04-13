// proxy_server.ts
import { serve } from "https://deno.land/std@0.152.0/http/server.ts";
import { getCookies, setCookie } from "https://deno.land/std@0.152.0/http/cookie.ts";

// 加载环境配置
async function loadConfig() {
  const config = {
    PASSWORD: Deno.env.get("PROXY_PASSWORD") || "your_secure_password",
    COOKIE_NAME: Deno.env.get("PROXY_COOKIE_NAME") || "proxy_auth",
    PORT: parseInt(Deno.env.get("PROXY_PORT") || "8000"),
    COOKIE_MAX_AGE: parseInt(Deno.env.get("COOKIE_EXPIRE_TIME") || "604800")
  };

  // 确保APIPATH始终以/开头
  let apiPath = Deno.env.get("PROXY_APIPATH") || "/apipath";
  if (!apiPath.startsWith("/")) {
    apiPath = "/" + apiPath;
  }
  config.APIPATH = apiPath;

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
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Proxy Authentication</title>
      <style>
        :root {
          --primary-color: #4361ee;
          --secondary-color: #3a0ca3;
          --error-color: #e63946;
          --background-color: #f8f9fa;
          --card-color: #ffffff;
          --text-color: #212529;
          --shadow: 0 4px 12px rgba(0, 0, 0, 0.08);
        }
        
        * {
          box-sizing: border-box;
          margin: 0;
          padding: 0;
        }
        
        body {
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
          background: var(--background-color);
          color: var(--text-color);
          display: flex;
          justify-content: center;
          align-items: center;
          min-height: 100vh;
          padding: 1rem;
        }
        
        .container {
          background: var(--card-color);
          padding: 2rem;
          border-radius: 12px;
          box-shadow: var(--shadow);
          width: 100%;
          max-width: 360px;
          text-align: center;
          transition: transform 0.2s ease;
        }
        
        .container:hover {
          transform: translateY(-2px);
        }
        
        h1 {
          color: var(--primary-color);
          margin-bottom: 1.5rem;
          font-weight: 600;
        }
        
        form {
          display: flex;
          flex-direction: column;
          gap: 1rem;
        }
        
        input {
          width: 100%;
          padding: 0.75rem 1rem;
          border: 1px solid #dee2e6;
          border-radius: 8px;
          font-size: 16px;
          transition: border-color 0.15s ease;
        }
        
        input:focus {
          border-color: var(--primary-color);
          outline: none;
          box-shadow: 0 0 0 3px rgba(67, 97, 238, 0.15);
        }
        
        button {
          background-color: var(--primary-color);
          color: white;
          padding: 0.75rem 1rem;
          border: none;
          border-radius: 8px;
          cursor: pointer;
          font-size: 16px;
          font-weight: 500;
          transition: background-color 0.15s ease;
        }
        
        button:hover {
          background-color: var(--secondary-color);
        }
        
        .message {
          color: var(--error-color);
          margin-bottom: 1rem;
          padding: 0.75rem;
          background-color: rgba(230, 57, 70, 0.1);
          border-radius: 8px;
          font-size: 14px;
        }
        
        @media (max-width: 480px) {
          .container {
            padding: 1.5rem;
          }
          
          h1 {
            font-size: 1.5rem;
            margin-bottom: 1rem;
          }
        }
      </style>
    </head>
    <body>
      <div class="container">
        <h1>Proxy Authentication</h1>
        ${message ? `<div class="message">${message}</div>` : ""}
        <form method="POST" action="/auth">
          <input type="password" name="password" placeholder="Enter password" required>
          <button type="submit">Access Proxy</button>
        </form>
      </div>
    </body>
    </html>
  `,

  guidePage: `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Proxy Guide</title>
      <style>
        :root {
          --primary-color: #4361ee;
          --secondary-color: #3a0ca3;
          --accent-color: #4895ef;
          --background-color: #f8f9fa;
          --card-color: #ffffff;
          --text-color: #212529;
          --light-text: #6c757d;
          --shadow: 0 4px 12px rgba(0, 0, 0, 0.08);
        }
        
        * {
          box-sizing: border-box;
          margin: 0;
          padding: 0;
        }
        
        body {
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
          background: var(--background-color);
          color: var(--text-color);
          display: flex;
          justify-content: center;
          align-items: center;
          min-height: 100vh;
          padding: 1rem;
        }
        
        .container {
          background: var(--card-color);
          padding: 2rem;
          border-radius: 12px;
          box-shadow: var(--shadow);
          width: 100%;
          max-width: 550px;
          text-align: center;
        }
        
        h1 {
          color: var(--primary-color);
          margin-bottom: 1.5rem;
          font-weight: 600;
        }
        
        form {
          display: flex;
          flex-direction: column;
          gap: 1rem;
          margin-bottom: 1.5rem;
        }
        
        .input-group {
          position: relative;
          display: flex;
          border-radius: 8px;
          box-shadow: 0 2px 6px rgba(0, 0, 0, 0.05);
          overflow: hidden;
        }
        
        input {
          flex: 1;
          padding: 0.75rem 1rem;
          border: 1px solid #dee2e6;
          border-right: none;
          border-radius: 8px 0 0 8px;
          font-size: 16px;
        }
        
        input:focus {
          outline: none;
          border-color: var(--primary-color);
        }
        
        button {
          background-color: var(--primary-color);
          color: white;
          padding: 0.75rem 1.25rem;
          border: none;
          border-radius: 0 8px 8px 0;
          cursor: pointer;
          font-size: 16px;
          font-weight: 500;
          transition: background-color 0.15s ease;
          display: flex;
          align-items: center;
        }
        
        button:hover {
          background-color: var(--secondary-color);
        }
        
        .examples {
          background-color: rgba(67, 97, 238, 0.05);
          border-radius: 8px;
          padding: 1.25rem;
          text-align: left;
        }
        
        .examples h2 {
          font-size: 1rem;
          color: var(--accent-color);
          margin-bottom: 0.75rem;
          font-weight: 500;
        }
        
        .examples ul {
          list-style-type: none;
          display: flex;
          flex-direction: column;
          gap: 0.5rem;
        }
        
        .examples li {
          background-color: rgba(67, 97, 238, 0.03);
          padding: 0.5rem 0.75rem;
          border-radius: 4px;
          color: var(--light-text);
          font-family: monospace;
          font-size: 0.9rem;
          cursor: pointer;
          transition: background 0.15s ease;
        }
        
        .examples li:hover {
          background-color: rgba(67, 97, 238, 0.1);
          color: var(--primary-color);
        }
        
        @media (max-width: 600px) {
          .container {
            padding: 1.5rem;
          }
          
          h1 {
            font-size: 1.5rem;
            margin-bottom: 1rem;
          }
          
          .input-group {
            flex-direction: column;
            box-shadow: none;
          }
          
          input {
            border-radius: 8px;
            border-right: 1px solid #dee2e6;
            margin-bottom: 0.5rem;
          }
          
          button {
            border-radius: 8px;
            justify-content: center;
          }
        }
      </style>
    </head>
    <body>
      <div class="container">
        <h1>Web Proxy Service</h1>
        <form id="proxyForm">
          <div class="input-group">
            <input type="url" id="url" name="url" 
                   placeholder="Enter URL to proxy (e.g., https://example.com)" 
                   required autocomplete="off" spellcheck="false">
            <button type="submit">Visit</button>
          </div>
        </form>
        <div class="examples">
          <h2>Example URLs:</h2>
          <ul id="example-urls">
            <li data-url="https://example.com">https://example.com</li>
            <li data-url="https://httpbin.org/get">https://httpbin.org/get</li>
            <li data-url="https://news.ycombinator.com">https://news.ycombinator.com</li>
          </ul>
        </div>
      </div>
      <script>
        document.getElementById('proxyForm').addEventListener('submit', function(e) {
          e.preventDefault();
          const url = document.getElementById('url').value.trim();
          if (url) {
            window.location.href = '/proxy/' + encodeURIComponent(url);
          }
        });
        
        // 点击示例URL
        document.getElementById('example-urls').addEventListener('click', function(e) {
          if (e.target.tagName === 'LI') {
            const url = e.target.getAttribute('data-url');
            document.getElementById('url').value = url;
            document.getElementById('proxyForm').dispatchEvent(new Event('submit'));
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
  setCookie(headers, {
    name: CONFIG.COOKIE_NAME,
    value: CONFIG.PASSWORD,
    path: "/",
    httpOnly: true,
    secure: true, // 提高安全性
    sameSite: "Lax", // 提高安全性
    maxAge: CONFIG.COOKIE_MAX_AGE,
  });
}

// 提取并解码URL路径
function extractAndDecodeUrl(pathname: string, prefix: string): string | null {
  // 确保传入的prefix以/结尾
  const normalizedPrefix = prefix.endsWith("/") ? prefix : prefix + "/";
  
  // 如果pathname不以normalizedPrefix开头，则尝试查找其他可能的前缀格式
  if (!pathname.startsWith(normalizedPrefix)) {
    console.log(`Path ${pathname} doesn't start with expected prefix ${normalizedPrefix}`);
    return null;
  }
  
  const rawUrl = pathname.slice(normalizedPrefix.length);
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

// 重写HTML、CSS、JS内容中的URL
async function rewriteContent(content: string, contentType: string, baseUrl: string, proxyUrl: string): Promise<string> {
  // 获取基本URL信息用于构建绝对URL
  const target = new URL(baseUrl);
  const baseOrigin = target.origin;
  const basePath = target.pathname.split('/').slice(0, -1).join('/') + '/';
  
  // 处理HTML内容
  if (contentType.includes("text/html")) {
    // 替换各种HTML标签中的URL
    return content
      // 处理相对路径：src="assets/img.jpg" 或 href="style.css"
      .replace(/((?:src|href|action|poster)=["'])(?!(?:https?:|data:|javascript:|mailto:|tel:|#|\/\/))([^"']+)(["'])/gi, (match, prefix, url, suffix) => {
        if (url.startsWith('/')) {
          // 根路径: /assets/img.jpg
          return `${prefix}/proxy/${encodeURIComponent(baseOrigin + url)}${suffix}`;
        } else {
          // 相对路径: assets/img.jpg 或 ./assets/img.jpg
          const absoluteUrl = new URL(url.replace(/^\.\//, ''), baseOrigin + basePath).toString();
          return `${prefix}/proxy/${encodeURIComponent(absoluteUrl)}${suffix}`;
        }
      })
      // 处理绝对路径：src="https://example.com/img.jpg" 或 src="//example.com/img.jpg"
      .replace(/((?:src|href|action|poster)=["'])((?:https?:)?\/\/)([^"']+)(["'])/gi, (match, prefix, protocol, url, suffix) => {
        const fullUrl = (protocol === '//' ? 'https:' : '') + protocol + url;
        return `${prefix}/proxy/${encodeURIComponent(fullUrl)}${suffix}`;
      })
      // 处理style属性中的url()
      .replace(/style=["'].*?url\(['"]?(?!data:)([^'")]+)['"]?\).*?["']/gi, (match) => {
        return match.replace(/url\(['"]?(?!data:)([^'")]+)['"]?\)/gi, (urlMatch, url) => {
          if (url.startsWith('http')) {
            return `url(/proxy/${encodeURIComponent(url)})`;
          } else if (url.startsWith('/')) {
            return `url(/proxy/${encodeURIComponent(baseOrigin + url)})`;
          } else {
            const absoluteUrl = new URL(url.replace(/^\.\//, ''), baseOrigin + basePath).toString();
            return `url(/proxy/${encodeURIComponent(absoluteUrl)})`;
          }
        });
      })
      // 修改<base>标签
      .replace(/<base\s+href=["'](?!data:)([^"']+)["']/gi, `<base href="${proxyUrl}"`)
      // 添加meta标记，防止直接加载外部资源
      .replace(/<head>/i, '<head>\n<meta name="referrer" content="no-referrer">');
  }
  
  // 处理CSS内容
  else if (contentType.includes("text/css")) {
    return content.replace(/url\(['"]?(?!data:)([^'")]+)['"]?\)/gi, (match, url) => {
      if (url.startsWith('http')) {
        return `url(/proxy/${encodeURIComponent(url)})`;
      } else if (url.startsWith('/')) {
        return `url(/proxy/${encodeURIComponent(baseOrigin + url)})`;
      } else {
        const absoluteUrl = new URL(url.replace(/^\.\//, ''), baseOrigin + basePath).toString();
        return `url(/proxy/${encodeURIComponent(absoluteUrl)})`;
      }
    });
  }
  
  // 处理JavaScript内容
  else if (contentType.includes("javascript")) {
    // 这里可以添加针对JS的URL重写逻辑
    // 注意：这可能很复杂，因为JS中的URL可能以多种方式出现
    return content;
  }
  
  return content;
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
    
    // 添加referer头，有些网站会检查
    headers.set("referer", targetUrl.origin);
    
    // 添加User-Agent如果没有的话
    if (!headers.has("user-agent")) {
      headers.set("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36");
    }

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
      redirect: "manual", // 手动处理重定向以便我们可以重写Location
    });

    const resHeaders = new Headers(proxyRes.headers);
    
    // 处理重定向
    if ([301, 302, 303, 307, 308].includes(proxyRes.status)) {
      const location = proxyRes.headers.get("location");
      if (location) {
        let newLocation;
        try {
          // 处理绝对URL
          const locationUrl = new URL(location);
          newLocation = `/proxy/${encodeURIComponent(locationUrl.toString())}`;
        } catch {
          // 处理相对URL
          const absoluteUrl = new URL(location, targetUrl).toString();
          newLocation = `/proxy/${encodeURIComponent(absoluteUrl)}`;
        }
        resHeaders.set("location", newLocation);
      }
    }
    
    // 获取响应内容并处理
    const contentType = proxyRes.headers.get("content-type") || "";
    const proxyUrlPrefix = `/proxy/${encodeURIComponent(targetUrl.toString())}`;
    
    // 只处理文本内容
    if (contentType.includes("text/") || contentType.includes("application/javascript") || 
        contentType.includes("application/json") || contentType.includes("application/xml") ||
        contentType.includes("xml") || contentType.includes("html")) {
      try {
        const originalContent = await proxyRes.text();
        const rewrittenContent = await rewriteContent(
          originalContent, 
          contentType, 
          targetUrl.toString(),
          proxyUrlPrefix
        );
        
        return new Response(rewrittenContent, {
          status: proxyRes.status,
          headers: resHeaders,
        });
      } catch (error) {
        console.error("Content rewriting error:", error);
        // 如果处理失败，返回原始响应
        return new Response(proxyRes.body, {
          status: proxyRes.status,
          headers: resHeaders,
        });
      }
    }
    
    // 对于非文本内容，直接返回
    return new Response(proxyRes.body, {
      status: proxyRes.status,
      headers: resHeaders,
    });
  } catch (error) {
    console.error("Proxy error:", error);
    return new Response(`Proxy error: ${error.message}`, { 
      status: 500,
      headers: { "content-type": "text/html" }
    });
  }
}

// 主请求路由器
async function handleRequest(req: Request): Promise<Response> {
  const url = new URL(req.url);
  const cookies = getCookies(req.headers);

  // 打印请求信息以便调试
  console.log(`Request: ${req.method} ${url.pathname}`);

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
    // 不检查Cookie认证，用于API直接访问
    let targetUrlPath = url.pathname;
    
    // 如果路径中没有正确的API路径分隔符，尝试修复
    if (!targetUrlPath.startsWith(CONFIG.APIPATH + "/")) {
      if (targetUrlPath === CONFIG.APIPATH) {
        return badRequest("API路径需要以目标URL结尾。例如: " + CONFIG.APIPATH + "/https://example.com");
      }
      
      // 修复没有分隔符/的情况
      const fixedPath = CONFIG.APIPATH + "/" + targetUrlPath.substring(CONFIG.APIPATH.length);
      targetUrlPath = fixedPath;
    }
    
    const targetUrl = extractAndDecodeUrl(targetUrlPath, CONFIG.APIPATH);
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

  // 健康检查路由
  if (url.pathname === "/health") {
    return new Response(JSON.stringify({ status: "ok", timestamp: new Date().toISOString() }), {
      headers: { "content-type": "application/json" }
    });
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
    headers: { "content-type": "text/html; charset=utf-8" },
  });
}

function redirectTo(location: string): Response {
  const headers = new Headers();
  headers.set("location", location);
  return new Response(null, { status: 303, headers });
}

function badRequest(message: string): Response {
  return new Response(`
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Error</title>
      <style>
        body { font-family: system-ui, sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; background: #f8f9fa; }
        .error { max-width: 500px; padding: 2rem; background: white; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.08); text-align: center; }
        h1 { color: #e63946; margin-top: 0; }
        p { color: #495057; line-height: 1.6; }
        a { color: #4361ee; text-decoration: none; margin-top: 1rem; display: inline-block; }
        a:hover { text-decoration: underline; }
      </style>
    </head>
    <body>
      <div class="error">
        <h1>Error</h1>
        <p>${message}</p>
        <a href="/">Return to Home</a>
      </div>
    </body>
    </html>
  `, { 
    status: 400, 
    headers: { "content-type": "text/html; charset=utf-8" } 
  });
}

function notFound(): Response {
  return new Response(`
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Not Found</title>
      <style>
        body { font-family: system-ui, sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; background: #f8f9fa; }
        .error { max-width: 500px; padding: 2rem; background: white; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.08); text-align: center; }
        h1 { color: #e63946; margin-top: 0; }
        p { color: #495057; line-height: 1.6; }
        a { color: #4361ee; text-decoration: none; margin-top: 1rem; display: inline-block; }
        a:hover { text-decoration: underline; }
      </style>
    </head>
    <body>
      <div class="error">
        <h1>404 Not Found</h1>
        <p>The page you are looking for does not exist.</p>
        <a href="/">Return to Home</a>
      </div>
    </body>
    </html>
  `, { 
    status: 404, 
    headers: { "content-type": "text/html; charset=utf-8" } 
  });
}

// 启动服务器
console.log(`Proxy server running on http://localhost:${CONFIG.PORT}`);
serve(handleRequest, { port: CONFIG.PORT });
