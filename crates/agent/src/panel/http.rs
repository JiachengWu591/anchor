//! 面板用的最小 HTTP/1.1：只在 127.0.0.1 上给本机浏览器用，一次请求一个连接。
//! 请求头最多 16 KB，请求体最多 8 KB；超出就拒绝。

use std::io::{Read, Write};

const MAX_HEAD: usize = 16 * 1024;
pub const MAX_BODY: usize = 8 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub struct Request {
    pub method: String,
    /// 不带查询串的路径
    pub path: String,
    /// 名字已转成小写
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ReadError {
    /// 请求头或请求体太大
    TooLarge,
    /// 不是合法的 HTTP 请求
    Bad,
    /// 连接断了或超时
    Io,
}

/// 解析请求头（不含结尾的空行）。返回请求和 Content-Length。
pub fn parse_head(head: &str) -> Result<(Request, usize), ReadError> {
    let mut lines = head.split("\r\n");
    let mut first = lines.next().ok_or(ReadError::Bad)?.split(' ');
    let (method, target, version) = (first.next(), first.next(), first.next());
    let (Some(method), Some(target), Some(version)) = (method, target, version) else { return Err(ReadError::Bad) };
    if first.next().is_some() || !version.starts_with("HTTP/1.") || !target.starts_with('/') {
        return Err(ReadError::Bad);
    }
    let mut headers = Vec::new();
    for line in lines.filter(|l| !l.is_empty()) {
        let (k, v) = line.split_once(':').ok_or(ReadError::Bad)?;
        headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
    }
    let len = match headers.iter().find(|(k, _)| k == "content-length") {
        Some((_, v)) => v.parse::<usize>().map_err(|_| ReadError::Bad)?,
        None => 0,
    };
    if len > MAX_BODY {
        return Err(ReadError::TooLarge);
    }
    // 分块传输不支持：面板自己的请求从不用它
    if headers.iter().any(|(k, _)| k == "transfer-encoding") {
        return Err(ReadError::Bad);
    }
    let path = target.split(['?', '#']).next().unwrap_or("/").to_string();
    Ok((Request { method: method.to_string(), path, headers, body: Vec::new() }, len))
}

pub fn read_request(stream: &mut impl Read) -> Result<Request, ReadError> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    let end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i;
        }
        if buf.len() > MAX_HEAD {
            return Err(ReadError::TooLarge);
        }
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return Err(ReadError::Io),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    };
    let head = std::str::from_utf8(&buf[..end]).map_err(|_| ReadError::Bad)?;
    let (mut req, len) = parse_head(head)?;
    let mut body = buf[end + 4..].to_vec();
    while body.len() < len {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return Err(ReadError::Io),
            Ok(n) => body.extend_from_slice(&chunk[..n]),
        }
    }
    body.truncate(len);
    req.body = body;
    Ok(req)
}

pub struct Response {
    pub status: u16,
    pub content_type: &'static str,
    pub body: Vec<u8>,
}

impl Response {
    pub fn json(status: u16, v: &serde_json::Value) -> Self {
        Self { status, content_type: "application/json; charset=utf-8", body: v.to_string().into_bytes() }
    }

    pub fn error(status: u16, message: &str) -> Self {
        Self::json(status, &serde_json::json!({ "error": message }))
    }

    pub fn asset(content_type: &'static str, body: &str) -> Self {
        Self { status: 200, content_type, body: body.as_bytes().to_vec() }
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        503 => "Service Unavailable",
        _ => "Error",
    }
}

/// 页面只许加载自己的脚本和样式、只许连回自己，不许被别的页面嵌进去。
const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; \
                   base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

pub fn head_of(r: &Response) -> String {
    format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\
         X-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nReferrer-Policy: no-referrer\r\n\
         Content-Security-Policy: {CSP}\r\n\r\n",
        r.status,
        reason(r.status),
        r.content_type,
        r.body.len()
    )
}

pub fn write_response(stream: &mut impl Write, r: &Response) {
    let _ = stream.write_all(head_of(r).as_bytes());
    let _ = stream.write_all(&r.body);
    let _ = stream.flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_a_request_with_a_body() {
        let raw = b"POST /api/action?x=1 HTTP/1.1\r\nHost: 127.0.0.1:5000\r\nContent-Type: application/json\r\nContent-Length: 7\r\n\r\n{\"a\":1}extra";
        let req = read_request(&mut &raw[..]).unwrap();
        assert_eq!((req.method.as_str(), req.path.as_str()), ("POST", "/api/action"), "查询串不算路径");
        assert_eq!(req.header("host"), Some("127.0.0.1:5000"), "头的名字不分大小写");
        assert_eq!(req.body, b"{\"a\":1}", "只取 Content-Length 那么多");
    }

    #[test]
    fn rejects_what_it_does_not_understand() {
        let read = |raw: &[u8]| read_request(&mut &raw[..]);
        assert_eq!(read(b"GET / HTTP/1.1\r\n\r\n").unwrap().body, b"");
        assert_eq!(read(b"hello\r\n\r\n"), Err(ReadError::Bad));
        assert_eq!(read(b"GET http://evil/ HTTP/1.1\r\n\r\n"), Err(ReadError::Bad), "只认以 / 开头的路径");
        assert_eq!(read(b"GET / HTTP/1.1\r\nno colon\r\n\r\n"), Err(ReadError::Bad));
        assert_eq!(read(b"POST / HTTP/1.1\r\nContent-Length: 99999\r\n\r\n"), Err(ReadError::TooLarge));
        assert_eq!(read(b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"), Err(ReadError::Bad));
        assert_eq!(read(b"POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nab"), Err(ReadError::Io), "请求体没发完");
        assert_eq!(read(b"GET / HTTP/1.1\r\nHost: x"), Err(ReadError::Io), "请求头没发完");
        let big = [b"GET / HTTP/1.1\r\nX: ".to_vec(), vec![b'a'; MAX_HEAD + 2048]].concat();
        assert_eq!(read(&big), Err(ReadError::TooLarge));
    }

    #[test]
    fn responses_carry_the_security_headers() {
        let head = head_of(&Response::error(401, "x"));
        assert!(head.starts_with("HTTP/1.1 401 Unauthorized\r\n"), "{head}");
        for h in ["Cache-Control: no-store", "X-Frame-Options: DENY", "frame-ancestors 'none'", "script-src 'self'", "Connection: close"] {
            assert!(head.contains(h), "缺少 {h}");
        }
        assert!(head.ends_with("\r\n\r\n"));
    }
}
