package anytls

import (
	"io"
	"net"
	"strconv"
	"time"

	"github.com/xtls/xray-core/common/buf"
)

// decoyBody 是认证失败时伪装网站返回的页面正文。想改成别的内容(或换成你自己的落地页)
// 直接改这里即可——它对任何请求都返回同一页,足以让主动探测看到"一个正常网站"而不是
// "读几字节就断开的代理"。要做到每个路径都像真站需真后端(吃性能),弱机不建议。
var decoyBody = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Welcome</title>
<style>body{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:40px auto;max-width:640px;line-height:1.6;color:#333;padding:0 16px}h1{font-size:1.6rem}</style>
</head>
<body>
<h1>It works!</h1>
<p>This is the default landing page. The site is running normally.</p>
</body>
</html>
`

// serveDecoy 在 anytls 认证失败时把连接伪装成一个普通 HTTP 网站:尽量读走客户端(探测者)
// 发来的请求头,回一个 200 页面,再关闭。目的:避免"读几字节就闷声断开"被主动探测识别为
// 代理。全内置、无外连、无常驻进程,弱机无压力。
func serveDecoy(conn net.Conn, br *buf.BufferedReader) {
	// 像真服务器一样先读走请求(带上限与短超时,防止被吊住)。
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	drainHTTPHeader(br)
	_ = conn.SetReadDeadline(time.Time{})

	resp := "HTTP/1.1 200 OK\r\n" +
		"Server: nginx\r\n" +
		"Date: " + time.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05") + " GMT\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n" +
		"Content-Length: " + strconv.Itoa(len(decoyBody)) + "\r\n" +
		"Connection: close\r\n" +
		"\r\n" + decoyBody

	_ = conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	_, _ = conn.Write([]byte(resp))
	_ = conn.SetWriteDeadline(time.Time{})
}

// drainHTTPHeader 从 r 读到 HTTP 头结束(\r\n\r\n)或达到上限/出错为止,读到的内容丢弃。
// 只为让回落行为更像真服务器(先收完请求头再响应),即便没读到终止符也会返回、照常响应。
func drainHTTPHeader(r io.Reader) {
	b := make([]byte, 1)
	state := 0 // 匹配 \r\n\r\n 的进度
	for i := 0; i < 16384; i++ {
		if _, err := r.Read(b); err != nil {
			return
		}
		c := b[0]
		switch {
		case (state == 0 || state == 2) && c == '\r':
			state++
		case (state == 1 || state == 3) && c == '\n':
			state++
			if state == 4 {
				return
			}
		default:
			state = 0
		}
	}
}
