// 本地中继代理链（Proxy Chaining）
//
// 背景：部分目标代理（如 bestproxy）要求「来源 IP 必须为非大陆」，大陆 IP 既不能加白名单也会被拒（610）。
// 底层 TLS 引擎只支持单层代理，因此这里在本机起一个本地中继，把链路串成：
//   本机 → 本地中继 → 上游中转(非大陆, upstream) → 目标代理(target, bestproxy) → 目标站点
// 这样目标代理看到的来源 IP 是上游中转的出口（非大陆），即可通过。
//
// 仅实现 HTTP CONNECT 入站（注册全程为 https，足够）；上游中转支持 http / socks5(4)。

import net from 'net'
import { SocksClient } from 'socks'

interface ParsedChainProxy {
  protocol: 'http' | 'https' | 'socks5' | 'socks4'
  host: string
  port: number
  username?: string
  password?: string
}

function parseChainProxy(url: string): ParsedChainProxy | null {
  try {
    const u = new URL(url)
    const proto = u.protocol.replace(':', '').toLowerCase()
    let protocol: ParsedChainProxy['protocol']
    if (proto === 'http') protocol = 'http'
    else if (proto === 'https') protocol = 'https'
    else if (proto === 'socks5' || proto === 'socks5h' || proto === 'socks') protocol = 'socks5'
    else if (proto === 'socks4' || proto === 'socks4a') protocol = 'socks4'
    else return null
    const port = Number(u.port) || (protocol.startsWith('socks') ? 1080 : 8080)
    if (!u.hostname) return null
    return {
      protocol,
      host: u.hostname,
      port,
      username: u.username ? decodeURIComponent(u.username) : undefined,
      password: u.password ? decodeURIComponent(u.password) : undefined
    }
  } catch {
    return null
  }
}

interface ConnectResponse {
  status: number
  statusText: string
  headersRaw: string
  bodySnippet: string
}

export interface ChainDiagnose {
  upstreamReachable: boolean
  upstreamError?: string
  upstreamRtMs?: number
  targetReachable: boolean
  targetError?: string
  targetRtMs?: number
  targetStatus?: number
  targetStatusText?: string
  targetBodySnippet?: string
  endToEndOk?: boolean
  endToEndError?: string
  endToEndRtMs?: number
}

export class ChainProxyRelay {
  private server: net.Server | null = null
  /** 跟踪所有活跃的入站连接，stop() 时强制销毁，避免 server.close() 等 Keep-Alive 超时（~60s）*/
  private sockets = new Set<net.Socket>()
  private readonly upstream: ParsedChainProxy
  private readonly target: ParsedChainProxy
  private readonly log: (m: string) => void
  port = 0

  constructor(upstreamUrl: string, targetUrl: string, log?: (m: string) => void) {
    const up = parseChainProxy(upstreamUrl)
    const tg = parseChainProxy(targetUrl)
    if (!up) throw new Error(`Invalid upstream relay proxy: ${upstreamUrl}`)
    if (!tg) throw new Error(`Invalid target proxy: ${targetUrl}`)
    this.upstream = up
    this.target = tg
    this.log = log || ((): void => {})
  }

  /** 启动本地中继，返回可直接作为代理使用的 http://127.0.0.1:port */
  start(): Promise<string> {
    return new Promise((resolve, reject) => {
      const server = net.createServer((client) => this.handleClient(client))
      server.once('error', reject)
      server.listen(0, '127.0.0.1', () => {
        const addr = server.address()
        if (addr && typeof addr === 'object') {
          this.port = addr.port
          this.server = server
          server.removeListener('error', reject)
          resolve(`http://127.0.0.1:${this.port}`)
        } else {
          reject(new Error('Local relay failed to start: unable to get port'))
        }
      })
    })
  }

  stop(): Promise<void> {
    return new Promise((resolve) => {
      const srv = this.server
      this.server = null
      // 强制销毁所有活跃隧道连接：否则 server.close() 会等 DLL Go http.Transport
      // 的 Keep-Alive 连接自然超时（~60s），导致注册结束后 cleanup 卡住一分钟
      for (const sock of this.sockets) {
        try { sock.destroy() } catch { /* ignore */ }
      }
      this.sockets.clear()
      if (!srv) {
        resolve()
        return
      }
      srv.close(() => resolve())
      // 双保险：500ms 后无论 close 回调是否触发都 resolve
      setTimeout(resolve, 500)
    })
  }

  private handleClient(client: net.Socket): void {
    this.sockets.add(client)
    client.on('close', () => this.sockets.delete(client))
    client.on('error', () => client.destroy())
    client.once('data', (chunk) => {
      const head = chunk.toString('latin1')
      const m = head.match(/^CONNECT\s+([^\s:]+):(\d+)\s+HTTP\/1\.[01]/i)
      if (!m) {
        client.end('HTTP/1.1 405 Method Not Allowed\r\n\r\n')
        return
      }
      const host = m[1]
      const port = Number(m[2])
      this.dialChain(host, port)
        .then((tunnel) => {
          client.write('HTTP/1.1 200 Connection Established\r\n\r\n')
          client.pipe(tunnel)
          tunnel.pipe(client)
          client.on('close', () => tunnel.destroy())
          tunnel.on('close', () => client.destroy())
          tunnel.on('error', () => { client.destroy(); tunnel.destroy() })
        })
        .catch((err: unknown) => {
          this.log(`[ProxyChain] 隧道建立失败: ${err instanceof Error ? err.message : String(err)}`)
          if (!client.destroyed) client.end('HTTP/1.1 502 Bad Gateway\r\n\r\n')
        })
    })
  }

  /** 经上游中转连到目标代理入口，再在该连接上对目标代理做 CONNECT 抵达最终目标 */
  private async dialChain(host: string, port: number): Promise<net.Socket> {
    const sock = await this.connectViaUpstream(this.target.host, this.target.port)
    try {
      const resp = await this.sendConnectRequest(sock, host, port, this.target)
      if (resp.status !== 200) {
        throw new Error(this.formatConnectError('目标代理', resp))
      }
    } catch (err) {
      sock.destroy()
      throw err
    }
    return sock
  }

  private connectViaUpstream(host: string, port: number): Promise<net.Socket> {
    if (this.upstream.protocol === 'socks5' || this.upstream.protocol === 'socks4') {
      return this.connectViaSocks(host, port)
    }
    return this.connectViaHttpUpstream(host, port)
  }

  private connectViaHttpUpstream(host: string, port: number): Promise<net.Socket> {
    return new Promise((resolve, reject) => {
      const sock = net.connect(this.upstream.port, this.upstream.host)
      sock.setTimeout(20000)
      sock.once('timeout', () => { sock.destroy(); reject(new Error('上游中转连接超时')) })
      sock.once('error', reject)
      sock.once('connect', () => {
        sock.setNoDelay(true)
        this.sendConnectRequest(sock, host, port, this.upstream)
          .then((resp) => {
            sock.setTimeout(0)
            if (resp.status === 200) resolve(sock)
            else { sock.destroy(); reject(new Error(this.formatConnectError('上游中转', resp))) }
          })
          .catch((err: Error) => { sock.destroy(); reject(err) })
      })
    })
  }

  private connectViaSocks(host: string, port: number): Promise<net.Socket> {
    return new Promise((resolve, reject) => {
      void SocksClient.createConnection({
        proxy: {
          host: this.upstream.host,
          port: this.upstream.port,
          type: this.upstream.protocol === 'socks4' ? 4 : 5,
          userId: this.upstream.username,
          password: this.upstream.password
        },
        command: 'connect',
        destination: { host, port },
        timeout: 20000
      })
        .then(({ socket }) => {
          // socks 包返回的 socket 默认开启了 30s timeout，会在空闲后触发 'end'，导致我们误判为"被对端关闭"
          socket.setTimeout(0)
          socket.setNoDelay(true)
          socket.setKeepAlive(true, 30000)
          resolve(socket)
        })
        .catch((err: Error) => reject(err))
    })
  }

  /**
   * 通用 CONNECT：发送请求 + 解析响应。
   *
   * 关键容错：
   *   - 部分代理返回错误时只发状态行就 close，**不补 \r\n\r\n**（如 bestproxy 的 610），
   *     旧实现会等空行等到 FIN 触发 'end' 然后误报「代理连接被对端关闭」，错误状态码被丢。
   *     新实现：'end' 事件触发时若 buf 已含状态行，尽力解析；只有空 buf 才报「关闭」。
   *   - 附带常见兼容头（Proxy-Connection / User-Agent），减少代理服务端的策略性拒绝。
   */
  private sendConnectRequest(
    sock: net.Socket,
    host: string,
    port: number,
    auth: ParsedChainProxy
  ): Promise<ConnectResponse> {
    return new Promise((resolve, reject) => {
      const lines = [
        `CONNECT ${host}:${port} HTTP/1.1`,
        `Host: ${host}:${port}`,
        'Proxy-Connection: keep-alive',
        'User-Agent: Mozilla/5.0'
      ]
      if (auth.username) {
        const b64 = Buffer.from(`${auth.username}:${auth.password || ''}`).toString('base64')
        lines.push(`Proxy-Authorization: Basic ${b64}`)
      }
      const req = lines.join('\r\n') + '\r\n\r\n'

      this.readHttpResponse(sock).then(resolve, reject)
      sock.write(req)
    })
  }

  /** 读取 HTTP 响应：直到 \r\n\r\n 完整、或对端关闭/出错时尽力解析。返回结构化结果。 */
  private readHttpResponse(sock: net.Socket): Promise<ConnectResponse> {
    return new Promise((resolve, reject) => {
      let buf = ''
      const cleanup = (): void => {
        sock.removeListener('data', onData)
        sock.removeListener('error', onErr)
        sock.removeListener('end', onEnd)
        sock.removeListener('close', onEnd)
      }
      const parse = (raw: string): ConnectResponse | null => {
        const nlIdx = raw.indexOf('\r\n')
        if (nlIdx < 0) return null
        const statusLine = raw.slice(0, nlIdx)
        const m = statusLine.match(/^HTTP\/1\.[01]\s+(\d{3})\s*(.*)$/)
        if (!m) return null
        const status = Number(m[1])
        const statusText = m[2] || ''
        const sep = raw.indexOf('\r\n\r\n')
        const headersEnd = sep >= 0 ? sep : raw.length
        const headersRaw = raw.slice(nlIdx + 2, headersEnd)
        const bodySnippet = sep >= 0 ? raw.slice(sep + 4, sep + 4 + 200) : ''
        return { status, statusText, headersRaw, bodySnippet }
      }
      const finish = (raw: string, viaClose: boolean): void => {
        cleanup()
        const parsed = parse(raw)
        if (parsed) {
          if (parsed.status === 200 && raw.indexOf('\r\n\r\n') >= 0) {
            const sep = raw.indexOf('\r\n\r\n')
            const rest = raw.slice(sep + 4)
            if (rest.length > 0) sock.unshift(Buffer.from(rest, 'latin1'))
          }
          resolve(parsed)
        } else if (viaClose) {
          reject(new Error(raw ? `代理返回不可解析: ${raw.slice(0, 120)}` : '代理连接被对端关闭（无任何响应）'))
        }
      }
      const onData = (d: Buffer): void => {
        buf += d.toString('latin1')
        const sep = buf.indexOf('\r\n\r\n')
        if (sep >= 0) finish(buf, false)
      }
      const onErr = (err: Error): void => { cleanup(); reject(err) }
      const onEnd = (): void => finish(buf, true)
      sock.on('data', onData)
      sock.once('error', onErr)
      sock.once('end', onEnd)
      sock.once('close', onEnd)
    })
  }

  private formatConnectError(stage: string, resp: ConnectResponse): string {
    const suffix = resp.bodySnippet ? ` body=${resp.bodySnippet.replace(/[\r\n]/g, ' ').slice(0, 120)}` : ''
    return `${stage} CONNECT 失败: HTTP ${resp.status} ${resp.statusText}${suffix}`
  }

  /**
   * 分阶段诊断：
   *   A) 上游中转 TCP 连通
   *   B) 经上游 CONNECT 到目标代理入口
   *   C) 经完整链路 CONNECT 到 testHost:testPort
   * 不依赖本地 server，独立可用；定位问题精确到哪一层。
   */
  async diagnose(testHost = 'www.gstatic.com', testPort = 443): Promise<ChainDiagnose> {
    const result: ChainDiagnose = { upstreamReachable: false, targetReachable: false }
    const t0 = Date.now()
    try {
      await this.tcpProbe(this.upstream.host, this.upstream.port, 8000)
      result.upstreamReachable = true
      result.upstreamRtMs = Date.now() - t0
    } catch (err) {
      result.upstreamError = err instanceof Error ? err.message : String(err)
      return result
    }
    const t1 = Date.now()
    let chainSock: net.Socket | null = null
    try {
      chainSock = await this.connectViaUpstream(this.target.host, this.target.port)
      result.targetReachable = true
      result.targetRtMs = Date.now() - t1
    } catch (err) {
      result.targetError = err instanceof Error ? err.message : String(err)
      return result
    }
    const t2 = Date.now()
    try {
      const resp = await this.sendConnectRequest(chainSock, testHost, testPort, this.target)
      result.targetStatus = resp.status
      result.targetStatusText = resp.statusText
      result.targetBodySnippet = resp.bodySnippet
      result.endToEndOk = resp.status === 200
      result.endToEndRtMs = Date.now() - t2
      if (resp.status !== 200) {
        result.endToEndError = `目标代理拒绝: HTTP ${resp.status} ${resp.statusText}`
      }
    } catch (err) {
      result.endToEndOk = false
      result.endToEndError = err instanceof Error ? err.message : String(err)
    } finally {
      chainSock.destroy()
    }
    return result
  }

  private tcpProbe(host: string, port: number, timeoutMs: number): Promise<void> {
    return new Promise((resolve, reject) => {
      const sock = net.connect(port, host)
      const timer = setTimeout(() => { sock.destroy(); reject(new Error(`TCP 连接超时 ${host}:${port}`)) }, timeoutMs)
      sock.once('connect', () => { clearTimeout(timer); sock.destroy(); resolve() })
      sock.once('error', (err) => { clearTimeout(timer); reject(err) })
    })
  }
}
