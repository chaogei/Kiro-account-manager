// Proton 邮箱「借壳官方网页」取码（轻量版，借鉴 ElectronMail 思路）
//
// 原理：ProtonMail 是 E2E 加密、无官方 IMAP/SMTP/公开 API。本模块在主进程起一个
// 带持久化 session 的隐藏 BrowserWindow 加载官方网页 mail.proton.me，由官方网页自己
// 完成 SRP 登录 + PGP 解密；我们只通过 webContents.executeJavaScript 读取「已解密的 DOM」
// 提取 6 位验证码。不劫持 webpack 内部模块、不碰 PGP，仅依赖少量 DOM 选择器。
//
// 登录态：首次需用户在弹出的窗口里手动登录一次（含 hCaptcha/2FA），之后通过
// partition='persist:proton' 持久化复用，无需重复登录。这正是 ElectronMail 的做法。
//
// 多地址「匿名」：配合 Proton catch-all 自定义域名 / SimpleLogin 别名，一个收件箱可收
// 无限个 prefix@yourdomain 的验证码邮件。
//
// WARN: 标注「Proton DOM 依赖点」的选择器随 Proton 改版可能失效，届时只需更新本文件。

import { BrowserWindow, session, type Session } from 'electron'

const PARTITION = 'persist:proton'
// 真实 Chrome UA，去掉 Electron 标识，降低被 Proton 风控/拒绝的概率
const CHROME_UA =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36'
// 验证码邮件一般落 inbox；如需覆盖垃圾箱可改为 all-mail
const PROTON_INBOX_URL = 'https://mail.proton.me/u/0/inbox'

let win: BrowserWindow | null = null

export type ProtonLogger = (msg: string) => void

/**
 * 解析 Proton 窗口应使用的代理：优先显式传入，否则用「设置里的全局代理」
 * （设置页经 set-proxy 写入 process.env.HTTPS_PROXY，见 main/index.ts applyProxySettings）。
 * 注意：这里刻意用应用全局代理，而非注册代理池——代理池是逐账号轮换的临时出口，
 * 不适合常驻、需要稳定登录态的取码窗口。
 */
function resolveSettingsProxy(explicit?: string): string {
  const e = (explicit || '').trim()
  if (e) return e
  return (
    process.env.HTTPS_PROXY ||
    process.env.https_proxy ||
    process.env.HTTP_PROXY ||
    process.env.http_proxy ||
    ''
  ).trim()
}

function applyProxy(sess: Session, proxy?: string): Promise<void> {
  const resolved = resolveSettingsProxy(proxy)
  if (resolved) {
    console.log(`[Proton] 走设置代理: ${resolved.replace(/:[^:@/]+@/, ':***@')}`)
    return sess.setProxy({ proxyRules: resolved })
  }
  // 设置里未配代理 → 跟随系统代理（Proton 在受限网络下通常需要代理才能访问）
  console.log('[Proton] 设置未配代理，跟随系统代理')
  return sess.setProxy({ mode: 'system' })
}

/** 懒创建（或复用）Proton 窗口。show=true 时显示并聚焦，便于用户手动登录 */
async function ensureWindow(show: boolean, proxy?: string): Promise<BrowserWindow> {
  const sess = session.fromPartition(PARTITION)
  // 每次都按「设置里的代理」刷新 session 代理：设置变更后下次登录/取码即生效（窗口复用也更新）
  await applyProxy(sess, proxy)

  if (win && !win.isDestroyed()) {
    if (show) {
      win.show()
      win.focus()
    }
    return win
  }

  win = new BrowserWindow({
    width: 1024,
    height: 800,
    show,
    title: 'Proton Mail',
    autoHideMenuBar: true,
    webPreferences: {
      partition: PARTITION,
      // 后台隐藏时不节流定时器/网络，保证 Proton 仍能实时收新邮件
      backgroundThrottling: false,
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true
    }
  })

  win.webContents.setUserAgent(CHROME_UA)
  // 站内导航（登录跳转等）保持在本窗口；其它外链交给系统浏览器
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (/proton\.me/i.test(url)) return { action: 'allow' }
    return { action: 'deny' }
  })

  const closed = (): void => {
    win = null
  }
  win.on('closed', closed)

  await loadAndWait(win, PROTON_INBOX_URL)
  return win
}

/** 加载 URL 并等待页面 dom-ready（带超时兜底） */
function loadAndWait(w: BrowserWindow, url: string, timeoutMs = 30000): Promise<void> {
  return new Promise((resolve) => {
    let done = false
    const finish = (): void => {
      if (done) return
      done = true
      w.webContents.removeListener('dom-ready', finish)
      resolve()
    }
    w.webContents.once('dom-ready', finish)
    w.loadURL(url).catch(() => finish())
    setTimeout(finish, timeoutMs)
  })
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms))
}

/** 通过当前 URL + DOM 判断是否已登录 Proton Mail */
async function checkLoggedIn(w: BrowserWindow): Promise<boolean> {
  const url = w.webContents.getURL()
  // 未登录会跳到 account.proton.me 的 login/authorize 页
  if (/account\.proton\.me/i.test(url) || /\/(login|authorize|switch)/i.test(url)) return false
  if (!/mail\.proton\.me\/u\//i.test(url)) return false
  // DOM 兜底确认：已登录时存在邮件列表容器，登录页存在密码输入框
  try {
    const ok = await w.webContents.executeJavaScript(
      `(() => {
        if (document.querySelector('input[type="password"], #password')) return false
        const sels = ['[data-testid="message-list"]','.items-column-list','[data-shortcut-target="item-container"]','main [role="main"]']
        return sels.some(s => document.querySelector(s)) || /\\/u\\//.test(location.pathname)
      })()`,
      false
    )
    return Boolean(ok)
  } catch {
    return /mail\.proton\.me\/u\//i.test(url)
  }
}

/** 打开 Proton 登录窗口（显示），返回当前登录态。用户在窗口内手动完成登录 */
export async function openProtonLogin(
  proxy?: string
): Promise<{ success: boolean; loggedIn: boolean; error?: string }> {
  try {
    const w = await ensureWindow(true, proxy)
    // 给页面一点时间完成 Proton 的自动跳转（已登录直达 inbox / 未登录跳 login）
    await sleep(1200)
    const loggedIn = await checkLoggedIn(w)
    return { success: true, loggedIn }
  } catch (err) {
    return { success: false, loggedIn: false, error: err instanceof Error ? err.message : String(err) }
  }
}

/**
 * 尝试从 Proton 页面 DOM 读取当前登录的邮箱地址。
 * 多选择器兜底：settings 页 account 区域 > 页面内可见邮箱 > 未找到返回 undefined。
 */
async function readLoggedInEmail(w: BrowserWindow): Promise<string | undefined> {
  try {
    const email = await w.webContents.executeJavaScript(
      `(() => {
        // 1. 设置页 account 区域的邮箱显示
        const accountSels = [
          '[data-testid="account-address"]',
          '[class*="accountEmail"]',
          '[class*="account-email"]',
          '.settings-account-address',
        ];
        for (const s of accountSels) {
          const el = document.querySelector(s);
          if (el) {
            const t = (el.innerText || el.textContent || '').trim();
            if (t.includes('@')) return t.split(/\\s+/).find(w => w.includes('@')) || '';
          }
        }
        // 2. 页面中可见的邮箱地址文本（用户头像旁 / 用户名下拉等）
        const userArea = document.querySelector(
          '[class*="user-menu"], [class*="UserMenu"], [data-testid="sidebar-account"]'
        );
        if (userArea) {
          const text = (userArea as HTMLElement).innerText || '';
          const m = text.match(/[\\w.+-]+@[\\w.-]+\\.[a-z]{2,}/i);
          if (m) return m[0];
        }
        return '';
      })()`,
      false
    )
    return email || undefined
  } catch {
    return undefined
  }
}

/** 查询当前 Proton 登录态（不弹窗：窗口不存在则后台静默创建检测） */
export async function getProtonLoginStatus(
  proxy?: string,
  expectedEmail?: string
): Promise<{ loggedIn: boolean; currentEmail?: string; emailMatch?: boolean }> {
  try {
    const w = await ensureWindow(false, proxy)
    await sleep(600)
    const loggedIn = await checkLoggedIn(w)
    if (!loggedIn) return { loggedIn: false }

    const currentEmail = await readLoggedInEmail(w)

    // 如果传了 expectedEmail，做母邮箱一致性比较（两边都去点 + 小写）
    let emailMatch: boolean | undefined
    if (expectedEmail && currentEmail) {
      const normalize = (e: string) => {
        const [local, ...domainParts] = e.toLowerCase().split('@')
        return `${local.replace(/\\./g, '')}@${domainParts.join('@')}`
      }
      emailMatch = normalize(currentEmail) === normalize(expectedEmail)
    }

    return { loggedIn: true, currentEmail, emailMatch }
  } catch {
    return { loggedIn: false }
  }
}

/** 关闭 Proton 窗口（保留持久化 session，下次免登录） */
export function closeProtonWindow(): void {
  if (win && !win.isDestroyed()) win.destroy()
  win = null
}

// ===== 取码 =====

interface ScanResult {
  code: string
  from: 'body' | 'body-nocode' | 'wrong-recipient' | 'none' | 'error'
  matched: boolean
  aws?: boolean
  snippet?: string
  err?: string
}

/**
 * 在已解密的收件箱中查找「发给当前注册地址」那封 AWS 验证码邮件的验证码。
 * 三重定位（鲁棒优先）：
 *   1) 发件人筛选：只看发件人为 no-reply@signin.aws 的邮件，排除「Response Required」等非验证码 AWS 邮件；
 *   2) 读前两封：验证码邮件有时不是最新一封（会被其它邮件挤后），故对候选最多点开两封；
 *   3) 收件人精确匹配：用邮件头收件人原样带点地址区分同母号不同点号变体的旧码。
 * 收件人读不到时，因发件人已确认是 AWS 验证码邮件，退化为信任有码的那封。
 * @param address 当前注册使用的收件地址（点号变体，原样含点）
 */
function buildScanScript(address: string): string {
  // 点号归一化：Proton 邮箱忽略 local-part 中的点号，DOM 读到的收件人是去点的
  // e.g. "Mi.meKasu.ga05@proton.me" → "mikasuga05@proton.me"
  const [local, domain] = address.trim().toLowerCase().split('@')
  const addrFull = JSON.stringify(local.replace(/\./g, '') + '@' + domain)
  return `(async () => {
    const addrFull = ${addrFull};
    const extractCode = (t) => { const m = (t||'').match(/\\b\\d{6}\\b/g); return m ? m[m.length-1] : ''; };
    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
    const fire = (el, type) => el.dispatchEvent(new MouseEvent(type, { bubbles: true, cancelable: true, view: window }));
    // 读取当前打开邮件的收件人地址集合（Proton DOM 依赖点：mailto / recipient-label / recipients:item-）
    const readRecipients = () => {
      const set = new Set();
      document.querySelectorAll('a[href^="mailto:"]').forEach((a) => {
        const m = (a.getAttribute('href') || '').replace(/^mailto:/i, '').trim().toLowerCase();
        if (m.indexOf('@') > 0) set.add(m);
      });
      document.querySelectorAll('[data-testid="recipient-label"], bdi.message-recipient-item-label').forEach((el) => {
        const t = (el.innerText || '').trim().toLowerCase();
        if (t.indexOf('@') > 0) set.add(t);
      });
      document.querySelectorAll('[data-testid^="recipients:item-"]').forEach((el) => {
        const t = (el.getAttribute('data-testid') || '').replace('recipients:item-', '').trim().toLowerCase();
        if (t.indexOf('@') > 0) set.add(t);
      });
      return set;
    };
    // 列表项发件人地址（Proton DOM 依赖点）：AWS 验证码邮件发件人固定为 no-reply@signin.aws，
    // 用它精确筛掉同为 AWS 的非验证码邮件（如「Response Required: Your Kiro Account」，
    // 那封收件人也是当前地址，仅靠收件人校验会误判「匹配但无码」而卡住）。
    const SENDER = 'no-reply@signin.aws';
    const senderOf = (it) => {
      const el = it.querySelector('[data-testid="message-column:sender-address"]');
      return el ? (el.getAttribute('title') || el.innerText || '').trim().toLowerCase() : '';
    };
    // 打开某封邮件：避开行内星标 button / 复选框 input，否则只会切换星标而打不开邮件
    const openItem = (it) => {
      let target = it.querySelector('[data-testid="message-column:subject"]')
        || it.querySelector('[data-testid^="message-row"]')
        || it.querySelector('.item-subject-wrapper, .subject, span[role="heading"]');
      if (!target) {
        const cand = Array.from(it.querySelectorAll('span, div'))
          .filter((el) => !el.closest('button') && !el.querySelector('button, input') && (el.innerText || '').trim().length > 8);
        target = cand[0] || it;
      }
      fire(target, 'mousedown'); fire(target, 'mouseup'); fire(target, 'click');
    };
    // 读正文（Proton 正文渲染在 iframe 内，优先读 iframe）
    const readBody = () => {
      let body = '';
      const ifr = document.querySelector('iframe[data-testid="content-iframe"], iframe[title], iframe');
      if (ifr) { try { body = (ifr.contentDocument && ifr.contentDocument.body) ? (ifr.contentDocument.body.innerText || '') : ''; } catch (e) {} }
      if (!body) {
        const readSels = ['[data-testid="message-content"]','.message-content','[data-testid="message-view"]','main [role="article"]','main'];
        for (const rs of readSels) { const el = document.querySelector(rs); if (el && el.innerText) { body = el.innerText; break; } }
      }
      if (!body) body = document.body.innerText || '';
      return body;
    };
    // Proton DOM 依赖点：邮件列表项候选选择器（多重兜底）
    const listSels = ['[data-testid="message-item"]','[data-shortcut-target="item-container"]','.items-column-list [role="row"]','.item-container-wrapper','.item-container'];
    let items = [];
    for (const s of listSels) { const e = [...document.querySelectorAll(s)]; if (e.length) { items = e; break; } }
    if (!items[0]) return { code: '', from: 'none', matched: false };
    // 优先只看发件人为 AWS 验证码地址的邮件；筛不到时回退看前两封（兜底，防发件人 DOM 改版）
    const awsItems = items.filter((it) => senderOf(it) === SENDER);
    const candidates = (awsItems.length ? awsItems : items).slice(0, 2);
    const results = [];
    for (let i = 0; i < candidates.length; i++) {
      try {
        openItem(candidates[i]);
        // 轮询等渲染就绪（出现 6 位码 / 收件人+正文齐备）即提前继续，省去固定死等 2.2s。
        // 首次稍等 iframe 切到新邮件，之后细粒度轮询；上限 ~2s 与原死等相当但通常 0.5s 内命中。
        let body = '';
        let recipients = new Set();
        for (let t = 0; t < 11; t++) {
          await sleep(t === 0 ? 350 : 170);
          body = readBody();
          recipients = readRecipients();
          if (extractCode(body) || (recipients.size > 0 && body.length > 30)) break;
        }
        const r = {
          i,
          hasRecip: recipients.size > 0,
          match: recipients.has(addrFull),
          code: extractCode(body),
          recipText: Array.from(recipients).join(',').slice(0, 100),
          bodySnip: body.slice(0, 100)
        };
        results.push(r);
        // 早停：收件人精确匹配 + 有码 → 当前注册地址那封的验证码（最高置信）
        if (r.match && r.code) return { code: r.code, from: 'body', matched: true, snippet: 'aws#' + i + ' ' + r.bodySnip };
      } catch (e) {
        results.push({ i, hasRecip: false, match: false, code: '', recipText: '', bodySnip: 'err=' + String(e) });
      }
    }
    // 收件人读不到但有码（发件人已确认是 AWS 验证码邮件，可信）→ 退化采用
    const noRecipCode = results.find((r) => !r.hasRecip && r.code);
    if (noRecipCode) return { code: noRecipCode.code, from: 'body', matched: false, snippet: 'aws#' + noRecipCode.i + ' no-recipients; ' + noRecipCode.bodySnip };
    // 收件人精确匹配但还没读到码（邮件刚到正在渲染）
    const matchNoCode = results.find((r) => r.match && !r.code);
    if (matchNoCode) return { code: '', from: 'body-nocode', matched: true, snippet: 'aws#' + matchNoCode.i + ' ' + matchNoCode.bodySnip };
    // 有码但收件人是别的变体 → 不是当前的，继续等
    const wrongRecip = results.find((r) => r.code && r.hasRecip && !r.match);
    if (wrongRecip) return { code: '', from: 'wrong-recipient', matched: false, snippet: 'aws#' + wrongRecip.i + ' recipients=' + wrongRecip.recipText };
    return { code: '', from: 'body-nocode', matched: false, snippet: 'awsItems=' + awsItems.length + '; ' + results.map((r) => '#' + r.i + (r.code ? '+code' : '-nocode') + ' r=' + (r.recipText || 'none')).join(' | ').slice(0, 170) };
  })()`
}

/**
 * 轮询 Proton 收件箱 DOM 等待验证码。
 * @param address  收件地址（catch-all 下用于区分目标邮件）
 * @param opts.timeoutSec  总超时
 * @param opts.intervalSec 轮询间隔
 * @param opts.signal      注册取消信号
 * @param opts.log         日志回调
 * @param opts.proxy       可选代理
 */
interface WaitProtonOtpOptions {
  timeoutSec: number
  intervalSec: number
  signal?: AbortSignal
  log?: ProtonLogger
  proxy?: string
}

// 单窗口单收件箱：并发取码会互相打架（同时导航/点开同一窗口），故串行化排队。
// 批量并发注册时建议把 Proton 源的并发设为 1；即便设了更高并发，这里也会强制串行取码。
let otpQueue: Promise<unknown> = Promise.resolve()

export function waitProtonOtp(address: string, opts: WaitProtonOtpOptions): Promise<string> {
  const run = otpQueue.then(
    () => runWaitProtonOtp(address, opts),
    () => runWaitProtonOtp(address, opts)
  )
  // 保持队列链不被某次 reject 中断
  otpQueue = run.catch(() => undefined)
  return run
}

async function runWaitProtonOtp(address: string, opts: WaitProtonOtpOptions): Promise<string> {
  const log = opts.log ?? ((): void => {})
  const w = await ensureWindow(false, opts.proxy)

  if (!(await checkLoggedIn(w))) {
    throw new Error('Proton 未登录，请先在「登录 Proton」窗口完成登录')
  }

  // 邮箱一致性检查：如果当前登录的 Proton 账户与注册邮箱不匹配，提前中止
  // 避免在错误的收件箱里轮询 2 分钟才发现收不到码
  {
    const currentEmail = await readLoggedInEmail(w)
    if (currentEmail) {
      const normalize = (e: string) => {
        const [local, ...domainParts] = e.toLowerCase().split('@')
        return `${local.replace(/\\./g, '')}@${domainParts.join('@')}`
      }
      if (normalize(currentEmail) !== normalize(address)) {
        throw new Error(
          `Proton 登录账户 (${currentEmail}) 与注册邮箱 (${address}) 不匹配，请退出 Proton 重新登录正确的账户`
        )
      }
    }
  }

  // 取码前导航到 inbox 确保处于最新收件箱视图
  await loadAndWait(w, PROTON_INBOX_URL)
  await sleep(1500)

  // Proton 取码是「点开邮件读本地 DOM」，无网络 API 限流顾虑，且点开本身已自带耗时，
  // 故轮询间隔不沿用网络型邮箱的 intervalSec(默认3s)，钳到 ≤1s 让验证码到达后更快被读到。
  const pollMs = Math.min(Math.max(opts.intervalSec * 1000, 250), 1000)
  const maxRetries = Math.max(1, Math.floor((opts.timeoutSec * 1000) / pollMs))
  const script = buildScanScript(address)

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    if (opts.signal?.aborted) throw new Error('注册已取消')

    // 每 ~20 轮 reload 一次兜底（防止 SPA 长时间不刷新漏收）
    if (attempt > 1 && attempt % 20 === 0) {
      await loadAndWait(w, PROTON_INBOX_URL)
      await sleep(1200)
    }

    try {
      const res = (await w.webContents.executeJavaScript(script, true)) as ScanResult
      if (res && res.code && res.from === 'body') {
        // 收件人精确匹配当前注册地址（或收件人读不到时正文去点匹配）+ 读到 6 位码 → 当前邮件的验证码
        log(`[Proton] 验证码: ${res.code} (${res.matched ? '收件人精确匹配' : '正文去点兜底匹配'})`)
        return res.code
      } else if (res && res.from === 'wrong-recipient') {
        if (attempt % 8 === 0) log(`[Proton] 最新邮件收件人非当前地址，等待当前验证码... ${res.snippet || ''}`)
      } else if (res && res.from === 'body-nocode') {
        if (attempt % 8 === 0) log(`[Proton] ${res.matched ? '已打开当前邮件但未提取到码' : '暂无匹配邮件'}: ${res.snippet || ''}`)
      } else if (res && res.from === 'error') {
        if (attempt % 10 === 0) log(`[Proton] 取码脚本异常: ${res.err}`)
      }
    } catch (err) {
      if (attempt % 10 === 0) log(`[Proton] [${attempt}/${maxRetries}] 读取失败: ${err}`)
    }

    if (attempt % 10 === 0) log(`[Proton] [${attempt}/${maxRetries}] 暂无验证码...`)
    await sleep(pollMs)
  }

  throw new Error(`等待验证码超时 (${opts.timeoutSec}s)`)
}
