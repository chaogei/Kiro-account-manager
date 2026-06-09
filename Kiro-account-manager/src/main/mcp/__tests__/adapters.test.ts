import { describe, expect, it } from 'vitest'
import { getMcpAdapterById, readCodexTomlServers } from '../adapters'
import type { ManagedMcpServer } from '../types'

describe('MCP adapters', () => {
  it('converts HTTP MCP servers to Kiro mcp-remote stdio entries', () => {
    const adapter = getMcpAdapterById('kiro')
    expect(adapter).toBeTruthy()

    const server: ManagedMcpServer = {
      name: 'linear',
      transport: 'http',
      url: 'https://mcp.linear.app/mcp',
      headers: {
        Authorization: 'Bearer ${LINEAR_API_KEY}',
        'X-MCP-Name': 'linear'
      },
      env: { LINEAR_API_KEY: '${LINEAR_API_KEY}' },
      createdAt: 1,
      updatedAt: 1
    }

    expect(adapter!.toNative(server)).toEqual({
      command: 'npx',
      args: [
        'mcp-remote',
        'https://mcp.linear.app/mcp',
        '--header',
        'Authorization:Bearer ${LINEAR_API_KEY}',
        '--header',
        'X-MCP-Name:linear'
      ],
      env: { LINEAR_API_KEY: '${LINEAR_API_KEY}' }
    })
  })

  it('allows non-local HTTP MCP servers when converting them for Kiro', () => {
    const adapter = getMcpAdapterById('kiro')!
    const server: ManagedMcpServer = {
      name: 'internal-api',
      transport: 'http',
      url: 'http://mcp.example.test/mcp',
      createdAt: 1,
      updatedAt: 1
    }

    expect(adapter.toNative(server)).toEqual({
      command: 'npx',
      args: ['mcp-remote', 'http://mcp.example.test/mcp', '--allow-http']
    })
  })

  it('does not add allow-http for localhost MCP servers', () => {
    const adapter = getMcpAdapterById('kiro')!
    const server: ManagedMcpServer = {
      name: 'local-api',
      transport: 'http',
      url: 'http://localhost:3000/mcp',
      createdAt: 1,
      updatedAt: 1
    }

    expect(adapter.toNative(server)).toEqual({
      command: 'npx',
      args: ['mcp-remote', 'http://localhost:3000/mcp']
    })
  })

  it('restores Kiro mcp-remote entries as HTTP MCP servers', () => {
    const adapter = getMcpAdapterById('kiro')
    expect(adapter).toBeTruthy()

    const server = adapter!.fromNative('linear', {
      command: 'npx',
      args: [
        'mcp-remote',
        'http://mcp.example.test/mcp',
        '--header',
        'Authorization:Bearer test-token',
        '--header',
        'X-MCP-Name:linear',
        '--allow-http'
      ],
      env: { LINEAR_API_KEY: '${LINEAR_API_KEY}' }
    })

    expect(server).toMatchObject({
      name: 'linear',
      transport: 'http',
      url: 'http://mcp.example.test/mcp',
      headers: {
        Authorization: 'Bearer test-token',
        'X-MCP-Name': 'linear'
      },
      env: { LINEAR_API_KEY: '${LINEAR_API_KEY}' },
      source: 'kiro-settings'
    })
  })

  it('supports existing Kiro entries that use npx -y and a versioned mcp-remote', () => {
    const adapter = getMcpAdapterById('kiro')!

    expect(
      adapter.fromNative('legacy', {
        command: '/usr/local/bin/npx',
        args: ['-y', 'mcp-remote@latest', 'https://mcp.example.test/mcp']
      })
    ).toMatchObject({
      name: 'legacy',
      transport: 'http',
      url: 'https://mcp.example.test/mcp'
    })
  })

  it('keeps Codex env sections attached to their stdio MCP', () => {
    const servers = readCodexTomlServers(`
[mcp_servers.node_repl]
command = "/Applications/Codex.app/Contents/Resources/node_repl"
args = []

[mcp_servers.node_repl.env]
CODEX_HOME = "/Users/test/.codex"
`)

    expect(servers).toEqual({
      node_repl: {
        command: '/Applications/Codex.app/Contents/Resources/node_repl',
        args: [],
        env: { CODEX_HOME: '/Users/test/.codex' }
      }
    })
  })

  it('reads Codex HTTP headers as normal MCP headers', () => {
    const servers = readCodexTomlServers(`
[mcp_servers.remote_api]
url = "http://mcp.example.test/mcp"
http_headers = { Authorization = "Bearer test-token", "X-MCP-Name" = "remote,api" }
`)
    const adapter = getMcpAdapterById('codex')!

    expect(adapter.fromNative('remote_api', servers.remote_api)).toMatchObject({
      name: 'remote_api',
      transport: 'http',
      url: 'http://mcp.example.test/mcp',
      headers: {
        Authorization: 'Bearer test-token',
        'X-MCP-Name': 'remote,api'
      }
    })
  })
})
