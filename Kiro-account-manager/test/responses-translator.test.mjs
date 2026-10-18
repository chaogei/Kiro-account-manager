import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'
import { pathToFileURL } from 'node:url'
import ts from 'typescript'

const projectRoot = path.resolve(import.meta.dirname, '..')
const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'kam-responses-translator-'))

function transpile(sourcePath, outputName) {
  const source = fs.readFileSync(sourcePath, 'utf8')
  const result = ts.transpileModule(source, {
    compilerOptions: {
      module: ts.ModuleKind.ESNext,
      target: ts.ScriptTarget.ES2022
    }
  })
  const output = result.outputText
    .replace("from 'uuid'", "from './uuid.mjs'")
    .replace("'./kiroApi'", "'./kiroApi.mjs'")
    .replace("'./toolNameRegistry'", "'./toolNameRegistry.mjs'")
  fs.writeFileSync(path.join(tempDir, outputName), output)
}

transpile(path.join(projectRoot, 'src/main/proxy/translator.ts'), 'translator.mjs')
transpile(path.join(projectRoot, 'src/main/proxy/toolNameRegistry.ts'), 'toolNameRegistry.mjs')
fs.writeFileSync(
  path.join(tempDir, 'kiroApi.mjs'),
  'export const mapModelId = model => model\nexport const buildKiroPayload = () => ({})\n'
)
fs.writeFileSync(path.join(tempDir, 'uuid.mjs'), "export const v4 = () => 'test-uuid'\n")

const {
  openAIChatToResponsesResponse,
  rememberResponseConversation,
  responsesToOpenAIChat,
  restorePreviousResponse
} = await import(pathToFileURL(path.join(tempDir, 'translator.mjs')).href)

function chatResponse(message) {
  return {
    id: 'chat_1',
    object: 'chat.completion',
    created: 1,
    model: 'gpt-5.6-sol',
    choices: [{ index: 0, message, finish_reason: message.tool_calls ? 'tool_calls' : 'stop' }],
    usage: { prompt_tokens: 3, completion_tokens: 2, total_tokens: 5 }
  }
}

test('converts flat Responses function tools to Chat Completions tools', () => {
  const request = responsesToOpenAIChat({
    model: 'gpt-5.6-sol',
    input: 'weather?',
    reasoning: { effort: 'high' },
    tools: [
      {
        type: 'function',
        name: 'get_weather',
        description: 'Get weather',
        parameters: { type: 'object', properties: { city: { type: 'string' } } }
      }
    ]
  })

  assert.equal(request.reasoning_effort, 'high')
  assert.deepEqual(request.tools?.[0], {
    type: 'function',
    function: {
      name: 'get_weather',
      description: 'Get weather',
      parameters: { type: 'object', properties: { city: { type: 'string' } } }
    }
  })
})

test('flattens namespace tools and restores namespace on function calls', () => {
  const request = responsesToOpenAIChat({
    model: 'gpt-5.6-sol',
    input: 'list files',
    tools: [
      {
        type: 'namespace',
        name: 'shell',
        tools: [{ type: 'function', name: 'exec', parameters: { type: 'object' } }]
      }
    ]
  })
  const encodedName = request.tools?.[0].function.name
  assert.match(encodedName, /^__kiro_ns_5__shellexec$/)

  const response = openAIChatToResponsesResponse(
    chatResponse({
      role: 'assistant',
      content: null,
      tool_calls: [
        {
          id: 'call_1',
          type: 'function',
          function: { name: encodedName, arguments: '{"cmd":"pwd"}' }
        }
      ]
    })
  )

  assert.equal(response.status, 'completed')
  assert.deepEqual(
    { namespace: response.output[0].namespace, name: response.output[0].name },
    { namespace: 'shell', name: 'exec' }
  )
})

test('restores previous_response_id history for tool result turns', () => {
  const firstRequest = responsesToOpenAIChat({
    model: 'gpt-5.6-sol',
    input: 'weather?',
    tools: [{ type: 'function', name: 'get_weather', parameters: { type: 'object' } }]
  })
  rememberResponseConversation(
    'resp_previous',
    firstRequest,
    chatResponse({
      role: 'assistant',
      content: null,
      tool_calls: [
        {
          id: 'call_weather',
          type: 'function',
          function: { name: 'get_weather', arguments: '{"city":"Shanghai"}' }
        }
      ]
    })
  )

  const continuation = responsesToOpenAIChat({
    model: 'gpt-5.6-sol',
    previous_response_id: 'resp_previous',
    input: [{ type: 'function_call_output', call_id: 'call_weather', output: 'Sunny, 30 C' }]
  })
  const restored = restorePreviousResponse(continuation, 'resp_previous')

  assert.deepEqual(
    restored.messages.map((message) => message.role),
    ['user', 'assistant', 'tool']
  )
  assert.equal(restored.messages[2].content, 'Sunny, 30 C')
  assert.equal(restored.tools?.[0].function.name, 'get_weather')
})

test('omits OpenAI-hosted tools that Kiro cannot execute', () => {
  const request = responsesToOpenAIChat({
    model: 'gpt-5.6-sol',
    input: 'hello',
    tools: [{ type: 'web_search' }]
  })
  assert.deepEqual(request.tools, [])
})
