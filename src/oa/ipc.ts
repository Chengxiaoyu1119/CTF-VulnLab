import type { Readable, Writable } from 'node:stream'
import { randomUUID } from 'node:crypto'

type RpcHandler = (method: string, payload: unknown) => Promise<unknown> | unknown
type RpcMessage = { id?: string; method?: string; payload?: unknown; result?: unknown; error?: string }

export class RpcPeer {
  private readonly pending = new Map<string, { resolve: (value: any) => void; reject: (error: Error) => void; timer: NodeJS.Timeout }>()
  private buffered = ''
  private closed = false

  constructor(private readonly input: Readable, private readonly output: Writable, private readonly handler: RpcHandler, private readonly timeoutMs = 30_000) {
    input.setEncoding('utf8')
    input.on('data', chunk => this.consume(String(chunk)))
    input.on('error', error => this.fail(error))
    input.on('end', () => this.fail(new Error('OA IPC 已关闭。')))
  }

  private consume(chunk: string) {
    this.buffered += chunk
    if (this.buffered.length > 48 * 1024 * 1024) return this.fail(new Error('OA IPC 消息超过 48 MiB。'))
    while (true) {
      const end = this.buffered.indexOf('\n')
      if (end < 0) return
      const line = this.buffered.slice(0, end)
      this.buffered = this.buffered.slice(end + 1)
      if (!line) continue
      let message: RpcMessage
      try { message = JSON.parse(line) as RpcMessage } catch { return this.fail(new Error('OA IPC 消息格式无效。')) }
      if (message.id && !message.method) {
        const pending = this.pending.get(message.id)
        if (!pending) continue
        clearTimeout(pending.timer)
        this.pending.delete(message.id)
        if (message.error) pending.reject(new Error(message.error))
        else pending.resolve(message.result)
        continue
      }
      if (!message.id || !message.method) return this.fail(new Error('OA IPC 请求缺少标识或方法。'))
      void Promise.resolve(this.handler(message.method, message.payload)).then(
        result => this.write({ id: message.id, result }),
        error => this.write({ id: message.id, error: error instanceof Error ? error.message : String(error) }),
      )
    }
  }

  private write(message: RpcMessage) {
    if (this.closed) return
    this.output.write(`${JSON.stringify(message)}\n`)
  }

  call(method: string, payload: unknown): Promise<any> {
    if (this.closed) return Promise.reject(new Error('OA IPC 已关闭。'))
    const id = randomUUID()
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id)
        reject(new Error(`OA IPC 请求超时：${method}`))
      }, this.timeoutMs)
      this.pending.set(id, { resolve, reject, timer })
      this.write({ id, method, payload })
    })
  }

  private fail(error: Error) {
    if (this.closed) return
    this.closed = true
    for (const pending of this.pending.values()) {
      clearTimeout(pending.timer)
      pending.reject(error)
    }
    this.pending.clear()
  }

  close() {
    this.fail(new Error('OA IPC 已关闭。'))
  }
}
