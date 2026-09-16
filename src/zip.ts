import { Unzip, UnzipInflate } from 'fflate'

export interface ZipEntry {
  name: string
  bytes: Uint8Array
}

const joinChunks = (chunks: Uint8Array[], total: number) => {
  if (chunks.length === 1 && chunks[0]?.byteLength === total) return chunks[0]
  const output = new Uint8Array(total)
  let offset = 0
  for (const chunk of chunks) {
    output.set(chunk, offset)
    offset += chunk.byteLength
  }
  return output
}

export const readZipEntries = async (
  source: Uint8Array | AsyncIterable<Uint8Array>,
  limits: { maxFiles: number; maxBytes: number },
): Promise<ZipEntry[]> => {
  const entries: { name: string; directory: boolean; chunks: Uint8Array[]; bytes: number }[] = []
  let fileCount = 0
  let totalBytes = 0
  const unzip = new Unzip(file => {
    const directory = file.name.endsWith('/')
    const entry = { name: file.name, directory, chunks: [] as Uint8Array[], bytes: 0 }
    entries.push(entry)
    if (!directory && ++fileCount > limits.maxFiles) throw new Error('ZIP 文件数量超过限制。')
    file.ondata = (error, chunk) => {
      if (error) throw error
      if (directory || !chunk.byteLength) return
      entry.bytes += chunk.byteLength
      totalBytes += chunk.byteLength
      if (totalBytes > limits.maxBytes) throw new Error('ZIP 解压内容超过大小限制。')
      entry.chunks.push(chunk.slice())
    }
    file.start()
  })
  unzip.register(UnzipInflate)
  try {
    if (source instanceof Uint8Array) {
      const chunkSize = 1024 * 1024
      for (let offset = 0; offset < source.byteLength; offset += chunkSize) {
        unzip.push(source.subarray(offset, Math.min(source.byteLength, offset + chunkSize)), false)
      }
      unzip.push(new Uint8Array(0), true)
    } else {
      for await (const chunk of source) unzip.push(chunk, false)
      unzip.push(new Uint8Array(0), true)
    }
  } catch (error) {
    throw error instanceof Error ? error : new Error('ZIP 解压失败。')
  }
  return entries.filter(entry => !entry.directory).map(entry => ({ name: entry.name, bytes: joinChunks(entry.chunks, entry.bytes) }))
}
