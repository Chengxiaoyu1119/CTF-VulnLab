export class OaSeedError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'OaSeedError'
  }
}

export const adaptOaSeed = (source: string) => {
  const database = /^CREATE DATABASE IF NOT EXISTS `?oa_system`? DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;\s*$/mi
  const useDatabase = /^USE\s+`?oa_system`?;\s*$/mi
  if (!database.test(source) || !useDatabase.test(source)) throw new OaSeedError('OA 初始化脚本结构不符合已验证版本。')
  const adapted = source.replace(database, '').replace(useDatabase, '')
  if (/^\s*(?:CREATE DATABASE|USE\s+`?oa_system`?)\b/im.test(adapted)) throw new OaSeedError('OA 适配脚本仍包含固定数据库选择语句。')
  return adapted
}
