import assert from 'node:assert/strict'
import { resolve } from 'node:path'

const root = resolve(import.meta.dirname, '..')
const { CliMySqlManager, mysqlResourceNames } = await import(new URL('../src/VulnLab/dist/mysql.js', import.meta.url))

const calls = []
const config = {
  host: '127.0.0.1',
  port: 3307,
  adminUser: 'fixture-db-admin',
  adminPassword: 'admin-secret',
  appHost: '127.0.0.1',
  mysqlBinary: 'mysql-fixture',
}
const manager = new CliMySqlManager({
  passwordBytes: size => new Uint8Array(size).fill(65),
  execFileImpl: async (file, args, options) => {
    calls.push({ file, args, options })
    return { stdout: '1\n', stderr: '' }
  },
})

const resource = await manager.provision({ labSlug: 'dvwa', instanceId: 'instance-123', config })
const names = mysqlResourceNames('dvwa', 'instance-123')
assert.equal(resource.database, names.database)
assert.equal(resource.user, names.user)
assert.equal(Buffer.from(resource.password, 'base64').length > 0, true)
assert.match(calls[0].args.at(-1), /CREATE DATABASE/)
assert.match(calls[0].args.at(-1), /GRANT ALL PRIVILEGES ON/)
assert.equal(calls[0].options.env.MYSQL_PWD, config.adminPassword)
assert.equal(calls[0].args.some(value => value.includes(config.adminPassword)), false)

await manager.verify(resource)
await manager.destroy(resource)
await manager.destroyForInstance({ labSlug: 'dvwa', instanceId: 'instance-123', config })
assert.equal(calls.length, 4)
assert.ok(calls.at(-1).args.at(-1).includes(`DROP DATABASE IF EXISTS \`${names.database}\``))
assert.equal(calls.at(-1).options.env.MYSQL_PWD, config.adminPassword)

console.log('VulnLab MySQL manager test passed: isolated names, env-only passwords, provision, verify and cleanup.')
