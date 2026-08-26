import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { resolve } from 'node:path'

const root = resolve(import.meta.dirname, '..')
const read = path => readFile(resolve(root, path), 'utf8')
const installer = await read('operations/deploy/vulnlab/native/install.sh')
const service = await read('operations/deploy/vulnlab/native/vulnlab.service')
const environment = await read('operations/deploy/vulnlab/native/.env.example')
const deploymentReadme = await read('operations/deploy/vulnlab/native/README.zh-CN.md')

assert.match(installer, /NODE_VERSION="22\.23\.1"/)
assert.match(installer, /NODE_URL="https:\/\/nodejs\.org\/dist\/v\$\{NODE_VERSION\}\/node-v\$\{NODE_VERSION\}-linux-x64\.tar\.xz"/)
assert.match(installer, /NODE_SHA256="9749e988f437343b7fa832c69ded82a312e41a03116d766797ac14f6f9eee578"/)
assert.match(installer, /NODE_ROOT="\$\{DATA_DIR\}\/runtime\/toolchains\/node/)
assert.match(installer, /tar -xJf "\$\{archive\}" -C "\$\{staging\}"/)
assert.match(installer, /"\$\{NODE_NPM\}" ci/)
assert.match(installer, /"\$\{NODE_NPM\}" run build/)
assert.match(installer, /"\$\{NODE_NPM\}" prune --omit=dev/)
assert.match(installer, /__VULNLAB_APP_DIR__/)
assert.match(installer, /__VULNLAB_DATA_DIR__/)
assert.match(installer, /systemctl enable --now "\$\{SERVICE_NAME\}"/)
assert.doesNotMatch(installer, /Node\.js 22 or newer was not found on PATH/)

assert.match(service, /WorkingDirectory=__VULNLAB_APP_DIR__/)
assert.match(service, /Environment=PATH=__VULNLAB_NODE_DIR__:\/usr\/local\/sbin/)
assert.match(service, /ExecStart=__VULNLAB_NODE_BIN__ __VULNLAB_APP_DIR__\/dist\/server\.js/)
assert.match(service, /ReadWritePaths=__VULNLAB_DATA_DIR__/)
assert.doesNotMatch(service, /ExecStart=\/usr\/bin\/node/)

assert.match(environment, /VULNLAB_DATA_DIR=\/opt\/vulnlab\/data/)
assert.match(environment, /Node\.js 22\.23\.1/)
assert.match(deploymentReadme, /服务单元直接调用项目内 Node\.js/)
assert.match(deploymentReadme, /项目内 MariaDB/)

console.log('VulnLab native deployment check passed: project-local Node.js bootstrap, service paths, and deployment contract.')
