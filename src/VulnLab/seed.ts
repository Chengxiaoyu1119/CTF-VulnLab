import type { Difficulty, RuntimeKind, SourceType } from './types.js'

export interface SeedLab {
  slug: string
  title: string
  category: string
  difficulty: Difficulty
  sourceType: SourceType
  sourceUrl: string
  sourceRef: string
  license: string
  runtimeKind: RuntimeKind
  providerId: string
  version: string
  autoInstall: boolean
  summary: string
  tags: string[]
}

export const seedLabs: SeedLab[] = [
  {
    slug: 'dvwa',
    title: 'DVWA',
    category: 'Web',
    difficulty: '入门',
    sourceType: 'git',
    sourceUrl: 'https://github.com/digininja/DVWA',
    sourceRef: 'digininja/DVWA@5d5c76cced604e54462b13723f5c69af58e78748',
    license: 'GPL-3.0',
    runtimeKind: 'native-php',
    providerId: 'native-php',
    version: '5d5c76c',
    autoInstall: false,
    summary: '经典 Web 漏洞练习环境，覆盖常见输入与认证问题。',
    tags: ['PHP', 'Web', '基础'],
  },
  {
    slug: 'pikachu',
    title: 'Pikachu',
    category: 'Web',
    difficulty: '入门',
    sourceType: 'git',
    sourceUrl: 'https://github.com/zhuifengshaonianhanlu/pikachu',
    sourceRef: 'zhuifengshaonianhanlu/pikachu@5e1e8d9d14a3ba61d62f28cf35531c4df4dd24fc',
    license: 'Apache-2.0',
    runtimeKind: 'native-php',
    providerId: 'native-php',
    version: '5e1e8d9',
    autoInstall: false,
    summary: '中文 Web 安全训练平台，按场景练习常见漏洞。',
    tags: ['PHP', 'Web', '中文'],
  },
  {
    slug: 'sqli-labs',
    title: 'SQLi-Labs',
    category: 'Web',
    difficulty: '中等',
    sourceType: 'git',
    sourceUrl: 'https://github.com/Audi-1/sqli-labs',
    sourceRef: 'Audi-1/sqli-labs@e96f21776372c8613a7e565106e62bc01a59355e',
    license: '上游未声明',
    runtimeKind: 'native-php',
    providerId: 'native-php',
    version: 'e96f217',
    autoInstall: false,
    summary: '围绕错误回显、布尔盲注和时间盲注的 SQL 注入练习。',
    tags: ['SQLi', 'PHP', 'MySQL'],
  },
  {
    slug: 'upload-labs',
    title: 'Upload-Labs',
    category: 'Web',
    difficulty: '中等',
    sourceType: 'git',
    sourceUrl: 'https://github.com/c0ny1/upload-labs',
    sourceRef: 'c0ny1/upload-labs@3a0ff865d41d93ea7d57a91e837f084d9d2318e5',
    license: '上游未声明',
    runtimeKind: 'native-php',
    providerId: 'native-php',
    version: '3a0ff86',
    autoInstall: false,
    summary: '文件上传校验链路练习，覆盖多种绕过场景。',
    tags: ['Upload', 'PHP', '文件处理'],
  },
  {
    slug: 'xvwa',
    title: 'XVWA',
    category: 'Web',
    difficulty: '中等',
    sourceType: 'git',
    sourceUrl: 'https://github.com/s4n7h0/xvwa',
    sourceRef: 's4n7h0/xvwa@fb30fa517d288e618b521d252f61107ef6a24797',
    license: 'GPL-3.0',
    runtimeKind: 'native-php',
    providerId: 'native-php',
    version: 'fb30fa5',
    autoInstall: false,
    summary: '覆盖多类 Web 漏洞的 PHP/MySQL 综合练习环境。',
    tags: ['PHP', 'MySQL', 'Web'],
  },
  {
    slug: 'juice-shop',
    title: 'OWASP Juice Shop',
    category: 'Web',
    difficulty: '中等',
    sourceType: 'git',
    sourceUrl: 'https://github.com/juice-shop/juice-shop',
    sourceRef: 'juice-shop/juice-shop@5658473cf8814459bf89000ce373b20ed0b4eb37',
    license: 'MIT',
    runtimeKind: 'native-node',
    providerId: 'native-node',
    version: '20.2.0',
    autoInstall: false,
    summary: '现代 Web 应用安全训练环境，题目覆盖面广。',
    tags: ['OWASP', 'Node.js', 'Web'],
  },
  {
    slug: 'webgoat',
    title: 'OWASP WebGoat',
    category: 'Web',
    difficulty: '中等',
    sourceType: 'git',
    sourceUrl: 'https://github.com/WebGoat/WebGoat',
    sourceRef: 'WebGoat/WebGoat@5357a65e054976cd7d79b81ef3906ded050ed921',
    license: 'GPL-2.0-or-later',
    runtimeKind: 'native-java',
    providerId: 'native-java',
    version: '2023.8',
    autoInstall: false,
    summary: '面向教学的 Web 漏洞课程式训练平台。',
    tags: ['OWASP', 'Java', '课程'],
  },
  {
    slug: 'mutillidae',
    title: 'OWASP Mutillidae II',
    category: 'Web',
    difficulty: '中等',
    sourceType: 'git',
    sourceUrl: 'https://github.com/webpwnized/mutillidae',
    sourceRef: 'webpwnized/mutillidae@84f2c00d9141dbb9e26a448c8288e651e0b5bb04',
    license: 'GPL-3.0',
    runtimeKind: 'native-php',
    providerId: 'native-php',
    version: '84f2c00',
    autoInstall: false,
    summary: '覆盖 OWASP Top 10 的综合 Web 安全训练环境。',
    tags: ['OWASP', 'PHP', 'MySQL'],
  },
  {
    slug: 'pygoat',
    title: 'OWASP PyGoat',
    category: 'Web',
    difficulty: '中等',
    sourceType: 'git',
    sourceUrl: 'https://github.com/adeyosemanputra/pygoat',
    sourceRef: 'adeyosemanputra/pygoat@19d17cc8874861142b330636d068bbde54e86b85',
    license: 'MIT',
    runtimeKind: 'native-python',
    providerId: 'native-python',
    version: '19d17cc',
    autoInstall: false,
    summary: '基于 Django 的 OWASP Top 10 学习与练习环境。',
    tags: ['OWASP', 'Python', 'Django'],
  },
]

export const builtinLabBySlug = new Map(seedLabs.map(lab => [lab.slug, lab]))
export const autoInstallLabs = process.env.VULNLAB_AUTO_INSTALL_BUILTINS === '1'
  ? seedLabs
  : seedLabs.filter(lab => lab.autoInstall)
