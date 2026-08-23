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
    sourceRef: 'digininja/DVWA@master',
    license: 'GPL-3.0',
    runtimeKind: 'native-php',
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
    sourceRef: 'zhuifengshaonianhanlu/pikachu@master',
    license: 'Apache-2.0',
    runtimeKind: 'native-php',
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
    sourceRef: 'Audi-1/sqli-labs@master',
    license: '待核验',
    runtimeKind: 'native-php',
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
    sourceRef: 'c0ny1/upload-labs@master',
    license: '待核验',
    runtimeKind: 'native-php',
    summary: '文件上传校验链路练习，覆盖多种绕过场景。',
    tags: ['Upload', 'PHP', '文件处理'],
  },
  {
    slug: 'vulnhub',
    title: 'VulnHub Machines',
    category: 'VM',
    difficulty: '困难',
    sourceType: 'catalog',
    sourceUrl: 'https://www.vulnhub.com/',
    sourceRef: 'vulnhub.com',
    license: '按机器核验',
    runtimeKind: 'vm',
    summary: '虚拟机靶场目录，适合完整主机与网络路径训练。',
    tags: ['VM', 'Linux', '主机'],
  },
  {
    slug: 'vulhub',
    title: 'Vulhub',
    category: 'Web',
    difficulty: '中等',
    sourceType: 'git',
    sourceUrl: 'https://github.com/vulhub/vulhub',
    sourceRef: 'vulhub/vulhub@master',
    license: '按场景核验',
    runtimeKind: 'container',
    summary: '按漏洞与组件组织的预构建易受攻击环境集合。',
    tags: ['CVE', 'Docker', '组件'],
  },
  {
    slug: 'juice-shop',
    title: 'OWASP Juice Shop',
    category: 'Web',
    difficulty: '中等',
    sourceType: 'git',
    sourceUrl: 'https://github.com/juice-shop/juice-shop',
    sourceRef: 'juice-shop/juice-shop@master',
    license: 'MIT',
    runtimeKind: 'container',
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
    sourceRef: 'WebGoat/WebGoat@main',
    license: 'GPL-2.0',
    runtimeKind: 'container',
    summary: '面向教学的 Web 漏洞课程式训练平台。',
    tags: ['OWASP', 'Java', '课程'],
  },
  {
    slug: 'crapi',
    title: 'OWASP crAPI',
    category: 'API',
    difficulty: '中等',
    sourceType: 'git',
    sourceUrl: 'https://github.com/OWASP/crAPI',
    sourceRef: 'OWASP/crAPI@develop',
    license: 'Apache-2.0',
    runtimeKind: 'container',
    summary: '面向 OWASP API 安全风险的现代微服务训练环境。',
    tags: ['OWASP', 'API', '微服务'],
  },
]
