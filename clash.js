/***
 * Clash Verge Rev / Mihomo Party 优化脚本
 * 原作者: dahaha-365 (YaNet)
 * Github：https://github.com/dahaha-365/YaNet
 * 
 * 优化版本 - 包含以下改进:
 * - 修复倍率正则表达式,支持更多格式
 * - 支持分号和逗号分隔符
 * - 简化默认值处理逻辑
 * - 优化模式配置为对象映射
 * - 优化 DNS 策略配置
 * - 使用更稳定的 JSDelivr CDN
 * - 提取魔法数字为常量
 * - 优化代码组织结构
 * 
 * Clash Verge Rev 专属优化:
 * - DNS 黑名单模式（性能更好）
 * - 优化 Sniffer 配置（更准确）
 * - NTP 配置优化（30分钟同步）
 * - TUN 高性能配置（MTU 9000，端点独立 NAT）
 * - Keep-Alive 优化（30秒间隔）
 * - 添加 DNS fallback 防污染
 * - ARC 缓存算法
 */

// ============================================================================
// 工具函数
// ============================================================================

/**
 * 字符串转数组 - 支持分号和逗号分隔
 */
function stringToArray(val) {
  if (Array.isArray(val)) return val
  if (typeof val !== 'string') return []
  return val
    .split(/[;,]/)  // 支持分号和逗号
    .map((item) => item.trim())
    .filter((item) => item.length > 0)
}

// ============================================================================
// 常量定义
// ============================================================================

// 网络配置常量
const NETWORK_CONSTANTS = {
  SKIP_IPS: '10.0.0.0/8;100.64.0.0/10;127.0.0.0/8;169.254.0.0/16;172.16.0.0/12;192.168.0.0/16;198.18.0.0/16;FC00::/7;FE80::/10;::1/128',
  
  // 端口配置
  PORTS: {
    EXTERNAL_CONTROLLER: '0.0.0.0:1906',
    MIXED: 7890,
  },
  
  // 超时配置
  TIMEOUTS: {
    GROUP_TEST: 3000,
    GROUP_INTERVAL: 300,
    RULE_UPDATE: 86400,
    KEEP_ALIVE: 1800,
  },
  
  // 其他配置
  MTU: 1500,
  GSO_MAX_SIZE: 65536,
  GEO_UPDATE_INTERVAL: 24,
}

// DNS 配置常量
const DNS_SERVERS = {
  CHINA_DOH: 'https://doh.pub/dns-query;https://dns.alidns.com/dns-query',
  FOREIGN_DOH: 'https://dns.google/dns-query;https://dns.adguard-dns.com/dns-query',
  CHINA_IP: '119.29.29.29;223.5.5.5',
  FOREIGN_IP: '8.8.8.8;94.140.14.14',
}

// ============================================================================
// 参数配置
// ============================================================================

const args =
  typeof $arguments !== 'undefined'
    ? $arguments
    : {
        enable: true,
        ruleSet: 'all',
        regionSet: 'all',
        excludeHighPercentage: true,
        globalRatioLimit: 2,
        skipIps: NETWORK_CONSTANTS.SKIP_IPS,
        defaultDNS: DNS_SERVERS.CHINA_IP,
        directDNS: DNS_SERVERS.CHINA_IP,
        chinaDNS: DNS_SERVERS.CHINA_DOH,
        foreignDNS: DNS_SERVERS.FOREIGN_DOH,
        mode: 'fast',
        ipv6: true,
        logLevel: 'error',
      }

/**
 * 如果是直接在软件中粘贴脚本的，就手动修改下面这几个变量实现自定义配置
 * 支持格式: 'all' 或 'openai;youtube;ads' 或 'openai,youtube,ads'
 */
let {
  enable = true,
  ruleSet = 'all',
  regionSet = 'all',
  excludeHighPercentage = true,
  globalRatioLimit = 2,
  skipIps = NETWORK_CONSTANTS.SKIP_IPS,
  defaultDNS = DNS_SERVERS.CHINA_IP,
  directDNS = DNS_SERVERS.CHINA_IP,
  chinaDNS = DNS_SERVERS.CHINA_DOH,
  foreignDNS = DNS_SERVERS.FOREIGN_DOH,
  mode = 'fast',
  ipv6 = true,
  logLevel = 'error',
} = args

// ============================================================================
// 模式配置
// ============================================================================

/**
 * DNS 模式配置 - 使用对象映射替代 switch
 */
const MODE_CONFIGS = {
  securest: {
    defaultDNS: DNS_SERVERS.FOREIGN_IP,
    directDNS: DNS_SERVERS.FOREIGN_DOH,
  },
  secure: {
    defaultDNS: DNS_SERVERS.FOREIGN_IP,
    directDNS: DNS_SERVERS.CHINA_DOH,
    chinaDNS: DNS_SERVERS.CHINA_DOH,
    foreignDNS: DNS_SERVERS.FOREIGN_DOH,
  },
  default: {
    defaultDNS: DNS_SERVERS.CHINA_IP,
    directDNS: DNS_SERVERS.CHINA_IP,
    chinaDNS: DNS_SERVERS.CHINA_DOH,
    foreignDNS: DNS_SERVERS.FOREIGN_DOH,
  },
  fast: {
    defaultDNS: DNS_SERVERS.CHINA_IP,
    directDNS: DNS_SERVERS.CHINA_IP,
    chinaDNS: DNS_SERVERS.CHINA_IP,
    foreignDNS: DNS_SERVERS.CHINA_DOH,
  },
  fastest: {
    defaultDNS: DNS_SERVERS.CHINA_IP,
    directDNS: DNS_SERVERS.CHINA_IP,
    chinaDNS: DNS_SERVERS.CHINA_IP,
    foreignDNS: DNS_SERVERS.CHINA_IP,
  },
}

// 应用模式配置
if (MODE_CONFIGS[mode]) {
  const config = MODE_CONFIGS[mode]
  if (config.defaultDNS) defaultDNS = config.defaultDNS
  if (config.directDNS) directDNS = config.directDNS
  if (config.chinaDNS) chinaDNS = config.chinaDNS
  if (config.foreignDNS) foreignDNS = config.foreignDNS
}

// 转换为数组
skipIps = stringToArray(skipIps)
defaultDNS = stringToArray(defaultDNS)
directDNS = stringToArray(directDNS)
chinaDNS = stringToArray(chinaDNS)
foreignDNS = stringToArray(foreignDNS)

// ============================================================================
// 规则配置
// ============================================================================

/**
 * 分流规则配置，会自动生成对应的策略组
 * 设置的时候可遵循"最小，可用"原则，把自己不需要的规则全禁用掉，提高效率
 * true = 启用
 * false = 禁用
 */
let ruleOptions = {
  apple: false,
  microsoft: false,
  github: false,
  google: false,
  openai: false,
  spotify: false,
  youtube: false,
  bahamut: false,
  netflix: false,
  tiktok: false,
  disney: false,
  pixiv: false,
  hbo: false,
  mediaHMT: false,
  bilibili: false,
  tvb: false,
  hulu: false,
  primevideo: false,
  telegram: false,
  line: false,
  whatsapp: false,
  games: false,
  japan: false,
  ads: false,
}

if (ruleSet === 'all') {
  Object.keys(ruleOptions).forEach(key => ruleOptions[key] = true)
} else if (typeof ruleSet === 'string') {
  const enabledKeys = stringToArray(ruleSet)  // 支持分号和逗号
  enabledKeys.forEach(key => {
    if (Object.prototype.hasOwnProperty.call(ruleOptions, key)) {
      ruleOptions[key] = true
    }
  })
}

// 初始规则
const rules = [
  'RULE-SET,applications,下载软件',
  'PROCESS-NAME-REGEX,(?i).*Oray.*,直连',
  'PROCESS-NAME-REGEX,(?i).*Sunlogin.*,直连',
  'PROCESS-NAME-REGEX,(?i).*AweSun.*,直连',
  'PROCESS-NAME-REGEX,(?i).*NodeBaby.*,直连',
  'PROCESS-NAME-REGEX,(?i).*Node Baby.*,直连',
  'PROCESS-NAME-REGEX,(?i).*nblink.*,直连',
  'PROCESS-NAME-REGEX,(?i).*vpn.*,直连',
  'PROCESS-NAME-REGEX,(?i).*vnc.*,直连',
  'PROCESS-NAME-REGEX,(?i).*tvnserver.*,直连',
  'PROCESS-NAME-REGEX,(?i).*节点小宝.*,直连',
  'PROCESS-NAME-REGEX,(?i).*AnyDesk.*,直连',
  'PROCESS-NAME-REGEX,(?i).*ToDesk.*,直连',
  'PROCESS-NAME-REGEX,(?i).*RustDesk.*,直连',
  'PROCESS-NAME-REGEX,(?i).*TeamViewer.*,直连',
  'PROCESS-NAME-REGEX,(?i).*Zerotier.*,直连',
  'PROCESS-NAME-REGEX,(?i).*Tailscaled.*,直连',
  'PROCESS-NAME-REGEX,(?i).*phddns.*,直连',
  'PROCESS-NAME-REGEX,(?i).*ngrok.*,直连',
  'PROCESS-NAME-REGEX,(?i).*frpc.*,直连',
  'PROCESS-NAME-REGEX,(?i).*frps.*,直连',
  'PROCESS-NAME-REGEX,(?i).*natapp.*,直连',
  'PROCESS-NAME-REGEX,(?i).*cloudflared.*,直连',
  'PROCESS-NAME-REGEX,(?i).*xmqtunnel.*,直连',
  'PROCESS-NAME-REGEX,(?i).*Navicat.*,直连',
  'DOMAIN-SUFFIX,iepose.com,直连',
  'DOMAIN-SUFFIX,iepose.cn,直连',
  'DOMAIN-SUFFIX,nblink.cc,直连',
  'DOMAIN-SUFFIX,ionewu.com,直连',
  'DOMAIN-SUFFIX,vicp.net,直连',
]

// ============================================================================
// 地区定义
// ============================================================================

const allRegionDefinitions = [
  {
    name: 'HK香港',
    regex: /港|🇭🇰|hk|hongkong|hong kong/i,
    icon: 'https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Hong_Kong.png',
  },
  {
    name: 'US美国',
    regex: /(?!.*aus)(?=.*(美|🇺🇸|us(?!t)|usa|american|united states)).*/i,
    icon: 'https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/United_States.png',
  },
  {
    name: 'JP日本',
    regex: /日本|🇯🇵|jp|japan/i,
    icon: 'https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Japan.png',
  },
  {
    name: 'KR韩国',
    regex: /韩|🇰🇷|kr|korea/i,
    icon: 'https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Korea.png',
  },
  {
    name: 'SG新加坡',
    regex: /新加坡|🇸🇬|sg|singapore/i,
    icon: 'https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Singapore.png',
  },
  {
    name: 'CN中国大陆',
    regex: /中国|🇨🇳|cn|china/i,
    icon: 'https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/China_Map.png',
  },
  {
    name: 'TW台湾省',
    regex: /台湾|台灣|🇹🇼|tw|taiwan|tai wan/i,
    icon: 'https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/China.png',
  },
  {
    name: 'GB英国',
    regex: /英|🇬🇧|uk|united kingdom|great britain/i,
    icon: 'https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/United_Kingdom.png',
  },
  {
    name: 'DE德国',
    regex: /德国|🇩🇪|de|germany/i,
    icon: 'https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Germany.png',
  },
  {
    name: 'MY马来西亚',
    regex: /马来|🇲🇾|my|malaysia/i,
    icon: 'https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Malaysia.png',
  },
  {
    name: 'TK土耳其',
    regex: /土耳其|🇹🇷|tk|turkey/i,
    icon: 'https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Turkey.png',
  },
  {
    name: 'CA加拿大',
    regex: /加拿大|🇨🇦|ca|canada/i,
    icon: 'https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Canada.png',
  },
  {
    name: 'AU澳大利亚',
    regex: /澳大利亚|🇦🇺|au|australia|sydney/i,
    icon: 'https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Australia.png',
  },
]

let regionDefinitions = []
if (regionSet === 'all') {
  regionDefinitions = allRegionDefinitions
} else {
  const enabledRegions = stringToArray(regionSet)  // 支持分号和逗号
  regionDefinitions = allRegionDefinitions.filter(r => {
    const prefix = r.name.substring(0, 2) // 获取前两个字母
    return enabledRegions.includes(prefix)
  })
}

// ============================================================================
// DNS 配置
// ============================================================================

// Clash Verge Rev 专属优化 DNS 配置
const dnsConfig = {
  enable: true,
  listen: '0.0.0.0:53',
  ipv6: true,
  'log-level': logLevel,
  'prefer-h3': true,
  'use-hosts': true,
  'use-system-hosts': true,
  'enhanced-mode': 'fake-ip',
  'fake-ip-range': '198.18.0.0/16',
  
  // Clash Verge Rev 优化: 改为黑名单模式（性能更好）
  'fake-ip-filter-mode': 'blacklist',
  'fake-ip-filter': [
    // 局域网地址
    '+.lan',
    '+.local',
    
    // Windows 网络检测
    'localhost.ptlogin2.qq.com',
    'dns.msftncsi.com',
    '+.msftconnecttest.com',
    '+.msftncsi.com',
    
    // 各平台网络检测
    'network-test.debian.org',
    'detectportal.firefox.com',
    'cable.auth.com',
    'captive.apple.com',
    'connectivitycheck.gstatic.com',
    'nmcheck.gnome.org',
    
    // 运营商
    '+.10010.com',
    
    // NTP 服务器
    'ntp.*.com',
    'time.*.com',
    'time.*.gov',
    'time.*.edu.cn',
    'time.*.apple.com',
    'time1.*.com',
    'time2.*.com',
    'time3.*.com',
    'time4.*.com',
    'time5.*.com',
    'time6.*.com',
    'time7.*.com',
    'ntp1.*.com',
    'ntp2.*.com',
    'ntp3.*.com',
    'ntp4.*.com',
    'ntp5.*.com',
    'ntp6.*.com',
    'ntp7.*.com',
    '*.time.edu.cn',
    '*.ntp.org.cn',
    '+.pool.ntp.org',
    'time1.cloud.tencent.com',
    
    // 游戏 STUN 服务
    'stun.*.*',
    'stun.*.*.*',
    '+.stun.*.*',
    '+.stun.*.*.*',
    '+.stun.*.*.*.*',
    '+.stun.*.*.*.*.*',
    
    // 音乐服务（避免影响播放）
    'music.163.com',
    '*.music.163.com',
    '*.126.net',
    'musicapi.taihe.com',
    'music.taihe.com',
    'songsearch.kugou.com',
    'trackercdn.kugou.com',
    '*.kuwo.cn',
    'api-jooxtt.sanook.com',
    'api.joox.com',
    'joox.com',
    '+.y.qq.com',
    
    // 游戏平台
    'xbox.*.microsoft.com',
    '+.xboxlive.com',
    '+.battlenet.com.cn',
    '+.battlenet.com',
    '+.blzstatic.cn',
    '+.battle.net',
  ],
  
  nameserver: chinaDNS,
  'default-nameserver': defaultDNS,
  'proxy-server-nameserver': directDNS,
  
  // Clash Verge Rev 优化: 添加 fallback 防污染
  fallback: foreignDNS,
  'fallback-filter': {
    geoip: true,
    'geoip-code': 'CN',
    geosite: ['gfw'],
    ipcidr: ['240.0.0.0/4', '0.0.0.0/32'],
    domain: [
      '+.google.com',
      '+.facebook.com',
      '+.youtube.com',
      '+.twitter.com',
      '+.github.com',
    ],
  },
  
  // Clash Verge Rev 优化: 缓存算法
  'cache-algorithm': 'arc',
  
  // 优化后的 DNS 策略配置
  'nameserver-policy': {
    // 系统相关
    'geosite:private': 'system',
    
    // 国内域名
    'geosite:cn': chinaDNS,
    'geosite:tld-cn': chinaDNS,
    'geosite:category-companies@cn': chinaDNS,
    'geosite:steam@cn': chinaDNS,
    'geosite:category-games@cn': chinaDNS,
    'geosite:microsoft@cn': chinaDNS,
    'geosite:apple@cn': chinaDNS,
    'geosite:category-game-platforms-download@cn': chinaDNS,
    'geosite:category-public-tracker': chinaDNS,
    
    // 国外域名
    'geosite:gfw': foreignDNS,
    'geosite:category-ai-!cn': foreignDNS,
    'geosite:category-ai-chat-!cn': foreignDNS,
    'geosite:openai': foreignDNS,
    'geosite:anthropic': foreignDNS,
    'geosite:google@!cn': foreignDNS,
    'geosite:github': foreignDNS,
    'geosite:telegram': foreignDNS,
    'geosite:twitter': foreignDNS,
    'geosite:facebook': foreignDNS,
    'geosite:youtube': foreignDNS,
    'geosite:netflix': foreignDNS,
    'geosite:disney': foreignDNS,
    
    // 直接指定（更快）
    '+.openai.com': foreignDNS,
    '+.anthropic.com': foreignDNS,
    '+.github.com': foreignDNS,
    '+.github.io': foreignDNS,
    '+.githubusercontent.com': foreignDNS,
  },
}

// ============================================================================
// 通用配置
// ============================================================================

const ruleProviderCommon = {
  type: 'http',
  format: 'yaml',
  interval: NETWORK_CONSTANTS.TIMEOUTS.RULE_UPDATE,
}

const groupBaseOption = {
  interval: NETWORK_CONSTANTS.TIMEOUTS.GROUP_INTERVAL,
  timeout: NETWORK_CONSTANTS.TIMEOUTS.GROUP_TEST,
  url: 'http://www.gstatic.com/generate_204',
  lazy: true,
  'max-failed-times': 3,
  hidden: false,
}

// 预定义 Rule Providers
const ruleProviders = {
  applications: {
    ...ruleProviderCommon,
    behavior: 'classical',
    format: 'text',
    url: 'https://github.com/DustinWin/ruleset_geodata/raw/refs/heads/mihomo-ruleset/applications.list',
    path: './ruleset/DustinWin/applications.list',
  },
}

// ============================================================================
// 倍率正则 - 优化版
// ============================================================================

/**
 * 倍率检测正则表达式 - 支持更多格式
 * 匹配示例:
 * - "2.5x" "3X" "1.5✕"
 * - "[1.5倍]" "(2倍)"
 * - "倍率:2" "倍率 2.5"
 */
const multiplierRegex = /倍率[:\s]*([0-9.]+)|([0-9.]+)[xX✕✖⨉倍]/i

// ============================================================================
// 服务规则数据结构
// ============================================================================

const serviceConfigs = [
  {
    key: 'openai',
    name: '国外AI',
    icon: 'https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/ChatGPT.png',
    url: 'http://www.gstatic.com/generate_204',
    rules: [
      'GEOSITE,jetbrains-ai,国外AI',
      'GEOSITE,category-ai-!cn,国外AI',
      'GEOSITE,category-ai-chat-!cn,国外AI',
      'DOMAIN-SUFFIX,meta.ai,国外AI',
      'DOMAIN-SUFFIX,meta.com,国外AI',
      'PROCESS-NAME-REGEX,(?i).*Antigravity.*,国外AI',
      'PROCESS-NAME-REGEX,(?i).*language_server_.*,国外AI',
    ],
  },
  {
    key: 'youtube',
    name: 'YouTube',
    icon: 'https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/YouTube.png',
    url: 'http://www.gstatic.com/generate_204',
    rules: ['GEOSITE,youtube,YouTube'],
  },
  {
    key: 'mediaHMT',
    name: '港澳台媒体',
    icon: 'https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/TVB.png',
    url: 'http://www.gstatic.com/generate_204',
    rules: [
      'GEOSITE,tvb,港澳台媒体',
      'GEOSITE,hkt,港澳台媒体',
      'GEOSITE,hkbn,港澳台媒体',
      'GEOSITE,hkopentv,港澳台媒体',
      'GEOSITE,hkedcity,港澳台媒体',
      'GEOSITE,hkgolden,港澳台媒体',
      'GEOSITE,hketgroup,港澳台媒体',
      'RULE-SET,hk-media,港澳台媒体',
      'RULE-SET,tw-media,港澳台媒体',
    ],
    providers: [
      {
        key: 'hk-media',
        url: 'https://ruleset.skk.moe/Clash/non_ip/stream_hk.txt',
        path: './ruleset/ruleset.skk.moe/stream_hk.txt',
        format: 'text',
        behavior: 'classical',
      },
      {
        key: 'tw-media',
        url: 'https://ruleset.skk.moe/Clash/non_ip/stream_tw.txt',
        path: './ruleset/ruleset.skk.moe/stream_tw.txt',
        format: 'text',
        behavior: 'classical',
      },
    ],
  },
  {
    key: 'bilibili',
    name: '哔哩哔哩',
    icon: 'https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/bilibili_3.png',
    url: 'http://www.gstatic.com/generate_204',
    rules: ['GEOSITE,bilibili,哔哩哔哩'],
  },
  {
    key: 'bahamut',
    name: '巴哈姆特',
    icon: 'https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Bahamut.png',
    url: 'http://www.gstatic.com/generate_204',
    rules: ['GEOSITE,bahamut,巴哈姆特'],
  },
  {
    key: 'disney',
    name: 'Disney+',
    icon: 'https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Disney+.png',
    url: 'http://www.gstatic.com/generate_204',
    rules: ['GEOSITE,disney,Disney+'],
  },
  {
    key: 'netflix',
    name: 'NETFLIX',
    icon: 'https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Netflix.png',
    url: 'http://www.gstatic.com/generate_204',
    rules: ['GEOSITE,netflix,NETFLIX'],
  },
  {
    key: 'tiktok',
    name: 'Tiktok',
    icon: 'https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/TikTok.png',
    url: 'http://www.gstatic.com/generate_204',
    rules: ['GEOSITE,tiktok,Tiktok'],
  },
  {
    key: 'spotify',
    name: 'Spotify',
    icon: 'https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Spotify.png',
    url: 'http://www.gstatic.com/generate_204',
    rules: ['GEOSITE,spotify,Spotify'],
  },
  {
    key: 'pixiv',
    name: 'Pixiv',
    icon: 'https://play-lh.googleusercontent.com/8pFuLOHF62ADcN0ISUAyEueA5G8IF49mX_6Az6pQNtokNVHxIVbS1L2NM62H-k02rLM=w240-h480-rw',
    url: 'http://www.gstatic.com/generate_204',
    rules: ['GEOSITE,pixiv,Pixiv'],
  },
  {
    key: 'hbo',
    name: 'HBO',
    icon: 'https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/HBO.png',
    url: 'http://www.gstatic.com/generate_204',
    rules: ['GEOSITE,hbo,HBO'],
  },
  {
    key: 'primevideo',
    name: 'Prime Video',
    icon: 'https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Prime_Video.png',
    url: 'http://www.gstatic.com/generate_204',
    rules: ['GEOSITE,primevideo,Prime Video'],
  },
  {
    key: 'hulu',
    name: 'Hulu',
    icon: 'https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Hulu.png',
    url: 'http://www.gstatic.com/generate_204',
    rules: ['GEOSITE,hulu,Hulu'],
  },
  {
    key: 'telegram',
    name: 'Telegram',
    icon: 'https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Telegram.png',
    url: 'http://www.gstatic.com/generate_204',
    rules: ['GEOIP,telegram,Telegram'],
  },
  {
    key: 'whatsapp',
    name: 'WhatsApp',
    icon: 'https://static.whatsapp.net/rsrc.php/v3/yP/r/rYZqPCBaG70.png',
    url: 'http://www.gstatic.com/generate_204',
    rules: ['GEOSITE,whatsapp,WhatsApp'],
  },
  {
    key: 'line',
    name: 'Line',
    icon: 'https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Line.png',
    url: 'http://www.gstatic.com/generate_204',
    rules: ['GEOSITE,line,Line'],
  },
  {
    key: 'games',
    name: '游戏专用',
    icon: 'https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Game.png',
    rules: [
      'GEOSITE,category-games@cn,国内网站',
      'GEOSITE,category-games,游戏专用',
    ],
  },
  {
    key: 'ads',
    name: '广告过滤',
    icon: 'https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Advertising.png',
    rules: [
      'GEOSITE,category-ads-all,广告过滤',
      'RULE-SET,adblockmihomo,广告过滤',
    ],
    providers: [
      {
        key: 'adblockmihomo',
        url: 'https://github.com/217heidai/adblockfilters/raw/refs/heads/main/rules/adblockmihomo.mrs',
        path: './ruleset/adblockfilters/adblockmihomo.mrs',
        format: 'mrs',
        behavior: 'domain',
      },
    ],
    reject: true,
  },
  {
    key: 'apple',
    name: '苹果服务',
    icon: 'https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Apple_2.png',
    url: 'http://www.gstatic.com/generate_204',
    rules: ['GEOSITE,apple-cn,苹果服务'],
  },
  {
    key: 'google',
    name: '谷歌服务',
    icon: 'https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Google_Search.png',
    url: 'http://www.gstatic.com/generate_204',
    rules: ['GEOSITE,google,谷歌服务'],
  },
  {
    key: 'github',
    name: 'Github',
    icon: 'https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/GitHub.png',
    url: 'http://www.gstatic.com/generate_204',
    rules: ['GEOSITE,github,Github'],
  },
  {
    key: 'microsoft',
    name: '微软服务',
    icon: 'https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Microsoft.png',
    url: 'http://www.gstatic.com/generate_204',
    rules: ['GEOSITE,microsoft@cn,国内网站', 'GEOSITE,microsoft,微软服务'],
  },
  {
    key: 'japan',
    name: '日本网站',
    icon: 'https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/JP.png',
    url: 'http://www.gstatic.com/generate_204',
    rules: [
      'RULE-SET,category-bank-jp,日本网站',
      'GEOIP,jp,日本网站,no-resolve',
    ],
    providers: [
      {
        key: 'category-bank-jp',
        url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/category-bank-jp.mrs',
        path: './ruleset/MetaCubeX/category-bank-jp.mrs',
        format: 'mrs',
        behavior: 'domain',
      },
    ],
  },
]

// ============================================================================
// 辅助函数
// ============================================================================

/**
 * 应用基础配置到 config 对象
 */
function applyBaseConfig(config) {
  config['allow-lan'] = true
  config['bind-address'] = '*'
  config['mode'] = 'rule'
  config['ipv6'] = ipv6
  config['external-controller'] = NETWORK_CONSTANTS.PORTS.EXTERNAL_CONTROLLER
  config['mixed-port'] = NETWORK_CONSTANTS.PORTS.MIXED
  config['external-ui'] = 'ui'
  config['external-ui-url'] =
    'https://github.com/Zephyruso/zashboard/releases/latest/download/dist.zip'
  config['dns'] = dnsConfig
  config['profile'] = {
    'store-selected': true,
    'store-fake-ip': true,
  }
  config['unified-delay'] = true
  config['tcp-concurrent'] = true
  config['keep-alive-interval'] = 30  // Clash Verge Rev 优化: 30 秒
  config['find-process-mode'] = 'strict'
  config['geodata-mode'] = false
  config['geodata-loader'] = 'memconservative'
  config['geo-auto-update'] = true
  config['geo-update-interval'] = NETWORK_CONSTANTS.GEO_UPDATE_INTERVAL

  // Clash Verge Rev 专属优化 Sniffer 配置
  config['sniffer'] = {
    enable: true,
    'force-dns-mapping': true,
    'parse-pure-ip': true,  // Clash Verge Rev 优化: 解析纯 IP
    'override-destination': true,
    
    sniff: {
      HTTP: {
        ports: [80, '8080-8880'],
        'override-destination': true,
      },
      TLS: {
        ports: [443, 8443],
      },
      QUIC: {
        ports: [443, 8443],
      },
    },
    
    'skip-src-address': skipIps,
    'skip-dst-address': skipIps,
    
    // Clash Verge Rev 优化: 扩展强制域名嗅探
    'force-domain': [
      '+.google.com',
      '+.googleapis.com',
      '+.googleusercontent.com',
      '+.googlevideo.com',
      '+.gstatic.com',
      '+.youtube.com',
      '+.ytimg.com',
      '+.twitter.com',
      '+.twimg.com',
      '+.facebook.com',
      '+.fbcdn.net',
      '+.messenger.com',
      '+.instagram.com',
      '+.whatsapp.com',
      '+.telegram.org',
      '+.github.com',
      '+.github.io',
      '+.githubusercontent.com',
      '+.netflix.com',
      '+.nflxvideo.net',
      '+.nflximg.net',
      '+.nflxso.net',
      '+.nflxext.com',
    ],
    
    // Clash Verge Rev 优化: 扩展跳过域名
    'skip-domain': [
      'Mijia Cloud',
      '+.oray.com',
      '+.sunlogin.net',
      '+.awesun.com',
      '+.parsec.app',
      '+.teamviewer.com',
      '+.anydesk.com',
      '+.todesk.com',
      '+.rustdesk.com',
      'captive.apple.com',
      'connectivitycheck.gstatic.com',
      'detectportal.firefox.com',
      'msftconnecttest.com',
      'nmcheck.gnome.org',
    ],
    
    // Clash Verge Rev 特性
    'sniff-tls-sni': true,
  }

  // Clash Verge Rev 专属优化 NTP 配置
  config['ntp'] = {
    enable: true,
    'write-to-system': false,
    server: 'ntp.aliyun.com',  // 阿里云 NTP（国内快）
    port: 123,
    interval: 30,  // Clash Verge Rev 优化: 30 分钟同步
  }

  // Clash Verge Rev 专属优化 TUN 配置
  config['tun'] = {
    enable: true,
    stack: 'mixed',  // Clash Verge Rev 推荐
    device: 'Meta',  // Clash Verge Rev 默认设备名
    'auto-route': true,
    'auto-redirect': true,
    'auto-detect-interface': true,
    'strict-route': true,
    
    // Clash Verge Rev 性能优化
    mtu: 9000,  // Jumbo Frame (高性能网络)，家庭网络可改为 1500
    gso: true,
    'gso-max-size': NETWORK_CONSTANTS.GSO_MAX_SIZE,
    'udp-timeout': 300,  // UDP 超时 300 秒
    
    // Clash Verge Rev 特性
    'endpoint-independent-nat': true,  // 端点独立 NAT
    
    'exclude-interface': [
      'NodeBabyLink',
      'VMware.*',
      'VirtualBox.*',
      'Hyper-V.*',
    ],
    
    'route-exclude-address': skipIps.filter((ip) => ip !== '198.18.0.0/16'),
    
    // Clash Verge Rev 优化: 优先路由
    'route-address': [
      '0.0.0.0/1',
      '128.0.0.0/1',
      '::/1',
      '8000::/1',
    ],
    
    'dns-hijack': ['any:53', 'tcp://any:53'],
  }

  // 使用 JSDelivr CDN 替代 gh-proxy (更稳定)
  config['geox-url'] = {
    geoip: 'https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip-lite.dat',
    geosite: 'https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat',
    mmdb: 'https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/country.mmdb',
    asn: 'https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/GeoLite2-ASN.mmdb',
  }
}

/**
 * 分类代理节点
 */
function classifyProxies(proxies, proxyCount) {
  const regionGroups = {}
  regionDefinitions.forEach(
    (r) =>
      (regionGroups[r.name] = {
        ...r,
        proxies: [],
      })
  )
  const otherProxies = []

  for (const proxy of proxies) {
    const name = proxy.name
    let matched = false

    // 检查倍率 - 使用优化后的正则
    if (excludeHighPercentage) {
      const match = multiplierRegex.exec(name)
      if (match) {
        const ratio = parseFloat(match[1] || match[2])
        if (ratio > globalRatioLimit) {
          continue
        }
      }
    }

    // 尝试匹配地区
    for (const region of regionDefinitions) {
      if (region.regex.test(name)) {
        regionGroups[region.name].proxies.push(name)
        matched = true
        break
      }
    }

    if (!matched) {
      otherProxies.push(name)
    }
  }

  return { regionGroups, otherProxies }
}

/**
 * 生成地区策略组
 */
function generateRegionGroups(regionGroups) {
  const generatedRegionGroups = []
  
  regionDefinitions.forEach((r) => {
    const groupData = regionGroups[r.name]
    if (groupData.proxies.length > 0) {
      generatedRegionGroups.push({
        ...groupBaseOption,
        name: r.name,
        type: 'url-test',
        tolerance: 50,
        icon: r.icon,
        proxies: groupData.proxies,
      })
    }
  })

  return generatedRegionGroups
}

/**
 * 构建功能策略组
 */
function buildFunctionalGroups(regionGroupNames, hasOtherProxies) {
  const functionalGroups = []

  functionalGroups.push({
    ...groupBaseOption,
    name: '默认节点',
    type: 'select',
    proxies: [...regionGroupNames, '其他节点', '直连'].filter(
      (n) => n !== '其他节点' || hasOtherProxies
    ),
    icon: 'https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Proxy.png',
  })

  serviceConfigs.forEach((svc) => {
    if (ruleOptions[svc.key]) {
      rules.push(...svc.rules)

      if (Array.isArray(svc.providers)) {
        svc.providers.forEach((p) => {
          ruleProviders[p.key] = {
            ...ruleProviderCommon,
            behavior: p.behavior,
            format: p.format,
            url: p.url,
            path: p.path,
          }
        })
      }

      let groupProxies
      if (svc.reject) {
        groupProxies = ['REJECT', '直连', '默认节点']
      } else if (svc.key === 'biliintl' || svc.key === 'bahamut') {
        groupProxies = ['默认节点', '直连', ...regionGroupNames]
      } else {
        groupProxies = ['默认节点', ...regionGroupNames, '直连']
      }

      functionalGroups.push({
        ...groupBaseOption,
        name: svc.name,
        type: 'select',
        proxies: groupProxies,
        url: svc.url,
        icon: svc.icon,
      })
    }
  })

  return functionalGroups
}

/**
 * 添加兜底策略组
 */
function addFallbackGroups(regionGroupNames) {
  return [
    {
      ...groupBaseOption,
      name: '下载软件',
      type: 'select',
      proxies: ['直连', 'REJECT', '默认节点', '国内网站', ...regionGroupNames],
      icon: 'https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Download.png',
    },
    {
      ...groupBaseOption,
      name: '其他外网',
      type: 'select',
      proxies: ['默认节点', '国内网站', ...regionGroupNames],
      icon: 'https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Streaming!CN.png',
    },
    {
      ...groupBaseOption,
      name: '国内网站',
      type: 'select',
      proxies: ['直连', '默认节点', ...regionGroupNames],
      url: 'https://wifi.vivo.com.cn/generate_204',
      icon: 'https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/StreamingCN.png',
    },
  ]
}

// ============================================================================
// 主入口
// ============================================================================

function main(config) {
  if (!enable) return config

  const proxies = config?.proxies || []
  const proxyCount = proxies.length
  const proxyProviderCount =
    typeof config?.['proxy-providers'] === 'object'
      ? Object.keys(config['proxy-providers']).length
      : 0

  if (proxyCount === 0 && proxyProviderCount === 0) {
    throw new Error('配置文件中未找到任何代理')
  }

  // 应用基础配置
  applyBaseConfig(config)

  // 添加直连和拒绝节点
  config.proxies.push(
    {
      name: '直连',
      type: 'direct',
      udp: true,
    },
    {
      name: '拒绝',
      type: 'reject',
      udp: true,
    }
  )

  // 分类代理节点
  const { regionGroups, otherProxies } = classifyProxies(proxies, proxyCount)

  // 生成地区策略组
  const generatedRegionGroups = generateRegionGroups(regionGroups)
  const regionGroupNames = generatedRegionGroups.map((g) => g.name)

  // 添加其他节点组
  if (otherProxies.length > 0) {
    generatedRegionGroups.push({
      ...groupBaseOption,
      name: '其他节点',
      type: 'select',
      proxies: otherProxies,
      icon: 'https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/World_Map.png',
    })
  }

  // 构建功能策略组
  const functionalGroups = buildFunctionalGroups(
    regionGroupNames,
    otherProxies.length > 0
  )

  // 添加兜底规则
  rules.push(
    'GEOSITE,private,直连',
    'GEOSITE,category-public-tracker,直连',
    'GEOSITE,category-game-platforms-download@cn,直连',
    'GEOIP,private,直连,no-resolve',
    'GEOSITE,cn,国内网站',
    'GEOIP,cn,国内网站,no-resolve',
    'MATCH,其他外网'
  )

  // 添加兜底策略组
  const fallbackGroups = addFallbackGroups(regionGroupNames)

  // 组装最终配置
  config['proxy-groups'] = [
    ...functionalGroups,
    ...fallbackGroups,
    ...generatedRegionGroups,
  ]
  config['rules'] = rules
  config['rule-providers'] = ruleProviders

  return config
}
