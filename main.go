package main

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ============================================================================
// КОНСТАНТЫ
// ============================================================================

const (
	WorkerCount        = 50
	ConnectTimeout     = 5 * time.Second
	TLSHandshakeTimeout = 5 * time.Second
	HTTPRequestTimeout = 10 * time.Second

	// Минимальное количество использований SNI для попадания в whitelist
	MinUsageCount = 2

	// Результаты
	ResultsDir = "results"
)

// ============================================================================
// РАСШИРЕННЫЙ BLACKLIST - VPN/PROXY МУСОР
// ============================================================================

// Домены-мусор которые 100% не нужны
var blacklistedSNI = []string{
	// Big Tech (заблокированы или не нужны)
	"google.com", "youtube.com", "facebook.com", "instagram.com", "twitter.com",
	"cloudflare.com", "amazon.com", "microsoft.com", "apple.com", "github.com",
	"chatgpt.com", "openai.com", "reddit.com", "tiktok.com",

	// Adult/Gambling
	"pornhub", "xvideos", "xhamster", "redtube", "porn", "xxx",
	"bet", "casino", "gambling", "poker", "slot",

	// Suspicious TLDs
	".ir", ".cn", ".pk", ".af", ".sy", ".sa", ".vn", ".id", ".br",
	".su", ".xyz", ".top", ".click", ".site", ".online", ".shop", ".icu",
	".win", ".loan", ".trade", ".science", ".work", ".party", ".rugby",
	".cfd", ".sbs", ".fun", ".monster", ".ovh", ".pro", ".info", ".biz",
	".tech", ".store", ".app", ".dev", ".page", ".club", ".online",

	// VPN/Proxy services - ГЛАВНЫЙ МУСОР
	"vpn", "proxy", "tunnel", "v2ray", "xray", "shadowsocks", "trojan",
	"outline", "clash", "sing-box", "nekoray", "vless", "vmess",
	"ssr", "socks", "tor", "obfs",

	// Конкретные VPN/Proxy домены - МУСОР
	"invisevps", "firstvds", "ultimateserv", "suio.me", "smarteracloud",
	"outlinekeys", "jugsenkeys", "fasssst", "privetnet", "shadow-net",
	"resetnet", "allonetworks", "normbot", "kopobkatopta",
	"harknmav.fun", "harknmav", "darknet.run", "darknet",
	"scroogethebest.com", "scroogethebest",
	"fonixapp.org", "fonixapp",
	"cowjuice.me", "cowjuice",
	"vles.space", "vles", "prod.n7.homes",
	"ultima.foundation", "ultima",
	"vitalik.space", "vitalik",
	"asbndx.com", "asbndx",
	"nosok-top.com", "nosok",
	"geodema.network", "geodema",
	"boxypn.com", "boxypn",
	"rexten.cc", "rexten",
	"spectrum.vu", "spectrum",
	"overload.ovh", "overload",
	"freednet.org", "freednet",
	"webunlocked.org", "webunlocked",
	"unlocknet.org", "unlocknet",
	"unboundaccess.org", "unboundaccess",
	"unboundworld.org", "unboundworld",
	"unlockmatrix.org", "unlockmatrix",
	"luckernld.org", "luckernld",
	"lackerdeu.org", "lackerdeu",
	"deulucker.org", "deulucker",
	"luckerusa.org", "luckerusa",
	"clearorbitllc.com", "clearorbit",
	"yourbot.biz", "yourbot",
	"mizbandana.org", "mizbandana",
	"teleport.lat", "teleport",
	"zapret-tg.ru", "zapret",
	"minzt.ru", "minzt",
	"plus-hit.ru", "plus-hit",
	"morro-settings.ru", "morro",
	"melbicom.ru", "melbicom",
	"mediakit-ozon.ru", "mediakit",
	"astracat.ru", "astracat",
	"convert24.ru", "convert24",
	"mindbox.ru", "mindbox",
	"boot-lee.ru", "boot-lee",
	"botchillus.ru", "botchillus",
	"bot-iphone.ru", "bot-iphone",
	"hwowst.ru", "hwowst",
	"adr-cloud.ru", "adr-cloud",
	"ardor-cloud.ru", "ardor-cloud",
	"atlanta-internet.ru", "atlanta",
	"pryanik.net.ru", "pryanik",
	"gorhub.ru", "gorhub",
	"dnsttlocate.ru", "dnstt",
	"seemsflower.ru", "seemsflower",
	"trustsub.ru", "trustsub",
	"trustformydns.ru", "trustformydns",
	"vmelectronics.ru", "vmelectronics",
	"youtubesaver.ru", "youtubesaver",
	"nitroo-tech.ru", "nitroo",
	"plansv.tech", "plansv",
	"krasivogame.ru", "krasivogame",
	"intfreed.ru", "intfreed",
	"stat-ozon.ru", "stat-ozon",
	"skfv-mirror.ru", "skfv",
	"keshe-voz.ru", "keshe",
	"mutabor-sec.ru", "mutabor",
	"reality.tv123.ru", "reality.tv123",
	"connect-iskra.ru", "connect-iskra",
	"connect-opengate.ru", "connect-opengate",
	"maviks.ru", "maviks", "maviks.eu",
	"connect-iskra.cv", "connect-iskra.cv",
	"nodu", "nodu1", "nodu2", "nodu3",
	"pp.ua",
	"ccwu.cc",
	"gptban.com",
	"ads.limit.info", "adslimit.info",
	"ping-box.com",
	"pingless.com",
	"moktana.digital",
	"aliparvaresh",
	"shadownet.pro",
	"wenllies.com",
	"jobby.ai",
	"curfuffled.com",
	"towersflowerss.com",
	"monolithgate.com",
	"hutsharing.com",
	"freerunet.lat",
	"netliberated.org",
	"indosoxr.info",
	"zimba-zula.org",
	"gitlab.org",
	"dalixw.fun",
	"panelse",
	"marandcity.com",
	"kalbodim",
	"vezzeee.com",
	"titimoji",
	"marzshekan",
	"kanal-tel-nufilter",
	"pecan.run",
	"fosfor",
	"vidoo",
	"agah",
	"dolat",
	"irn",
	"chort",
	"vitiv",
	"miyazono-kaori.com",
	"dostup.lat",
	"f-sub.cfd", "f-sub.com",
	"visi.rip",
	"skystreamgame.com",
	"team-pluss.com",
	"globalfymain.com",
	"chandplus.com",
	"alpacalounge.com",
	"gagtubelol.com",
	"kitten-tube.com",
	"abrdns.com",
	"v-tun.com",
	"silverzebra",
	"beast-masters",
	"antimage",
	"dwarvensniper",
	"huskar",
	"darkterror",
	"butcher",
	"bloodseeker",
	"tuskar",
	"invoker",
	"zeusolympus",
	"elementalss",
	"ezalor",
	"sandking",
	"alchemistss",
	"bountyhunter",
	"dota2play",
	"fonixapp.org",
	"userapi.com",
	"sun6-", "sun9-", "sun1-", "sun2-", "sun4-",
	"pp.userapi.com",

	// Hosting/CDN
	"cdn.stun", "cdnvideo", "cdnv-img", "cdns.su", "msemse.ru",
	"lagzero", "quattro-tech", "jojack.ru", "serverstats",
	"hb-by3", "pkvc-hls4", "nlcdn", "cdn.",

	// Cloud platforms (бесплатные)
	"worker", "pages.dev", "herokuapp", "workers.dev", "vercel.app",
	"netlify.app", "railway.app", "render.com",
	"eu-central-1.clawcloudrun.com",
	"github.io",

	// Local/Private
	"localhost", "127.0.0.1", "0.0.0.0",

	// Analytics/Ads
	"doubleclick", "adservice", "analytics", "cdnjs", "fonts.googleapis",
	"counter.yadro", "ad.mail.ru", "googletagmanager",
	"googlesyndication", "google-analytics",
	"static.cloudflareinsights.com",

	// Other trash
	"fuck.rkn", "arvancloud", "derp",
	"example.com", "example.org",
	"test.com", "demo.com",
	"docker.com", "docker.io",
	"quay.io",
	"npmjs.com", "npmjs.org",
	"pypi.org",
	"medium.com",
	"substack.com",
	"patreon.com",
	"ko-fi.com",
	"buymeacoffee.com",
	"stripe.com",
	"paypal.com",
	"wise.com",
	"transferwise.com",
	"revolut.com",
	"binance.com",
	"coinbase.com",
	"kraken.com",
	"poloniex.com",
	"coinmarketcap.com",
}

// Категории SNI для классификации
var sniCategories = map[string][]string{
	"banks": {
		"sberbank", "tbank", "tinkoff", "vtb", "alfa", "alfabank", "raiffeisen",
		"gazprombank", "moscow.megafon", "rosbank", "psbank", "mkb", "open.ru",
		"unicredit", "otpbank", "pochtabank", "qiwi", "yoomoney",
	},
	"ecommerce": {
		"ozon", "wildberries", "avito", "yandex", "market.yandex", "beru",
		"aliexpress", "lamoda", "sportmaster", "dns-shop", "mvideo", "eldorado",
		"citilink", "leroymerlin", "petrovich", "detmir", "x5.ru", "magnit",
	},
	"social": {
		"vk.com", "ok.ru", "mail.ru", "dzen", "rutube", "kinopoisk",
		"pikabu", "livejournal", "rambler",
	},
	"government": {
		"gosuslugi", "mos.ru", "nalog", "pochta.ru", "rzd", "government",
		"duma.gov", "kremlin", "genproc", "edu.ru",
	},
	"tech": {
		"hh.ru", "habr", "2gis", "tutu", "aviasales", "drive2", "drom",
		"auto.ru", "autoru", "cian", "gismeteo", "rbc", "lenta", "kp.ru",
		"gazeta", "ivi", "apteka",
	},
	"mobile": {
		"mts", "megafon", "beeline", "tele2", "t2.ru", "yota",
	},
	"cloud": {
		"yandexcloud", "cloud.yandex", "vkcloud", "sbercloud", "selectel",
		"timeweb", "mcs.mail",
	},
}

// Элитные домены - самые надёжные против ТСПУ
var eliteDomains = []string{
	// Топ-приоритет
	"sberbank.ru", "tbank.ru", "tinkoff.ru", "vtb.ru", "alfabank.ru",
	"yandex.ru", "ya.ru", "vk.com", "vk.ru", "mail.ru", "ok.ru",
	"gosuslugi.ru", "mos.ru", "nalog.gov.ru", "rzd.ru",
	"ozon.ru", "wildberries.ru", "avito.ru", "market.yandex.ru",
	"mts.ru", "megafon.ru", "beeline.ru", "tele2.ru",
	"hh.ru", "habr.ru", "2gis.ru", "kinopoisk.ru",
	"rbc.ru", "lenta.ru", "rambler.ru",
	"dzen.ru", "rutube.ru",
	"ivi.ru", "okko.ru",
	"gismeteo.ru", "weather",
}

// Подозрительные поддомены (технические)
var suspiciousSubdomains = []string{
	"api", "api-", "api.", "-api",
	"static", "st.", "st-", "cdn", "cdn-", "cdn.",
	"edge", "edge-", "node", "node-", "relay", "relay-",
	"test", "demo", "dev", "staging", "stage", "beta", "alpha",
	"tmp", "temp", "backup", "bak",
	"old", "new", "v1", "v2", "v3", "v4",
	"ws", "wss", "ws-", "socket",
	"img", "img-", "image", "images", "img.", "images.",
	"assets", "asset", "static-", "files", "file",
	"download", "download-", "dl", "dl-", "dl.",
	"upload", "upload-",
	"admin", "admin-", "panel", "dashboard",
	"mail", "smtp", "imap", "pop", "pop3",
	"vpn", "proxy", "tunnel",
	"secure", "security", "ssl", "tls",
	"mobile", "m.", "wap", "app", "apps",
	"sso", "login", "auth", "oauth", "saml",
	"key", "keys", "token", "secret",
	"serv", "server", "host", "hosting", "vps",
	"db", "database", "sql", "mysql", "postgres",
	"cache", "cached", "memcache", "redis",
	"monitor", "mon", "metrics", "stats", "stat", "analytics",
	"log", "logs", "logging",
	"internal", "internal-", "int.", "intranet",
	"private", "private-",
	"local", "local-",
	"preview", "pre", "pre-",
	"sandbox", "sandbox-",
	"debug", "debug-",
	"counter", "track", "tracker", "pixel",
	"ads", "ad.", "adv", "ads.", "banner", "promo",
	"widgets", "widget",
	"embed", "embed-",
	"player", "player-",
	"stream", "stream-", "live", "live-",
	"video", "video-", "audio", "audio-",
	"media", "media-", "content", "content-",
	"avatar", "avatars", "avatar.", "avatars.",
	"userapi", "user-api",
	"sun1", "sun2", "sun3", "sun4", "sun5", "sun6", "sun7", "sun8", "sun9",
	"sun6-", "sun9-", "sun1-", "sun2-", "sun4-", "sun5-", "sun7-", "sun8-",
	"pp.", "pp-", "pp1", "pp2", "pp3",
}

// ============================================================================
// СТРУКТУРЫ ДАННЫХ
// ============================================================================

type SNIInfo struct {
	SNI          string    `json:"sni"`
	Count        int       `json:"count"`
	Alive        bool      `json:"alive"`
	HTTPStatus   int       `json:"http_status"`
	ResponseTime int       `json:"response_time"`
	Category     string    `json:"category"`
	IsRussian    bool      `json:"is_russian"`
	IsElite      bool      `json:"is_elite"`
	HasHTTPS     bool      `json:"has_https"`
	QualityScore int       `json:"quality_score"` // 0-100
	FirstSeen    time.Time `json:"first_seen"`
	LastChecked  time.Time `json:"last_checked"`
	Servers      []string  `json:"servers,omitempty"`
}

type Stats struct {
	TotalSNIs     int32
	DNSFailed     int32
	TCPFailed     int32
	TLSFailed     int32
	HTTPFailed    int32
	Blacklisted   int32
	Filtered      int32
	NotRU         int32
	Success       int32
	EliteFound    int32
}

// ============================================================================
// ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ
// ============================================================================

var (
	stats       Stats
	httpClient  *http.Client
	minCount    int
	checkTLS    bool
	checkHTTP   bool
	verbose     bool
	strictRU    bool  // Строгий режим - только .ru домены
)

// ============================================================================
// УТИЛИТЫ
// ============================================================================

func init() {
	httpClient = &http.Client{
		Timeout: HTTPRequestTimeout,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   ConnectTimeout,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   TLSHandshakeTimeout,
			ExpectContinueTimeout: 1 * time.Second,
			DisableKeepAlives:     true,
		},
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func uniqueStrings(s []string) []string {
	seen := make(map[string]bool)
	result := []string{}
	for _, v := range s {
		if v != "" && !seen[v] {
			seen[v] = true
			result = append(result, v)
		}
	}
	return result
}

func isIP(s string) bool {
	return net.ParseIP(s) != nil
}

func cleanSNI(sni string) string {
	sni = strings.TrimSpace(sni)
	sni = strings.TrimPrefix(sni, ".")
	sni = strings.ToLower(sni)
	if idx := strings.Index(sni, ":"); idx != -1 {
		sni = sni[:idx]
	}
	re := regexp.MustCompile(`[^\w\.\-].*$`)
	sni = re.ReplaceAllString(sni, "")
	return sni
}

// ============================================================================
// ПАРСИНГ SNI ИЗ КОНФИГОВ
// ============================================================================

var (
	vlessRegex      = regexp.MustCompile(`vless://[^@]+@[^?]+\?.*?sni=([^&@#\s]+)`)
	trojanRegex     = regexp.MustCompile(`trojan://[^@]+@[^?]+\?.*?sni=([^&@#\s]+)`)
	vmessHeader     = regexp.MustCompile(`vmess://`)
	sniParamRegex   = regexp.MustCompile(`sni=([^&@\s#]+)`)
	serverNameRegex = regexp.MustCompile(`"serverName"\s*:\s*"([^"]+)"`)
	domainInURL     = regexp.MustCompile(`@([^@:]+):(\d+)`)
)

func decodeBase64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	for len(s)%4 != 0 {
		s += "="
	}

	// Пробуем standard
	b, err := base64.StdEncoding.DecodeString(s)
	if err == nil {
		return b, nil
	}

	// Пробуем raw URL
	b, err = base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
	if err == nil {
		return b, nil
	}

	// Пробуем URL encoding
	b, err = base64.URLEncoding.DecodeString(s)
	if err == nil {
		return b, nil
	}

	return nil, fmt.Errorf("base64 decode failed")
}

func extractSNI(line string) []string {
	var snis []string
	line = strings.TrimSpace(line)

	if line == "" || strings.HasPrefix(line, "#") {
		return snis
	}

	// VLESS
	if strings.HasPrefix(line, "vless://") {
		matches := vlessRegex.FindStringSubmatch(line)
		if len(matches) > 1 {
			snis = append(snis, cleanSNI(matches[1]))
		}
		hostMatches := domainInURL.FindStringSubmatch(line)
		if len(hostMatches) > 1 {
			host := cleanSNI(hostMatches[1])
			if !isIP(host) && host != "" {
				snis = append(snis, host)
			}
		}
	}

	// Trojan
	if strings.HasPrefix(line, "trojan://") {
		matches := trojanRegex.FindStringSubmatch(line)
		if len(matches) > 1 {
			snis = append(snis, cleanSNI(matches[1]))
		}
	}

	// VMess (base64 JSON)
	if vmessHeader.MatchString(line) {
		encoded := strings.TrimPrefix(line, "vmess://")
		decoded, err := decodeBase64(encoded)
		if err == nil {
			var vmessConfig map[string]interface{}
			if json.Unmarshal(decoded, &vmessConfig) == nil {
				if sni, ok := vmessConfig["sni"].(string); ok {
					snis = append(snis, cleanSNI(sni))
				}
				if add, ok := vmessConfig["add"].(string); ok {
					if !isIP(add) {
						snis = append(snis, cleanSNI(add))
					}
				}
				if host, ok := vmessConfig["host"].(string); ok {
					snis = append(snis, cleanSNI(host))
				}
			}
		}
	}

	// Общий поиск sni= параметра
	matches := sniParamRegex.FindAllStringSubmatch(line, -1)
	for _, m := range matches {
		if len(m) > 1 {
			snis = append(snis, cleanSNI(m[1]))
		}
	}

	// JSON с serverName
	matches = serverNameRegex.FindAllStringSubmatch(line, -1)
	for _, m := range matches {
		if len(m) > 1 {
			snis = append(snis, cleanSNI(m[1]))
		}
	}

	return uniqueStrings(snis)
}

// ============================================================================
// ПРОВЕРКА SNI
// ============================================================================

func categorizeSNI(sni string) string {
	sniLower := strings.ToLower(sni)
	for category, patterns := range sniCategories {
		for _, pattern := range patterns {
			if strings.Contains(sniLower, strings.ToLower(pattern)) {
				return category
			}
		}
	}
	return "other"
}

func isRussianSNI(sni string) bool {
	sniLower := strings.ToLower(sni)

	// .ru и .рф - точно русские
	if strings.HasSuffix(sniLower, ".ru") || strings.HasSuffix(sniLower, ".рф") {
		return true
	}

	// Известные русские домены на других TLD
	ruPatterns := []string{
		"yandex", "vk.com", "vk.ru", "mail.ru", "ok.ru", "sber", "tbank", "tinkoff",
		"gosuslugi", "mos.ru", "nalog", "pochta", "rzd", "ozon", "wildberries",
		"avito", "dzen", "rutube", "kinopoisk", "hh.ru", "habr", "2gis",
		"mts", "megafon", "beeline", "tele2", "mvideo", "eldorado", "citilink",
		"dns-shop", "lamoda", "sportmaster", "leroymerlin", "petrovich",
		"alfabank", "vtb", "raiffeisen", "gazprombank", "rosbank",
		"rbc", "lenta", "kp.ru", "gazeta", "rambler",
		"ivi", "okko",
	}
	for _, pattern := range ruPatterns {
		if strings.Contains(sniLower, pattern) {
			return true
		}
	}
	return false
}

func isEliteSNI(sni string) bool {
	sniLower := strings.ToLower(sni)
	for _, elite := range eliteDomains {
		if sniLower == elite || strings.HasSuffix(sniLower, "."+elite) {
			return true
		}
	}
	return false
}

// isStrictRU - проверка на строго .ru домен
func isStrictRU(sni string) bool {
	sniLower := strings.ToLower(sni)
	return strings.HasSuffix(sniLower, ".ru") || strings.HasSuffix(sniLower, ".рф")
}

// isBlacklisted - проверка на мусор
func isBlacklisted(sni string) bool {
	sniLower := strings.ToLower(sni)

	for _, bl := range blacklistedSNI {
		blLower := strings.ToLower(bl)
		// Проверяем содержит ли SNI blacklist-паттерн
		if strings.Contains(sniLower, blLower) {
			return true
		}
	}
	return false
}

// hasSuspiciousSubdomain - проверка на технические поддомены
func hasSuspiciousSubdomain(sni string) bool {
	sniLower := strings.ToLower(sni)
	parts := strings.Split(sniLower, ".")

	if len(parts) < 2 {
		return false
	}

	subdomain := parts[0]

	// Проверяем поддомен на подозрительные паттерны
	for _, susp := range suspiciousSubdomains {
		suspLower := strings.ToLower(susp)
		if subdomain == suspLower {
			return true
		}
		// Проверяем начало поддомена
		if strings.HasSuffix(suspLower, "-") && strings.HasPrefix(subdomain, strings.TrimSuffix(suspLower, "-")) {
			return true
		}
		if strings.HasPrefix(suspLower, "-") && strings.HasSuffix(subdomain, strings.TrimPrefix(suspLower, "-")) {
			return true
		}
		if strings.HasSuffix(suspLower, ".") && strings.HasPrefix(subdomain, strings.TrimSuffix(suspLower, ".")) {
			return true
		}
	}

	// Много цифр в поддомене - подозрительно (cdh47dh3.domain.ru)
	digitCount := 0
	for _, c := range subdomain {
		if c >= '0' && c <= '9' {
			digitCount++
		}
	}
	if digitCount > 3 {
		return true
	}

	// Очень длинный поддомен (>25 символов) - подозрительно
	if len(subdomain) > 25 {
		return true
	}

	// Случайный набор букв (более 15 согласных подряд)
	consonants := 0
	for _, c := range subdomain {
		if c >= 'a' && c <= 'z' && !strings.ContainsRune("aeiou", c) {
			consonants++
			if consonants > 15 {
				return true
			}
		} else {
			consonants = 0
		}
	}

	return false
}

// calculateQualityScore - оценка качества SNI (0-100)
func calculateQualityScore(sni string, count int, isAlive bool) int {
	score := 0

	// Базовые баллы
	if isAlive {
		score += 20
	}

	// Русский домен
	if isRussianSNI(sni) {
		score += 30
	}

	// Строго .ru
	if isStrictRU(sni) {
		score += 10
	}

	// Элитный домен
	if isEliteSNI(sni) {
		score += 25
	}

	// Частота использования
	if count >= 5 {
		score += 10
	} else if count >= 3 {
		score += 5
	}

	// Короткий домен = лучше
	parts := strings.Split(sni, ".")
	if len(parts) == 2 {
		score += 5 // Второй уровень (domain.ru)
	}

	// Нет технических поддоменов
	if !hasSuspiciousSubdomain(sni) {
		score += 5
	}

	// Проверяем на категории
	category := categorizeSNI(sni)
	if category != "other" {
		score += 5
	}

	if score > 100 {
		score = 100
	}

	return score
}

func checkSNI(sni string) *SNIInfo {
	info := &SNIInfo{
		SNI:       sni,
		FirstSeen: time.Now(),
	}

	// 1. DNS
	ips, err := net.LookupHost(sni)
	if err != nil {
		atomic.AddInt32(&stats.DNSFailed, 1)
		return info
	}
	if len(ips) > 0 {
		info.Servers = ips[:minInt(5, len(ips))]
	}

	// 2. Категоризация
	info.Category = categorizeSNI(sni)
	info.IsRussian = isRussianSNI(sni)
	info.IsElite = isEliteSNI(sni)

	// 3. TCP
	ip := ips[0]
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, "443"), ConnectTimeout)
	if err != nil {
		atomic.AddInt32(&stats.TCPFailed, 1)
		return info
	}
	conn.Close()

	// 4. TLS
	if checkTLS {
		start := time.Now()
		tlsConn, err := tls.DialWithDialer(
			&net.Dialer{Timeout: ConnectTimeout},
			"tcp",
			net.JoinHostPort(ip, "443"),
			&tls.Config{
				ServerName:         sni,
				InsecureSkipVerify: false,
				MinVersion:         tls.VersionTLS12,
			},
		)
		if err != nil {
			atomic.AddInt32(&stats.TLSFailed, 1)
			return info
		}
		tlsConn.Close()
		info.ResponseTime = int(time.Since(start).Milliseconds())
	}

	// 5. HTTP
	if checkHTTP {
		start := time.Now()
		resp, err := httpClient.Get("https://" + sni + "/")
		if err != nil {
			atomic.AddInt32(&stats.HTTPFailed, 1)
			return info
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		info.HTTPStatus = resp.StatusCode
		info.HasHTTPS = true
		info.ResponseTime = int(time.Since(start).Milliseconds())
	}

	info.Alive = true
	info.LastChecked = time.Now()
	atomic.AddInt32(&stats.Success, 1)

	if info.IsElite {
		atomic.AddInt32(&stats.EliteFound, 1)
	}

	return info
}

// ============================================================================
// ЧТЕНИЕ ФАЙЛОВ
// ============================================================================

func parseInputFiles(files []string) map[string]int {
	sniCounts := make(map[string]int)

	for _, file := range files {
		f, err := os.Open(file)
		if err != nil {
			fmt.Printf("⚠️ Cannot open %s: %v\n", file, err)
			continue
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		lineNum := 0
		for scanner.Scan() {
			lineNum++
			line := scanner.Text()
			snis := extractSNI(line)
			for _, sni := range snis {
				if sni == "" || isIP(sni) {
					continue
				}

				// Фильтрация
				if isBlacklisted(sni) {
					atomic.AddInt32(&stats.Blacklisted, 1)
					continue
				}

				// Строгий режим - только .ru
				if strictRU && !isStrictRU(sni) {
					atomic.AddInt32(&stats.NotRU, 1)
					continue
				}

				// Подозрительные поддомены
				if hasSuspiciousSubdomain(sni) {
					atomic.AddInt32(&stats.Filtered, 1)
					continue
				}

				sniCounts[sni]++
			}
		}
		fmt.Printf("📄 %s: %d lines processed\n", file, lineNum)
	}

	return sniCounts
}

// ============================================================================
// WORKER POOL
// ============================================================================

func processSNIs(sniCounts map[string]int) []*SNIInfo {
	var wg sync.WaitGroup
	sniChan := make(chan string, len(sniCounts))
	resultChan := make(chan *SNIInfo, len(sniCounts))

	for i := 0; i < WorkerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for sni := range sniChan {
				info := checkSNI(sni)
				info.Count = sniCounts[sni]
				info.QualityScore = calculateQualityScore(sni, info.Count, info.Alive)
				resultChan <- info
				if verbose {
					status := "✅"
					if !info.Alive {
						status = "❌"
					}
					elite := ""
					if info.IsElite {
						elite = " ⭐ELITE"
					}
					fmt.Printf("  %s %s (score: %d, count: %d, cat: %s)%s\n",
						status, sni, info.QualityScore, info.Count, info.Category, elite)
				}
			}
		}()
	}

	for sni := range sniCounts {
		sniChan <- sni
	}
	close(sniChan)

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	var results []*SNIInfo
	for info := range resultChan {
		results = append(results, info)
		atomic.AddInt32(&stats.TotalSNIs, 1)
	}

	return results
}

// ============================================================================
// CT LOGS
// ============================================================================

func fetchFromCTLogs(domain string) ([]string, error) {
	apiURL := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)

	resp, err := httpClient.Get(apiURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var ctResults []struct {
		NameValue string `json:"name_value"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&ctResults); err != nil {
		return nil, err
	}

	var snis []string
	for _, r := range ctResults {
		for _, name := range strings.Split(r.NameValue, "\n") {
			name = strings.TrimSpace(name)
			name = cleanSNI(name)

			if name == "" || strings.HasPrefix(name, "*") {
				continue
			}

			// Фильтруем мусор
			if isBlacklisted(name) || hasSuspiciousSubdomain(name) {
				continue
			}

			// Строгий режим
			if strictRU && !isStrictRU(name) {
				continue
			}

			snis = append(snis, name)
		}
	}

	return uniqueStrings(snis), nil
}

// ============================================================================
// ВЫВОД
// ============================================================================

func saveResults(results []*SNIInfo, outputFile string) error {
	// Сортировка: сначала по качеству, потом по alive, потом по русскому
	sort.Slice(results, func(i, j int) bool {
		if results[i].QualityScore != results[j].QualityScore {
			return results[i].QualityScore > results[j].QualityScore
		}
		if results[i].Alive != results[j].Alive {
			return results[i].Alive
		}
		if results[i].IsRussian != results[j].IsRussian {
			return results[i].IsRussian
		}
		return results[i].Count > results[j].Count
	})

	os.MkdirAll(ResultsDir, 0755)

	// JSON
	jsonData, _ := json.MarshalIndent(results, "", "  ")
	jsonFile := ResultsDir + "/sni_full.json"
	os.WriteFile(jsonFile, jsonData, 0644)
	fmt.Printf("📄 Saved full JSON: %s\n", jsonFile)

	// ELITE SNI - только самые качественные (score >= 70)
	var eliteSNI []string
	for _, r := range results {
		if r.Alive && r.QualityScore >= 70 {
			eliteSNI = append(eliteSNI, r.SNI)
		}
	}
	eliteFile := ResultsDir + "/elite_sni.txt"
	os.WriteFile(eliteFile, []byte(strings.Join(eliteSNI, "\n")), 0644)
	fmt.Printf("⭐ Saved ELITE SNI: %s (%d SNIs, score >= 70)\n", eliteFile, len(eliteSNI))

	// PREMIUM SNI - качественные (score >= 50)
	var premiumSNI []string
	for _, r := range results {
		if r.Alive && r.QualityScore >= 50 {
			premiumSNI = append(premiumSNI, r.SNI)
		}
	}
	premiumFile := ResultsDir + "/premium_sni.txt"
	os.WriteFile(premiumFile, []byte(strings.Join(premiumSNI, "\n")), 0644)
	fmt.Printf("💎 Saved PREMIUM SNI: %s (%d SNIs, score >= 50)\n", premiumFile, len(premiumSNI))

	// RAW - ВСЕ найденные SNI
	var allRaw []string
	for _, r := range results {
		allRaw = append(allRaw, r.SNI)
	}
	rawFile := ResultsDir + "/sni_raw_all.txt"
	os.WriteFile(rawFile, []byte(strings.Join(allRaw, "\n")), 0644)
	fmt.Printf("📄 Saved RAW (all found): %s (%d SNIs)\n", rawFile, len(allRaw))

	// Whitelist RU (живые + RU + score >= 30)
	var whitelist []string
	var whitelistAll []string
	for _, r := range results {
		if r.Alive && r.Count >= minCount && r.QualityScore >= 30 {
			whitelistAll = append(whitelistAll, r.SNI)
			if r.IsRussian {
				whitelist = append(whitelist, r.SNI)
			}
		}
	}

	wlFile := ResultsDir + "/" + outputFile
	os.WriteFile(wlFile, []byte(strings.Join(whitelist, "\n")), 0644)
	fmt.Printf("📄 Saved RU whitelist: %s (%d SNIs)\n", wlFile, len(whitelist))

	wlAllFile := ResultsDir + "/whitelist_all.txt"
	os.WriteFile(wlAllFile, []byte(strings.Join(whitelistAll, "\n")), 0644)
	fmt.Printf("📄 Saved ALL whitelist: %s (%d SNIs)\n", wlAllFile, len(whitelistAll))

	// По категориям (только качественные)
	categories := make(map[string][]string)
	for _, r := range results {
		if r.Alive && r.QualityScore >= 40 {
			categories[r.Category] = append(categories[r.Category], r.SNI)
		}
	}
	for cat, snis := range categories {
		catFile := ResultsDir + "/sni_" + cat + ".txt"
		os.WriteFile(catFile, []byte(strings.Join(snis, "\n")), 0644)
		fmt.Printf("📄 Saved %s: %d SNIs\n", catFile, len(snis))
	}

	return nil
}

func printStats() {
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("📊 SNI SCAN STATISTICS:")
	fmt.Printf("   📥 Total SNI processed: %d\n", stats.TotalSNIs)
	fmt.Printf("   🚫 Blacklisted:         %d\n", stats.Blacklisted)
	fmt.Printf("   🌍 Not .RU (filtered):  %d\n", stats.NotRU)
	fmt.Printf("   🗑️  Suspicious (filtered): %d\n", stats.Filtered)
	fmt.Printf("   ❌ DNS failed:          %d\n", stats.DNSFailed)
	fmt.Printf("   ❌ TCP failed:          %d\n", stats.TCPFailed)
	fmt.Printf("   ❌ TLS failed:          %d\n", stats.TLSFailed)
	fmt.Printf("   ❌ HTTP failed:         %d\n", stats.HTTPFailed)
	fmt.Printf("   ✅ Alive:               %d\n", stats.Success)
	fmt.Printf("   ⭐ Elite found:         %d\n", stats.EliteFound)
	fmt.Println(strings.Repeat("=", 60))
}

// ============================================================================
// MAIN
// ============================================================================

func main() {
	fmt.Println("🦫 zhopa-bobra v2.0 - SNI Hunter for TSPU Whitelists")
	fmt.Println("   🔥 Enhanced filtering for CLEAN RU SNI")
	fmt.Println(strings.Repeat("=", 60))

	var inputFiles string
	var outputFile string
	var ctDomains string

	flag.StringVar(&inputFiles, "input", "", "Comma-separated input files")
	flag.StringVar(&outputFile, "output", "target_sni.txt", "Output whitelist file")
	flag.IntVar(&minCount, "min-count", 1, "Minimum usage count")
	flag.BoolVar(&checkTLS, "tls", true, "Check TLS handshake")
	flag.BoolVar(&checkHTTP, "http", true, "Check HTTP connectivity")
	flag.BoolVar(&verbose, "v", false, "Verbose output")
	flag.StringVar(&ctDomains, "ct", "", "Comma-separated domains for CT logs")
	flag.BoolVar(&strictRU, "strict-ru", true, "Strict mode: only .ru domains")
	flag.Parse()

	sniCounts := make(map[string]int)

	// Парсинг файлов
	if inputFiles != "" {
		fmt.Println("\n📂 Parsing input files...")
		files := strings.Split(inputFiles, ",")
		for i, f := range files {
			files[i] = strings.TrimSpace(f)
		}
		counts := parseInputFiles(files)
		for sni, count := range counts {
			sniCounts[sni] += count
		}
	}

	// CT Logs
	if ctDomains != "" {
		fmt.Println("\n🔍 Fetching from Certificate Transparency logs...")
		domains := strings.Split(ctDomains, ",")
		for _, domain := range domains {
			domain = strings.TrimSpace(domain)
			fmt.Printf("   📡 Scanning %s...\n", domain)
			snis, err := fetchFromCTLogs(domain)
			if err != nil {
				fmt.Printf("   ⚠️ Error: %v\n", err)
				continue
			}
			for _, sni := range snis {
				if !isBlacklisted(sni) {
					sniCounts[sni]++
				}
			}
			fmt.Printf("   ✅ Found %d subdomains\n", len(snis))
			time.Sleep(500 * time.Millisecond)
		}
	}

	if len(sniCounts) == 0 {
		fmt.Println("❌ No SNI found. Provide -input or -ct")
		os.Exit(1)
	}

	fmt.Printf("\n📋 Found %d unique SNI candidates (after filtering)\n", len(sniCounts))

	fmt.Println("\n🔍 Checking SNI liveness...")
	results := processSNIs(sniCounts)

	fmt.Println("\n💾 Saving results...")
	saveResults(results, outputFile)

	printStats()

	fmt.Println("\n📁 Output files:")
	fmt.Println("   ⭐ elite_sni.txt    - Best SNI (score >= 70)")
	fmt.Println("   💎 premium_sni.txt  - Good SNI (score >= 50)")
	fmt.Println("   📄 target_sni.txt   - RU whitelist (score >= 30)")
}
