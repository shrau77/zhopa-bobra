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

// Чёрный список SNI (мусор)
var blacklistedSNI = []string{
        // Big Tech
        "google.com", "youtube.com", "facebook.com", "instagram.com", "twitter.com",
        "cloudflare.com", "amazon.com", "microsoft.com", "apple.com", "github.com",
        "chatgpt.com", "openai.com",
        
        // Adult/Gambling
        "pornhub", "xvideos", "bet", "casino", "gambling",
        
        // Suspicious TLDs
        ".ir", ".cn", ".pk", ".af", ".sy", ".sa", ".vn", ".id", ".br",
        ".su", ".xyz", ".top", ".click", ".site", ".online", ".shop", ".icu",
        ".win", ".loan", ".trade", ".science", ".work", ".party", ".rugby",
        
        // VPN/Proxy services
        "vpn", "proxy", "tunnel", "v2ray", "xray", "shadowsocks", "trojan",
        "outline", "clash", "sing-box", "nekoray", "vless",
        "invisevps", "firstvds", "ultimateserv", "suio.me", "smarteracloud",
        "outlinekeys", "jugsenkeys", "fasssst", "privetnet", "shadow-net",
        "resetnet", "allonetworks", "normbot", "kopobkatopta",
        
        // Hosting/CDN
        "cdn.stun", "cdnvideo", "cdnv-img", "cdns.su", "msemse.ru",
        "lagzero", "quattro-tech", "jojack.ru", "serverstats",
        "hb-by3", "pkvc-hls4", "nlcdn",
        
        // Cloud platforms
        "worker", "pages.dev", "herokuapp", "workers.dev", "vercel.app",
        "netlify.app", "railway.app", "render.com",
        
        // Local/Private
        "localhost", "127.0.0.1", "0.0.0.0",
        
        // Analytics/Ads
        "doubleclick", "adservice", "analytics", "cdnjs", "fonts.googleapis",
        "counter.yadro", "ad.mail.ru",
        
        // Other trash
        "fuck.rkn", ".ir", "arvancloud", "derp",
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
        HasHTTPS     bool      `json:"has_https"`
        FirstSeen    time.Time `json:"first_seen"`
        LastChecked  time.Time `json:"last_checked"`
        Servers      []string  `json:"servers,omitempty"`
}

type Stats struct {
        TotalSNIs   int32
        DNSFailed   int32
        TCPFailed   int32
        TLSFailed   int32
        HTTPFailed  int32
        Blacklisted int32
        Filtered    int32  // Отфильтровано как мусор
        Success     int32
}

// ============================================================================
// ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ
// ============================================================================

var (
        stats      Stats
        httpClient *http.Client
        minCount   int
        checkTLS   bool
        checkHTTP  bool
        verbose    bool
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
        if strings.HasSuffix(sniLower, ".ru") ||
                strings.HasSuffix(sniLower, ".рф") {
                return true
        }
        ruPatterns := []string{
                "yandex", "vk.com", "mail.ru", "ok.ru", "sber", "tbank", "tinkoff",
                "gosuslugi", "mos.ru", "nalog", "pochta", "rzd", "ozon", "wildberries",
                "avito", "dzen", "rutube", "kinopoisk", "hh.ru", "habr", "2gis",
                "mts", "megafon", "beeline", "tele2", "mvideo", "eldorado", "citilink",
                "dns-shop", "lamoda", "sportmaster", "leroymerlin", "petrovich",
                "alfabank", "vtb", "raiffeisen", "gazprombank", "rosbank",
        }
        for _, pattern := range ruPatterns {
                if strings.Contains(sniLower, pattern) {
                        return true
                }
        }
        return false
}

// isSuspiciousDomain - проверка на подозрительные паттерны
func isSuspiciousDomain(sni string) bool {
        sniLower := strings.ToLower(sni)
        
        // Подозрительные слова
        suspiciousWords := []string{
                "key", "keys4pay", "keys", "pass", "passwd", "password",
                "serv", "server", "vps", "host", "hosting",
                "cdn", "edge", "node", "relay",
                "test", "demo", "dev", "staging",
                "random", "temp", "tmp",
        }
        for _, word := range suspiciousWords {
                if strings.Contains(sniLower, word) {
                        return true
                }
        }
        
        // Много цифр в поддомене (cdh47dh3.domain.ru)
        parts := strings.Split(sni, ".")
        if len(parts) > 0 {
                subdomain := parts[0]
                digitCount := 0
                for _, c := range subdomain {
                        if c >= '0' && c <= '9' {
                                digitCount++
                        }
                }
                // Если больше 3 цифр в поддомене - подозрительно
                if digitCount > 3 {
                        return true
                }
        }
        
        // Очень длинный поддомен (>20 символов)
        if len(parts) > 0 && len(parts[0]) > 20 {
                return true
        }
        
        return false
}

func isBlacklisted(sni string) bool {
        sniLower := strings.ToLower(sni)
        for _, bl := range blacklistedSNI {
                if strings.Contains(sniLower, strings.ToLower(bl)) {
                        return true
                }
        }
        return false
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
                                if isSuspiciousDomain(sni) {
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
                                resultChan <- info
                                if verbose {
                                        status := "✅"
                                        if !info.Alive {
                                                status = "❌"
                                        }
                                        fmt.Printf("  %s %s (count: %d, cat: %s)\n", status, sni, info.Count, info.Category)
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
                        // Фильтруем: не wildcard, не blacklist, не подозрительный
                        if name != "" && !strings.HasPrefix(name, "*") && !isBlacklisted(name) && !isSuspiciousDomain(name) {
                                snis = append(snis, name)
                        }
                }
        }

        return uniqueStrings(snis), nil
}

// ============================================================================
// ВЫВОД
// ============================================================================

func saveResults(results []*SNIInfo, outputFile string) error {
        sort.Slice(results, func(i, j int) bool {
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

        // RAW - ВСЕ найденные SNI без фильтрации (до кучи)
        var allRaw []string
        for _, r := range results {
                allRaw = append(allRaw, r.SNI)
        }
        rawFile := ResultsDir + "/sni_raw_all.txt"
        os.WriteFile(rawFile, []byte(strings.Join(allRaw, "\n")), 0644)
        fmt.Printf("📄 Saved RAW (all found): %s (%d SNIs)\n", rawFile, len(allRaw))

        // Whitelist RU (живые + RU)
        var whitelist []string
        var whitelistAll []string
        for _, r := range results {
                if r.Alive && r.Count >= minCount {
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

        // По категориям
        categories := make(map[string][]string)
        for _, r := range results {
                if r.Alive && r.Count >= minCount {
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
        fmt.Println("\n" + strings.Repeat("=", 50))
        fmt.Println("📊 SNI SCAN STATISTICS:")
        fmt.Printf("   📥 Total SNI found:    %d\n", stats.TotalSNIs)
        fmt.Printf("   🚫 Blacklisted:        %d\n", stats.Blacklisted)
        fmt.Printf("   🗑️  Filtered (trash):    %d\n", stats.Filtered)
        fmt.Printf("   ❌ DNS failed:         %d\n", stats.DNSFailed)
        fmt.Printf("   ❌ TCP failed:         %d\n", stats.TCPFailed)
        fmt.Printf("   ❌ TLS failed:         %d\n", stats.TLSFailed)
        fmt.Printf("   ❌ HTTP failed:        %d\n", stats.HTTPFailed)
        fmt.Printf("   ✅ Alive:              %d\n", stats.Success)
        fmt.Println(strings.Repeat("=", 50))
}

// ============================================================================
// MAIN
// ============================================================================

func main() {
        fmt.Println("🦫 zhopa-bobra - SNI Hunter for TSPU Whitelists")
        fmt.Println(strings.Repeat("=", 50))

        var inputFiles string
        var outputFile string
        var ctDomains string

        flag.StringVar(&inputFiles, "input", "", "Comma-separated input files")
        flag.StringVar(&outputFile, "output", "target_sni.txt", "Output whitelist file")
        flag.IntVar(&minCount, "min-count", 2, "Minimum usage count")
        flag.BoolVar(&checkTLS, "tls", true, "Check TLS handshake")
        flag.BoolVar(&checkHTTP, "http", true, "Check HTTP connectivity")
        flag.BoolVar(&verbose, "v", false, "Verbose output")
        flag.StringVar(&ctDomains, "ct", "", "Comma-separated domains for CT logs")
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

        fmt.Printf("\n📋 Found %d unique SNI candidates\n", len(sniCounts))

        fmt.Println("\n🔍 Checking SNI liveness...")
        results := processSNIs(sniCounts)

        fmt.Println("\n💾 Saving results...")
        saveResults(results, outputFile)

        printStats()
}
