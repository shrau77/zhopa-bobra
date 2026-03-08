# 🦫 zhopa-bobra v2.0

**Автономный SNI Hunter для TSPU Whitelists с усиленной фильтрацией мусора**

Потому что никто не хочет лезть в жопу бобра. Теперь с ⭐ ELITE фильтрацией!

## 🔥 Что нового в v2.0

- **Усиленная фильтрация** - убираем 99% VPN/Proxy мусора
- **Quality Scoring** - каждый SNI получает оценку качества 0-100
- **Strict RU Mode** - режим только .ru доменов
- **Elite SNI** - файл с самыми качественными доменами (score >= 70)
- **Полная автономность** - работает месяцами без вмешательства
- **Публичные источники** - автоматически скачивает конфиги из GitHub

## 🎯 Что делает

1. **Извлекает SNI** из VPN конфигов (VLESS, Trojan, VMess)
2. **Фильтрует мусор** - VPN/Proxy домены, технические поддомены, подозрительные TLD
3. **Проверяет живучесть** (DNS → TCP → TLS → HTTP)
4. **Оценивает качество** - scoring по множеству критериев
5. **Классифицирует** по категориям (banks, ecommerce, social, government...)
6. **Генерирует whitelist** для обхода ТСПУ

## 📊 Выходные файлы

| Файл | Описание | Качество |
|------|----------|----------|
| `elite_sni.txt` | ⭐ Лучшие SNI | score >= 70 |
| `premium_sni.txt` | 💎 Хорошие SNI | score >= 50 |
| `target_sni.txt` | 📄 RU whitelist | score >= 30 |
| `whitelist_all.txt` | Все живые | score >= 30 |
| `sni_banks.txt` | Банки | - |
| `sni_ecommerce.txt` | E-commerce | - |
| `sni_social.txt` | Соцсети | - |
| `sni_government.txt` | Госучреждения | - |
| `sni_full.json` | Полный JSON | - |

## 🚀 Запуск (локально)

```bash
# Собрать
go build -o zhopa-bobra .

# Строгий режим (только .ru)
./zhopa-bobra -input configs.txt -strict-ru=true

# Мягкий режим (все домены, но с фильтрацией мусора)
./zhopa-bobra -input configs.txt -strict-ru=false

# CT Logs + конфиги
./zhopa-bobra -input proxies.txt -ct yandex.ru,sberbank.ru,vk.com

# Быстрый режим (без проверки HTTP)
./zhopa-bobra -input configs.txt -http=false

# Полный вывод
./zhopa-bobra -input proxies.txt -ct yandex.ru -output target_sni.txt -min-count 1 -v
```

## 📋 Флаги

| Флаг | Описание | По умолчанию |
|------|----------|--------------|
| `-input` | Файлы с конфигами (через запятую) | - |
| `-output` | Выходной файл whitelist | `target_sni.txt` |
| `-ct` | Домены для CT logs (через запятую) | - |
| `-min-count` | Мин. использований SNI | `1` |
| `-tls` | Проверять TLS handshake | `true` |
| `-http` | Проверять HTTP | `true` |
| `-strict-ru` | Только .ru домены | `true` |
| `-v` | Verbose вывод | `false` |

## 🤖 GitHub Actions - Автономный режим

### Автоматический запуск
- **Каждые 4 часа** - сканирование конфигов и CT Logs
- **Еженедельно** - глубокий скан всех крупных RU доменов
- Автоматически скачивает публичные конфиги из GitHub
- Автоматически коммитит результаты

### Источники данных
1. **Приватные репозитории** (если есть GTA_TOKEN):
   - `loshad-scoc` - проверенные RU конфиги
   - `hpp` - смешанные конфиги

2. **Публичные источники** (автоматически):
   - mahsan0/maHSan
   - yebekhe/TelegramV2rayCollector
   - и другие

### Ручной запуск
```yaml
workflow_dispatch:
  inputs:
    input_urls: "https://example.com/configs.txt"
    ct_domains: "yandex.ru,sberbank.ru,vk.com"
    min_count: "1"
    strict_ru: true
```

### Настройка секретов

Добавь в **Settings → Secrets and variables → Actions**:

| Secret | Описание |
|--------|----------|
| `GTA_TOKEN` | GitHub Personal Access Token с правами `repo` |

## 🔬 Как работает Quality Scoring

| Критерий | Баллы |
|----------|-------|
| SNI живой (alive) | +20 |
| Русский домен | +30 |
| Строго .ru/.рф | +10 |
| Элитный домен (sberbank, yandex, vk...) | +25 |
| Частота использования >= 5 | +10 |
| Короткий домен (domain.ru) | +5 |
| Без технических поддоменов | +5 |
| Известная категория | +5 |

**Максимум: 100 баллов**

## 🗑️ Фильтрация мусора

Автоматически отсеиваем:

### VPN/Proxy домены
- harknmav.fun, darknet.run, scroogethebest.com
- fonixapp.org, cowjuice.me, vles.space
- asbndx.com, nosok-top.com, vitalik.space
- И сотни других...

### Подозрительные TLD
- .ir, .cn, .pk, .xyz, .top, .click, .site
- .online, .shop, .icu, .win, .loan, .cfd, .sbs

### Технические поддомены
- api., static., cdn., edge., node.
- test., demo., dev., staging., beta.
- vpn., proxy., tunnel.
- И многие другие...

### Подозрительные паттерны
- Много цифр в поддомене (cdh47dh3.domain.ru)
- Очень длинные поддомены (>25 символов)
- Случайные наборы букв

## 📈 Пример вывода

```
🦫 zhopa-bobra v2.0 - SNI Hunter for TSPU Whitelists
   🔥 Enhanced filtering for CLEAN RU SNI
============================================================

📂 Parsing input files...
📄 configs.txt: 5000 lines processed

📋 Found 234 unique SNI candidates (after filtering)

🔍 Checking SNI liveness...
  ✅ sberbank.ru (score: 95, count: 45, cat: banks) ⭐ELITE
  ✅ yandex.ru (score: 95, count: 32, cat: ecommerce) ⭐ELITE
  ✅ vk.com (score: 85, count: 28, cat: social) ⭐ELITE
  ✅ mail.ru (score: 80, count: 15, cat: social)
  ❌ dead-domain.ru (score: 30, count: 1, cat: other)

💾 Saving results...
⭐ Saved ELITE SNI: results/elite_sni.txt (156 SNIs, score >= 70)
💎 Saved PREMIUM SNI: results/premium_sni.txt (234 SNIs, score >= 50)
📄 Saved RU whitelist: results/target_sni.txt (312 SNIs)

============================================================
📊 SNI SCAN STATISTICS:
   📥 Total SNI processed: 500
   🚫 Blacklisted:         3200
   🌍 Not .RU (filtered):  850
   🗑️  Suspicious (filtered): 450
   ❌ DNS failed:          45
   ❌ TCP failed:          23
   ❌ TLS failed:          12
   ❌ HTTP failed:         38
   ✅ Alive:               382
   ⭐ Elite found:         156
============================================================

📁 Output files:
   ⭐ elite_sni.txt    - Best SNI (score >= 70)
   💎 premium_sni.txt  - Good SNI (score >= 50)
   📄 target_sni.txt   - RU whitelist (score >= 30)
```

## 🔗 Интеграция с пайплайном

```bash
# После работы scout
./zhopa-bobra -input ../loshad-scoc/verified_ru.txt -strict-ru=true

# После работы hpp
./zhopa-bobra -input ../hpp/output/all_mixed.txt -strict-ru=true

# Обновить whitelist для node-filter
./zhopa-bobra -input proxies.txt -output ../node-filter/whitelists.txt
```

## ⚠️ Рекомендации по использованию

### Для ТСПУ (РФ)
1. Используй `elite_sni.txt` - самые надёжные
2. Если нужно больше - `premium_sni.txt`
3. `target_sni.txt` - расширенный список

### Категории
- **sni_banks.txt** - для финансовых операций
- **sni_government.txt** - для госуслуг
- **sni_ecommerce.txt** - для маркетплейсов

## 📊 Статистика

Средний результат за один запуск:
- Обработано: 10,000+ конфигов
- Отфильтровано мусора: ~80%
- Найдено живых SNI: 200-500
- Elite SNI: 50-150

---

*🦫 Не лезь в жопу бобра - пусть он сам найдёт тебе чистые SNI*
