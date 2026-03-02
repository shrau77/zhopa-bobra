# 🦫 zhopa-bobra

SNI Hunter for TSPU Whitelists. Потому что никто не хочет лезть в жопу бобра.

## 🎯 Что делает

1. **Извлекает SNI** из VPN конфигов (VLESS, Trojan, VMess)
2. **Проверяет живучесть** (DNS → TCP → TLS → HTTP)
3. **Классифицирует** по категориям (banks, ecommerce, social, government...)
4. **Генерирует whitelist** для обхода ТСПУ
5. **CT Logs** - ищет поддомены через Certificate Transparency

## 🚀 Запуск (локально)

```bash
# Собрать
go build -o zhopa-bobra .

# Из файлов с конфигами
./zhopa-bobra -input verified_ru.txt,output/all_mixed.txt

# Из Certificate Transparency логов
./zhopa-bobra -ct yandex.ru,sberbank.ru,vk.com

# Всё вместе
./zhopa-bobra -input proxies.txt -ct yandex.ru -output target_sni.txt -min-count 2 -v
```

## 📋 Флаги

| Флаг | Описание | По умолчанию |
|------|----------|--------------|
| `-input` | Файлы с конфигами (через запятую) | - |
| `-output` | Выходной файл whitelist | `target_sni.txt` |
| `-ct` | Домены для CT logs (через запятую) | - |
| `-min-count` | Мин. использований SNI | `2` |
| `-tls` | Проверять TLS handshake | `true` |
| `-http` | Проверять HTTP | `true` |
| `-v` | Verbose вывод | `false` |

## 🤖 GitHub Actions

### Автоматический запуск
- Каждые 6 часов
- Берёт конфиги из `loshad-scoc` и `hpp`
- CT Logs для основных RU доменов

### Ручной запуск
```yaml
workflow_dispatch:
  inputs:
    input_urls: "https://example.com/configs.txt,https://..."
    ct_domains: "yandex.ru,sberbank.ru,vk.com"
    min_count: "1"
    check_tls: true
    check_http: true
```

### Настройка секретов

Добавь в **Settings → Secrets and variables → Actions**:

| Secret | Описание |
|--------|----------|
| `GTA_TOKEN` | GitHub Personal Access Token с правами `repo` |

GTA_TOKEN нужен для:
- Клонирования приватных реп с конфигами
- Доступа к loshad-scoc, hpp

## 📁 Результаты

```
results/
├── sni_raw_all.txt       # 🆕 ВСЕ найденные SNI (до кучи)
├── sni_full.json         # Полный JSON со всеми данными
├── target_sni.txt        # RU whitelist (живые)
├── whitelist_all.txt     # Все живые SNI
├── sni_banks.txt         # Банки
├── sni_ecommerce.txt     # E-commerce
├── sni_social.txt        # Соцсети
├── sni_government.txt    # Госучреждения
├── sni_tech.txt          # Технологии
├── sni_mobile.txt        # Мобильные операторы
└── sni_cloud.txt         # Облака
```

## 🔬 Как работает проверка

1. **DNS** - резолвим домен
2. **TCP** - коннект на порт 443
3. **TLS** - handshake с SNI
4. **HTTP** - GET запрос на https://sni/

Если все этапы прошли - SNI считается живым.

## 📊 Категории SNI

| Категория | Примеры |
|-----------|---------|
| banks | sberbank.ru, tinkoff.ru, alfabank.ru, vtbe.ru |
| ecommerce | ozon.ru, wildberries.ru, yandex.ru, avito.ru |
| social | vk.com, ok.ru, mail.ru, dzen.ru |
| government | gosuslugi.ru, mos.ru, nalog.ru, rzd.ru |
| tech | hh.ru, habr.ru, 2gis.ru, kinopoisk.ru |
| mobile | mts.ru, megafon.ru, beeline.ru, tele2.ru |
| cloud | yandexcloud.net, sbercloud.ru, selectel.ru |

## 🎲 Источники SNI

1. **Конфиги** - парсим VLESS/Trojan/VMess ссылки
2. **CT Logs** - crt.sh API для поиска поддоменов
3. **Частота** - SNI используемый ≥N раз = надёжный кандидат

## ⚠️ Blacklist

Автоматически отсеиваем:
- Google, YouTube, Facebook, etc
- .ir, .cn, .pk домены
- Cloudflare, AWS, Azure
- VPN/Proxy-related домены

## 🔗 Интеграция с пайплайном

```bash
# После работы scout
./zhopa-bobra -input ../loshad-scoc/verified_ru.txt

# После работы hpp  
./zhopa-bobra -input ../hpp/output/all_mixed.txt,../hpp/output/ultra_elite.txt

# Обновить whitelist для node-filter
./zhopa-bobra -input proxies.txt -output ../node-filter/whitelists.txt
```

## 📈 Пример вывода

```
🦫 zhopa-bobra - SNI Hunter for TSPU Whitelists
==================================================

📂 Parsing input files...
📄 verified_ru.txt: 1523 lines processed

📋 Found 847 unique SNI candidates

🔍 Checking SNI liveness...
  ✅ st.ozone.ru (count: 45, cat: ecommerce)
  ✅ api.sberbank.ru (count: 32, cat: banks)
  ❌ some-dead-domain.com (count: 1, cat: other)
  ...

💾 Saving results...
📄 Saved RAW (all found): results/sni_raw_all.txt (847 SNIs)
📄 Saved RU whitelist: results/target_sni.txt (234 SNIs)
📄 Saved ALL whitelist: results/whitelist_all.txt (312 SNIs)
📄 Saved sni_banks.txt: 45 SNIs
📄 Saved sni_ecommerce.txt: 67 SNIs

==================================================
📊 SNI SCAN STATISTICS:
   📥 Total SNI found:    847
   ❌ DNS failed:         123
   ❌ TCP failed:         89
   ❌ TLS failed:         45
   ❌ HTTP failed:        78
   ✅ Alive:              512
==================================================
```

---

*🦫 Не лезь в жопу бобра*
