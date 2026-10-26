# 🔌 SecurAI MCP Scanner

🇬🇧 [English README](README.md)


اسکنر امنیتی برای سرورهای **MCP** (Model Context Protocol) - همان پروتکلی که ابزارها را به ایجنت‌های AI (کلود، کورسر، ChatGPT با پلاگین و...) وصل می‌کند.

بخشی از **[مجموعه‌ی SecurAI](https://github.com/ElhamBidarigh/securai)** - عضوی از خانواده که لایه‌ی «ابزار/ایجنت» را پوشش می‌دهد، مکمل بقیه‌ی اعضا که روی کد اپ‌های تولیدشده با AI تمرکز دارند.

این ابزار سه لایه را بررسی می‌کند:

1. **پیکربندی سرور** (استاتیک، بدون نیاز به اتصال): تزریق دستور (command injection)، وابستگی‌های بدون نسخه‌ی ثابت، رمز عبور خام در فایل کانفیگ، دسترسی بیش‌ازحد به فایل‌سیستم، اتصال ناامن HTTP.
2. **توضیحات ابزارها (Tool Poisoning)**: بررسی متن `description` هر ابزار برای پیدا کردن دستورات مخفی prompt injection — همان چیزی که مدل می‌خواند ولی کاربر در رابط کاربری نمی‌بیند.
3. **رصد تغییرات (Rug Pull Detection)**: یک "بیس‌لاین" (baseline) از وضعیت فعلی سرور ذخیره می‌کند و در اسکن بعدی هر تغییر مشکوک را هشدار می‌دهد.

به‌صورت اختیاری می‌تواند به‌طور زنده (`--live`) به خود سرور وصل شود و لیست واقعی ابزارها را بگیرد، و می‌تواند از API آنتروپیک به‌عنوان یک لایه‌ی داوری معنایی برای کاهش false positive استفاده کند (`--llm-judge`).

بخش پایانی این فایل (پس‌از "نمونه گزارش") **قدم‌به‌قدم** توضیح می‌دهد چطور از این ابزار برای گرفتن مشتری واقعی استفاده کنی.

---

## نصب

```bash
cd securAI-mcp-scanner
python3 -m venv venv
source venv/bin/activate          # ویندوز: venv\Scripts\activate

# بخش اصلی هیچ وابستگی‌ای ندارد. برای ویژگی‌های اختیاری:
pip install -e ".[all]"           # هم --live هم --llm-judge
# یا جدا:
pip install -e ".[live]"          # فقط اتصال زنده به سرور
pip install -e ".[llm]"           # فقط داوری LLM
```

بعد از نصب، دستور `mcp-trust-scanner` در دسترس است. بدون نصب هم می‌شود مستقیم اجرا کرد:

```bash
python -m mcp_trust_scanner.cli scan <config.json>
```

## شروع سریع (۳۰ ثانیه)

```bash
python -m mcp_trust_scanner.cli scan examples/vulnerable_config.json
```

این دستور یک کانفیگ نمونه (که عمداً آسیب‌پذیر ساخته شده) را اسکن می‌کند و گزارش Markdown را مستقیم در ترمینال چاپ می‌کند.

## اسکن کانفیگ واقعی یک مشتری

فایل کانفیگ MCP معمولاً یکی از این مسیرهاست (بسته به کلاینت):

| کلاینت | مسیر فایل کانفیگ |
|---|---|
| Claude Desktop (مک) | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Claude Desktop (ویندوز) | `%APPDATA%\Claude\claude_desktop_config.json` |
| Claude Code | `.mcp.json` در ریشه‌ی پروژه، یا `~/.claude.json` |
| Cursor | `.cursor/mcp.json` در پروژه، یا تنظیمات سراسری |
| VS Code | `.vscode/mcp.json` |

```bash
python -m mcp_trust_scanner.cli scan "/path/to/claude_desktop_config.json" \
  --client-name "نام شرکت مشتری" \
  --consultant-name "Ellie Bidarigh" \
  --consultant-contact "elham.bidarigh@gmail.com" \
  --out report.md \
  --json-out report.json
```

خروجی: `report.md` (برای ارسال به مشتری) و `report.json` (اگر خواستی در ابزار دیگری پردازشش کنی یا در پایپ‌لاین CI بگذاری).

## اسکن زنده (--live)
اگر مشتری اجازه بدهد سرورهایش را واقعاً اجرا کنی (نه فقط فایل کانفیگش را بخوانی)، `--live` لیست واقعی و به‌روز ابزارها را از خود سرور می‌گیرد - چون بعضی سرورها ابزار را در فایل کانفیگ نمی‌نویسند و در زمان اجرا اعلام می‌کنند:
```bash
python -m mcp_trust_scanner.cli scan client_config.json --live --live-timeout 30
```

نیازمند `pip install mcp` است (در نصب `[live]`/`[all]` همراه است).

⚠️ فقط روی سرورهایی `--live` بزن که اجازه‌ی صریح داری اجرایشان کنی - این حالت واقعاً سرور را روشن می‌کند.
## داوری معنایی با LLM (--llm-judge)

لایه‌ی regex ممکن است گاهی متن بی‌گناه را هم پرچم بزند (false positive). این حالت هر توضیح ابزار را برای یک بار دیگر به مدل کلود می‌دهد تا نظر مستقل بدهد:

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
python -m mcp_trust_scanner.cli scan client_config.json --llm-judge
```

یا با `--api-key sk-ant-...` به‌جای متغیر محیطی.

## رصد Rug Pull با baseline (--pin)

اولین بار که یک سرور را برای مشتری اسکن و تأیید کردی:

```bash
python -m mcp_trust_scanner.cli scan client_config.json --pin --baseline-dir .mcp-trust/baselines
```

این وضعیت فعلی هر ابزار (نام + توضیح + اسکیمای ورودی، هش‌شده) را ذخیره می‌کند. دفعه‌ی بعد که همان کانفیگ را اسکن کنی (بدون `--pin`)، اگر توضیح یا اسکیمای یک ابزار **بی‌سروصدا** عوض شده باشد، یافته‌ی `DRIFT-003` با شدت Critical می‌گیری — دقیقاً همان چیزی که این حوزه به آن می‌گویند «rug pull».

پیشنهاد برای مشتری‌های دائمی: پوشه‌ی `.mcp-trust/baselines` را داخل گیت پروژه‌شان نگه دارند و این دستور را به‌صورت هفتگی یا در CI اجرا کنند:

```bash
python -m mcp_trust_scanner.cli scan client_config.json --fail-on high
```

`--fail-on high` باعث می‌شود دستور با کد خروجی غیرصفر تمام شود اگر یافته‌ای با شدت High یا بالاتر پیدا شود - یعنی می‌توانی این را در GitHub Actions بگذاری تا هر تغییر خطرناک در MCP جلوی merge را بگیرد.

## همه‌ی گزینه‌های خط فرمان

```
mcp-trust-scanner scan CONFIG.json
  --live                    اتصال زنده به سرورها برای گرفتن لیست واقعی ابزارها
  --live-timeout SECONDS    تایم‌اوت اتصال زنده (پیش‌فرض ۲۰)
  --llm-judge               داوری معنایی با Claude
  --api-key KEY             کلید Anthropic (یا متغیر ANTHROPIC_API_KEY)
  --baseline-dir DIR        مسیر ذخیره‌ی baseline (پیش‌فرض .mcp-trust/baselines)
  --pin                     ذخیره/به‌روزرسانی baseline بعد از این اسکن
  --no-drift-check          رد کردن مقایسه با baseline
  --out FILE.md             ذخیره‌ی گزارش Markdown
  --json-out FILE.json      ذخیره‌ی گزارش JSON
  --client-name NAME        نام مشتری در سربرگ گزارش
  --consultant-name NAME    نام تو در سربرگ گزارش
  --consultant-contact C    ایمیل/سایت تو در سربرگ گزارش
  --fail-on SEVERITY        خروج با کد غیرصفر اگر یافته‌ای در این حد یا بالاتر بود (برای CI)
  --quiet                   حذف خط خلاصه از stderr
```

## مجموعه‌ی کامل SecurAI

| ابزار | نوع | لینک |
|---|---|---|
| 🛡️ Audit Tool | خودارزیابی (مرورگر) | [نسخه‌ی زنده](https://elhambidarigh.github.io/securai/) |
| 🔬 Vuln Lab | آموزشی (PHP/MySQL) | [ریپو](https://github.com/ElhamBidarigh/securAI-vuln-lab) |
| 🔐 JWT Analyzer | CLI (پایتون) | [ریپو](https://github.com/ElhamBidarigh/jwt-analyzer) |
| 🔍 Active Scanner | اسکنر URL زنده (PHP) | [ریپو](https://github.com/ElhamBidarigh/securAI-active-scanner) |
| 🔌 MCP Scanner | CLI (پایتون) | همین‌جایی که هستی |

## ساختار پروژه

```
mcp_trust_scanner/
  config_parser.py    خواندن فایل‌های کانفیگ (Claude Desktop / Cursor / VS Code / لیست خام)
  static_checks.py     ۸ قانون بررسی پیکربندی (CFG-001 تا CFG-008)
  heuristics.py         ۷ قانون بررسی توضیح ابزار برای tool poisoning (TDX-001 تا TDX-007)
  live_connector.py     اتصال زنده stdio/http/sse با SDK رسمی mcp
  llm_judge.py           داوری معنایی با Anthropic API
  baseline.py            pin/diff برای تشخیص rug pull
  report.py              تولید گزارش Markdown و JSON
  cli.py                  رابط خط فرمان
examples/
  vulnerable_config.json  کانفیگ نمونه‌ی عمداً آسیب‌پذیر، برای دمو و تست
  sample_report.md        گزارش نمونه‌ی تولیدشده روی همان کانفیگ (برای نشان‌دادن به مشتری احتمالی)
  toy_server.py           یک سرور واقعی و کوچک MCP، فقط برای تست --live
```

هسته‌ی ابزار (`config_parser` + `static_checks` + `heuristics` + `report`) **هیچ وابستگی خارجی‌ای ندارد** — فقط پایتون استاندارد. یعنی می‌توانی همین را روی ماشین مشتری هم بدون نصب چیزی اجرا کنی، فقط `python3` لازم است.

---

