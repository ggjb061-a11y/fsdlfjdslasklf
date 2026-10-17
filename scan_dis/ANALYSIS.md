# تحليل أداة AutoVulnScan (autoscan) — تقرير مراجعة وPoC

**النطاق:** مستودع `ggjb061-a11y/fsdlfjdslasklf` (الفرع `claude/affectionate-bell-5mcmj3`)، الإصدار 4.4.0 حسب آخر commit.
**الحالة:** تحليل ثابت للكود + PoC قابلة للتشغيل. لم يُعدَّل أي ملف داخل `scanner/`.

---

## 0. ملاحظة عن الملف الخارجي (gofile)

رابط `https://gofile.io/d/iXtkFALk` **غير قابل للوصول** من هذه الجلسة: بوابة الخروج (egress proxy) ترفض `gofile.io` و`api.gofile.io` بسبب سياسة الشبكة في البيئة (`connect_rejected`).
لم أتجاوز هذه السياسة. لتفعيل التحميل يحتاج صاحب البيئة إلى إضافة النطاقين في **Allowed domains** من إعدادات البيئة، أو رفع الملف مباشرة إلى المحادثة/المستودع.

لذلك التحليل أدناه مبني على **الكود الموجود في المستودع** (أداة autoscan). لم أتحقق من أن محتوى الرابط نفس هذه النسخة.

---

## 1. ماذا تفعل الأداة؟

أداة أتمتة لفحص الأمن (Recon → Vulnerability Scanning → Report) مخصصة للاختبار المصرّح به فقط. تعمل كغلاف (wrapper) فوق أدوات خارجية مثل `subfinder`, `httpx`, `nuclei`, `sqlmap`, `nmap`, مع فحوصات مدمجة بلغة Python.

### خط المعالجة (8 مراحل)

| المرحلة | الوحدة | ما تفعله |
|---|---|---|
| 1 | `recon.py`, `recon_extended.py`, `recon_sources/` | النطاقات الفرعية، DNS/AXFR، crt.sh وغيرها، port scan، WAF |
| 2 | `passive.py` | robots/sitemap، كشف CMS، ملفات حساسة (.env, .git…)، إيميلات |
| 3 | `crawler.py` | جمع الروابط من gau/wayback/katana/gospider + fallback بـ curl |
| 4 | `js_analyzer.py` | 22 نمط regex لأسرار JS + استخراج endpoints |
| 5 | `params.py` | اكتشاف المعاملات (arjun/paramspider + canary) |
| 6 | `http_methods.py` | اختبار 9 methods، تعليم PUT/DELETE/TRACE |
| 7 | `vulnscan.py` → `checks/` | **42 فحصاً** (`ALL_CHECKS`) + مجلد `checks/cves/` لكشف CVEs |
| 8 | `reporter.py`, `output/` | تقارير HTML / JSON / Markdown / SARIF / CSV |

### ملفات الأساس
- `autoscan.py` — CLI والتنسيق بين المراحل (`scan_target`) والـ resume والـ diff وبوابة `--fail-on`.
- `scanner/utils.py` — **كل** استدعاءات الشبكة تمر من `run()`، وفيها تُضاف هيدرات المصادقة وحد حجم الاستجابة وحد عدد redirects.
- `scanner/validators.py` — التحقق من الهدف (target) وعنوان الـ webhook.
- `scanner/checks/base.py` — `BaseCheck`، كل فحص يرث منه ويستخدم `_fetch`/`_post`.
- `scanner/checkpoint.py` — حفظ الحالة بعد كل مرحلة (`.checkpoint.json`).
- `tests/` — 259 اختبار، **كلها تمر** (`python3 -m pytest tests`).

### نقاط قوة ملاحظة
- التنفيذ عبر قائمة argv بدون `shell=True`، ولا يوجد `eval`/`exec`/`pickle`/`yaml.load` على بيانات خارجية.
- قالب HTML يستخدم Jinja2 مع `autoescape=True`، وتُفلتر روابط `javascript:`/`data:`.
- CSV يستخدم `QUOTE_ALL`، وتوجد حماية من CSV injection.
- تحقق الهدف يرفض `-` في البداية والمحارف الخاصة بالـ shell.
- Webhook: http/https فقط، بدون userinfo، ويمنع العناوين الخاصة.
- `--max-filesize` و`--max-redirs` مفعّلان على كل curl.
- `_redact_argv` يخفي الهيدرات الحساسة من سجلات الأخطاء.
- إنشاء المجلدات يعقّم اسم الهدف من أحرف المسار.

---

## 2. النتائج (Findings)

| ID | الشدة | العنوان | الحالة في PoC |
|---|---|---|---|
| **F-01** | **High** | تسريب Bearer token وCookie الخاصين بالهدف إلى خدمات OSINT طرف ثالث | **مُثبَت** — `poc_03` |
| **F-02** | Medium (وظيفي) | `--resume` يفشل دائماً مع أي نطاق يحتوي نقطة | **مُثبَت** — `poc_01` |
| **F-03** | Low (كامن) | `curl -d "@file"` يقرأ ملفاً محلياً ويرسله إلى الهدف | **مُثبَت** — `poc_02` |
| **F-04** | Info / Design risk | TLS verification معطّل دائماً (`-k`) | مؤكد بالقراءة (لا PoC) |

### F-01 — تسريب بيانات اعتماد الهدف إلى أطراف ثالثة (High)

**السبب:** `scanner/utils.py:102-113` — `run()` تضيف `Authorization` و`Cookie` و`-u` إلى **كل** أمر `curl`، لا لطلبات الهدف فقط.
**أين يتعدى ذلك الحد:** `scanner/recon_sources/_helpers.py` (`http_get_text` / `http_get_json`) يستدعي `run()`. مصادر crt.sh وhackertarget وrapiddns وurlscan وغيرها تمر من هنا. كذلك `checks/s3_buckets.py` وعدة فحوصات أخرى تستدعي `run(["curl", ...])`.
**Webhook:** `autoscan.py:283` (`send_webhook`) يستدعي `run(["curl", ...])` أيضاً، فيُرسل توكن الهدف إلى Slack/Discord المحدد. لم أُثبِت هذا المسار بـ PoC لأن `validate_webhook_url` يمنع العناوين المحلية، لكنه يستخدم الآلية نفسها.

**الأثر:** مستخدم يشغّل `--bearer` أو `--cookie` على تطبيق داخلي، يُسرّب التوكن إلى خدمات عامة لا تحتاجه. وإذا كان التوكن ذا صلاحيات، يصبح تسريباً لبيانات اعتماد حقيقية.

**إثبات:** `poc_03` — الخادم الذي يحاكي الطرف الثالث استقبل:
```
Authorization: Bearer TARGET-BEARER-TOKEN-9c1e
Cookie: session=TARGET-SESSION-COOKIE-4b2d
```

**الإصلاح المقترح:** تمرير هيدرات المصادقة فقط للطلبات الموجهة إلى الهدف. مثلاً إضافة معامل `auth=True` إلى `run()` أو فصل دالة `run_target_curl()` عن دالة `run_external_curl()`، وجعل `recon_sources` و`send_webhook` يستخدمان الثانية.

---

### F-02 — `--resume` لا يعمل لأي نطاق فيه نقطة (Medium، وظيفي)

**السبب:** ثلاث حلقات تتفاعل معاً:
1. `scanner/utils.py:185-186` — `create_dirs()` يحوّل `example.com` إلى المجلد `example_com`.
2. `autoscan.py:515-516` — `--resume` يستخرج اسم الهدف من مسار المجلد (`parts[-2]`) فيصبح `example_com`.
3. `scanner/validators.py:14` — `_HOSTNAME_RE` لا يسمح بالشرطة السفلية `_`، فيرفض `scan_target()` الاسم في أول سطر.

**النتيجة:** `autoscan.py:535` يلتقط الاستثناء ويطبع `Resumed target failed`، فيفشل الاستئناف لكل هدف فيه نقطة، أي تقريباً كل النطاقات.

**إثبات:** `poc_01` — `scan_target('example_com')` يرفع `ValidationError: not a valid hostname or IP: 'example_com'`، بينما `validate_target('example.com')` ينجح.

**الإصلاح المقترح:** إما حفظ الهدف الأصلي داخل `.checkpoint.json` واستخدامه عند `--resume`، أو عكس التعقيم عند الاستئناف. الأولى أسلم، لأن التعقيم قد يكون غير قابل للعكس (مثلاً `a.b` و`a_b` يصبحان المجلد نفسه).

**ملاحظة:** الاختبارات الـ259 تمر ولم تلتقط هذا، لذلك لا يوجد اختبار `resume` لنطاق بنقطة.

---

### F-03 — `curl -d "@file"` يقرأ ملفات محلية (Low، كامن)

**السبب:** `scanner/checks/base.py:83` — `args += ["-d", data]`. أي نص يبدأ بـ `@` يعامله curl كمسار ملف يُقرأ محتواه ويُرسل كجسم الطلب.

**الأثر الفعلي الحالي:** **كامن**. الاستدعاء الوحيد لـ `BaseCheck._post` لا يمرّر نصاً من الهدف. `form_fuzzer.py:40-47` يُرمّز القيم بـ `urllib.parse.quote` فيُحوَّل `@` إلى `%40`، فلا يبدأ الجسم بـ `@` أبداً. لكن أي فحص مستقبلي يمرّر بيانات خام من الهدف يصبح ثغرة قراءة ملفات محلية.

**إثبات:** `poc_02` — `_post(url, data="@/tmp/.../local_secret.txt")` أرسل محتوى الملف إلى الخادم.

**الإصلاح المقترح:** استخدام `--data-raw` بدل `-d`، فهو لا يفسّر `@`. ويمكن كذلك إرسال الجسم عبر `stdin_data` مع `--data-binary @-`.

---

### F-04 — TLS verification معطّل دائماً (Info، تصميمي)

`scanner/checks/base.py:70,122,157` تضع `insecure=True` في كل الفحوص، فتُضاف `-k` لكل طلب. `cves/base.py:72` يستخدم `-sk` بشكل ثابت.

هذا قرار مقصود لأن أهداف الفحص غالباً شهادتها غير صحيحة، لكنه يعني أن أي MITM يستطيع قراءة توكنات المصادقة (F-01 يزيد الأثر) أو تزوير نتائج الفحص. يُنصح بخيار `--verify-tls` افتراضياً `off` مع تحذير واضح.

---

## 3. ما لم أتحقق منه

- لم أفحص كل الـ42 فحصاً سطراً بسطر. ركّزت على طبقة الشبكة والمدخلات والتقارير، لأنها الأكثر تأثيراً.
- لم أشغّل الأدوات الخارجية (nuclei/sqlmap/…)، لأنها غير مثبتة هنا وتحتاج أهدافاً مصرّحاً بها.
- لم أتحقق من محتوى رابط gofile (انظر القسم 0).
- لم أُنشئ PR ولم أعمل commit؛ الملفات الجديدة غير متتبّعة (`?? scan_dis/`).

---

## 4. تشغيل PoC

```bash
python3 scan_dis/poc/run_all.py
```

النتيجة الحالية:
```
[CONFIRMED] PoC-01: --resume rejects every dotted domain
[CONFIRMED] PoC-02: curl -d '@file' reads local files into POST bodies
[CONFIRMED] PoC-03: target Bearer token and Cookie leak to third-party recon APIs
3/3 PoCs reproduced
```

كل PoC يعمل على `127.0.0.1` فقط، ولا يتصل بأي هدف حقيقي أو خدمة خارجية.
