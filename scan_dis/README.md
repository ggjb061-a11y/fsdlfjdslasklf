# scan_dis

مجلد منفصل لتحليل أداة `autoscan` (AutoVulnScan) ونتائج مراجعتها. لم يُدمج في `scanner/` ولم يُعدَّل أي ملف فيه.

```
scan_dis/
├── README.md              ← هذا الملف
├── ANALYSIS.md            ← التقرير الكامل (المعمارية، النتائج، الإصلاحات المقترحة)
└── poc/
    ├── _common.py         ← خادم stub محلي (127.0.0.1) ومساعدات مشتركة
    ├── poc_01_resume_dotted_domain.py
    ├── poc_02_curl_data_at_file.py
    ├── poc_03_auth_leak_third_party.py
    └── run_all.py         ← يشغّل الكل ويطبع الملخص
```

## التشغيل

من جذر المستودع:

```bash
python3 scan_dis/poc/run_all.py
```

المتطلبات: Python 3.10+ والـ `curl` في PATH. لا تحتاج إلى حزم إضافية.

## النتائج باختصار

| PoC | الشدة | الملخص |
|---|---|---|
| poc_03 | High | Bearer/Cookie الهدف يُرسلان إلى خدمات OSINT طرف ثالث |
| poc_01 | Medium | `--resume` يفشل لكل نطاق فيه نقطة |
| poc_02 | Low (كامن) | `curl -d "@file"` يقرأ ملفات محلية |

التفاصيل والإصلاحات المقترحة في `ANALYSIS.md`.
