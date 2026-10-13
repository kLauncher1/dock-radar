<div align="center">

<!-- 10-Language Navigation Bar -->
<p align="center">
  <a href="../../README.md">🇺🇸 English</a> · <a href="./ko.md">🇰🇷 한국어</a> · <a href="./zh-CN.md">🇨🇳 简体中文</a> · <a href="./ja.md">🇯🇵 日本語</a> · <a href="./es.md">🇪🇸 Español</a><br />
  <a href="./fr.md">🇫🇷 Français</a> · <a href="./ru.md">🇷🇺 Русский</a> · <a href="./pt-BR.md">🇧🇷 Português</a> · <b>🇸🇦 العربية</b> · <a href="./hi.md">🇮🇳 हिन्दी</a>
</p>

# 📡 Dock-Radar

**مراقب خفيف للغاية للحاويات ومقاييس النظام في ملف تنفيذي فردي مع لوحة تحكم ويب مظلمة مدمجة.**

<sub>تم تطويره بواسطة kLauncher1 · مصمم بأقل استهلاك للموارد للمختبرات المنزلية وأجهزة الحافة.</sub>

</div>

---

## ⚡ المزايا الرئيسية

- **نشر بملف تنفيذي فردي**: لوحة التحكم مدمجة مباشرة داخل ملف Go الثنائي عبر `//go:embed`. لا حاجة لبيئة Node.js أو خوادم ويب منفصلة.
- **استهلاك ذاكرة ضئيل للغاية**: يعمل باستمرار بأقل من **15 ميغابايت من الذاكرة العشوائية (RAM)**، مما يجعله مثالياً لأجهزة VPS الضعيفة وRaspberry Pi.
- **فحص مباشر لمقبس Docker**: يتصل مباشرة بـ `/var/run/docker.sock` أو الأنابيب المسماة في Windows مع استجابة احتياطية عند عدم الاتصال.
- **قياس عن بُعد لنظام المضيف**: تتبع فوري لأنوية المعالج، والـ Goroutines، والذاكرة المخصصة، ودورات GC، ووقت التشغيل.
- **واجهة مستخدم زجاجية داكنة**: لوحة تحكم نظيفة وعالية التباين لفحص الحاويات وسجلات الأحداث الفورية.

---

## 🚀 البدء السريع

```bash
git clone https://github.com/kLauncher1/dock-radar.git
cd dock-radar

# التشغيل المباشر
go run .

# بناء الملف التنفيذي
go build -ldflags="-s -w" -o dock-radar .
./dock-radar
```

لوحة التحكم: 👉 **`http://localhost:9080`**

---

<sub>Copyright © 2026 kLauncher1. Apache-2.0 License.</sub>
