# Task 02 — Phishing Awareness Training Module

> **CodeAlpha Cybersecurity Internship** | Security Awareness & Human Factor  
> **Difficulty:** ⭐⭐ Beginner | **Estimated Time:** 4–6 hours

---

## 🎯 Objective

Build a **complete, interactive phishing awareness training platform** as a single HTML file — no frameworks, no build step, runs in any browser. Covers recognition, psychology, real examples, best practices, and a 50-question quiz bank.

---

## 📂 Folder Structure

```
02_phishing_awareness_module/
├── index.html                  # Single-file app (6 sections, ~1500 lines)
└── README.md                   # This file
```

---

## 🚀 Quick Start

### Option 1: Double-Click (Easiest)
```bash
# Navigate to folder and double-click index.html
# Opens in your default browser — works offline!
```

### Option 2: Local Server (Recommended for full features)
```bash
cd 02_phishing_awareness_module

# Python 3
python -m http.server 8080
# → http://localhost:8080

# Or Node.js
npx serve .
# → http://localhost:3000
```

> **No dependencies, no install, no build.** Pure HTML5 + CSS3 + Vanilla ES6 JavaScript.

---

## 📚 Module Sections (6 Tabs)

| # | Section | Description | Key Features |
|---|---------|-------------|--------------|
| **1** | 🏠 **Introduction** | Phishing stats, attack types, why training matters | 4 stat cards, 6 attack type cards (email, spear, whale, smishing, clone, BEC) |
| **2** | 🔍 **Recognize Phishing** | 7 red flags + green flags with interactive examples | 7 expandable red-flag cards, hover tooltips, green-flag comparison |
| **3** | 🎭 **Social Engineering** | 6 psychological tactics + 6 advanced modern tactics | Tactics grid (urgency, authority, trust, reciprocity, FOMO, social proof), modern: OAuth phishing, quishing, AI-enhanced |
| **4** | 📧 **Real Examples** | Interactive email analyzer + 3 annotated examples + vishing script | **Email analyzer**: click flags to highlight sender/urgency/links/threats; Microsoft 365 harvest, CEO fraud, legitimate Amazon; vishing scenario |
| **5** | ✅ **Best Practices** | STOP method, daily habits, incident response checklist | STOP cards (Stop/Think/Observe/Proceed), 15+ habit checkboxes, 6-step incident response |
| **6** | 🧠 **Interactive Quiz** | 50-question bank, 10 random per attempt, instant feedback | 50 questions across 5 categories, explanations for every answer, visual scoring (excellent/good/fair/poor), retake button |

---

## 🎮 Interactive Features

### Email Analyzer (Section 4)
- **Click flag buttons** (Sender, Urgency, Links, Threats) to highlight suspicious elements
- **Hover highlighted text** for explanation tooltips
- **"Show All Flags"** reveals every red flag at once
- **Legitimate comparison** shows green flags side-by-side

### Quiz Engine (Section 6)
- **50 questions** across 5 categories: Email Red Flags, Website/URL Analysis, Social Engineering, Incident Response, Advanced Tactics
- **10 random questions** per attempt — different every time
- **Instant feedback** with detailed explanations
- **Visual scoring**: 🟢 Excellent (≥90%), 🔵 Good (70-89%), 🟠 Fair (50-69%), 🔴 Poor (<50%)
- **Retake anytime** — new random selection each time

### Progress Tracking
- **Top progress bar** fills as you complete sections
- **Section counter** (1 of 6, 2 of 6, etc.)
- **localStorage** persists quiz state across refreshes

---

## 🎨 Technical Highlights

| Feature | Implementation |
|---------|----------------|
| **Zero Dependencies** | No npm, no CDN, no frameworks — pure browser APIs |
| **Responsive Design** | CSS Grid + Flexbox, mobile-first, works 320px–4K |
| **Accessibility** | Semantic HTML, ARIA roles, keyboard navigation, focus styles |
| **Animations** | CSS keyframes (fadeIn, slideDown, spin), smooth transitions |
| **State Management** | Vanilla JS module pattern, localStorage for quiz persistence |
| **Code Organization** | IIFE modules, event delegation, clean separation of concerns |
| **Print-Friendly** | Quick-reference card at bottom, `@media print` styles |

---

## 📝 Quiz Question Bank (50 Questions)

| Category | Count | Sample Topics |
|----------|-------|---------------|
| Email Red Flags | 10 | Generic greetings, mismatched URLs, urgency, attachments, sender domains |
| Website/URL Analysis | 8 | HTTPS misconceptions, subdomain tricks, typosquatting, redirect chains, password manager behavior |
| Social Engineering | 8 | Vishing, IRS scams, authority impersonation, reciprocity, FOMO, OAuth phishing, quishing, AI deepfakes |
| Incident Response | 6 | Immediate steps, MFA recovery, reporting channels, credit freeze, malware scanning |
| Advanced Tactics | 8 | Conversation hijacking, consent phishing, QR codes, multi-channel, AI-generated content, supply chain |

> Full question bank embedded in `index.html` (lines 425–1200). Each question: `id`, `category`, `question`, `options[]`, `correct`, `explanation`.

---

## 🎓 Learning Outcomes

- ✅ **Phishing taxonomy** — Email, spear, whale, smishing, vishing, clone, BEC
- ✅ **Red flag recognition** — 7 universal indicators + green flags for legitimate mail
- ✅ **Social engineering psychology** — 6 core tactics (Cialdini) + 6 modern variants
- ✅ **URL analysis** — Domain parsing, subdomain tricks, typosquatting, HTTPS limits
- ✅ **STOP methodology** — Stop, Think, Observe, Proceed/Report decision framework
- ✅ **Incident response** — 6-step playbook for clicked/compromised accounts
- ✅ **Frontend engineering** — Single-file architecture, vanilla JS state, CSS animations

---

## 🛠️ Customization Guide

### Add Your Organization's Branding
```html
<!-- In <style> section, update CSS variables -->
:root {
  --primary: #00d2ff;      /* Your brand color */
  --secondary: #3a7bd5;    /* Your accent color */
  --bg-gradient: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
}
```

### Add Custom Quiz Questions
```javascript
// In QUESTION_BANK array, add objects:
{
  id: 51,
  cat: "Custom Category",
  q: "Your custom question?",
  opts: [
    {v: "a", t: "Option A"},
    {v: "b", t: "Option B"},
    {v: "c", t: "Option C"},
    {v: "d", t: "Option D"}
  ],
  correct: "b",
  exp: "Explanation why B is correct."
}
```

### Embed in LMS/Intranet
```html
<!-- Include as iframe -->
<iframe src="index.html" width="100%" height="800px" frameborder="0"></iframe>
```

---

## 🧪 Testing Checklist

- [ ] Open `index.html` directly in Chrome/Firefox/Safari/Edge — all sections load
- [ ] Navigate all 6 tabs — smooth transitions, progress bar updates
- [ ] Email Analyzer — click each flag button, verify highlights appear
- [ ] Quiz — answer 10 questions, submit, verify score + explanations
- [ ] Retake quiz — new random questions appear
- [ ] Mobile view (DevTools device toolbar) — responsive, touch-friendly
- [ ] Print preview — quick-reference card renders cleanly
- [ ] Accessibility — Tab navigation, screen reader labels, color contrast

---

## 📚 Learning Resources

| Topic | Resource |
|-------|----------|
| Phishing Statistics | https://www.cisa.gov/phishing |
| Social Engineering | https://www.social-engineer.org/ |
| NIST Phishing Guidance | https://csrc.nist.gov/pubs/sp/800/115/final |
| Google Phishing Quiz | https://phishingquiz.withgoogle.com/ |
| KnowBe4 Resources | https://www.knowbe4.com/ |
| Anti-Phishing Working Group | https://apwg.org/ |

---

## ✅ Submission Deliverables

- [ ] `index.html` — complete, working, pushed to GitHub
- [ ] LinkedIn post with screenshots of: email analyzer, quiz result, STOP method
- [ ] Video demo (2–3 min) walking through all 6 sections
- [ ] CodeAlpha submission form completed

---

## 🔗 Navigation

← **Task 01** [`../01_security_code_audit/README.md`](../01_security_code_audit/README.md) | **Master README** [`../README.md`](../README.md) | **Task 03 →** [`../03_network_packet_analyzer/README.md`](../03_network_packet_analyzer/README.md)