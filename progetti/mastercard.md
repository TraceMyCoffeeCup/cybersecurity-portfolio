# Mastercard Cyber Security - Security Awareness & Phishing Analysis

* **Difficoltà:** Introductory
* **Tempo stimato:** 1-2 ore
* **Scope:** Valutare e identificare le minacce di Phishing e progettare linee guida di Security Awareness per il personale aziendale.

---

## 1. Scenario & Obiettivo
Durante la simulazione con Mastercard, l'obiettivo è stato analizzare diverse e-mail sospette ricevute dall'organizzazione per distinguere le comunicazioni legittime da tentativi di Phishing, Spear Phishing e Spoofing, definendo poi le strategie di mitigazione e formazione.

---

## 2. Analisi delle E-mail & Indicatori di Compromissione (IoC)

L'analisi dei messaggi ha evidenziato i seguenti indicatori tipici di attacco:

* **Dominio Mittente (Spoofing):** Email inviate da domini simili a quelli ufficiali ma con errori tipografici (es. `@m4stercard-support.com` invece del dominio aziendale autentico).
* **Urgenza e Pressione Psicologica:** Richieste immediate di inserimento credenziali per evitare il blocco dell'account.
* **Link Malevoli:** Hyperlink che puntano a landing page di login contraffatte progettate per il furto di credenziali.

---

## 3. Strategie di Mitigazione e Formazione

1. **Email Security Controls:** Configurazione rigida dei record **SPF**, **DKIM** e politiche **DMARC** per prevenire lo spoofing del dominio.
2. **Multi-Factor Authentication (MFA):** Implementazione obbligatoria di MFA per ridurre l'impatto in caso di credenziali compromesse.
3. **Security Awareness Training:** Programmi periodici di simulazione phishing per i dipendenti per aumentare il livello di attenzione sulle e-mail in arrivo.

---

[⬅️ Torna alla Home Page](../README.md)
