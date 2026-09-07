# Deloitte Cyber Security - Task 1: Data Leak Investigation

* **Difficoltà:** Introductory
* **Tempo stimato:** 30–60 min
* **Scope:** Identificare la causa d'origine di un leak di dati aziendali riservati tramite l'analisi dei log web.

---

## 1. Analisi del Problema
Un cliente Deloitte ha riscontrato una potenziale fuga di dati sensibili. L'obiettivo dell'investigazione è analizzare le richieste HTTP presenti nei log del server web per individuare l'indirizzo IP responsabile e la vulnerabilità sfruttata.

---

## 2. Evidenze Trovate nei Log

Ispezionando i file di log web del server, è stata individuata la seguente richiesta anomala:

```text
192.168.1.105 - - [07/Sep/2026:10:14:22 +0000] "GET /admin/db_export.sql HTTP/1.1" 200 45210
```

* **IP Attaccante:** `192.168.1.105`
* **Vulnerabilità Sfruttata:** Broken Access Control (accesso diretto alla directory di amministrazione senza previa autenticazione).
* **Risorsa Esfiltrata:** `/admin/db_export.sql`

---

## 3. Azioni Correttive Consigliate
1. **Access Control:** Implementare regole RBAC / IAM rigide per bloccare l'accesso diretto ai file di backup.
2. **Hardening:** Spostare i file di backup del database al di fuori della Web Root del server.
3. **WAF Rules:** Configurare il Web Application Firewall per filtrare e bloccare i tentativi di download di estensioni sensibili (`.sql`, `.bak`, `.env`).

---

[⬅️ Torna alla Home Page](../README.md)
