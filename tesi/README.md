# 🔍 OSINT & Digital Investigation Dashboard

Toolkit investigativo modulare sviluppato in **Python** come progetto pratico a corredo della tesi di laurea triennale in **Ingegneria Informatica** dal titolo:

> **“Criminologia Informatica e OSINT: Tecniche di Investigazione Digitale”**

---

## 📌 Panoramica

**OSINT & Digital Investigation Dashboard** è un mini-toolkit interattivo da riga di comando progettato per supportare attività di **Open Source Intelligence (OSINT)**, **digital investigation** e **analisi preliminare forense**.

Il progetto integra in un unico flusso operativo diversi strumenti utili per:

* raccolta e organizzazione di informazioni OSINT;
* profilazione digitale di un soggetto;
* verifica dell'integrità dei reperti digitali;
* calcolo di hash crittografici;
* gestione della catena di custodia;
* normalizzazione e correlazione temporale degli eventi;
* analisi preliminare di dataset sospetti;
* individuazione di Indicatori di Compromissione (IoC);
* rilevamento di informazioni potenzialmente sensibili (PII);
* parsing automatico di file e log.

L'obiettivo è realizzare uno strumento **semplice, modulare e facilmente estendibile**, mantenendo il progetto interamente basato sulla libreria standard di Python.

---

## 🎯 Obiettivi del progetto

Il progetto nasce con finalità principalmente **didattiche e investigative**, con l'obiettivo di dimostrare come diverse tecniche di analisi digitale possano essere integrate all'interno di un'unica applicazione.

In particolare, il toolkit permette di:

1. strutturare informazioni raccolte tramite OSINT;
2. preservare e verificare l'integrità dei reperti digitali;
3. ricostruire una timeline degli eventi;
4. analizzare dataset e log alla ricerca di pattern sospetti;
5. individuare automaticamente IoC e dati potenzialmente sensibili;
6. produrre output strutturati utilizzabili all'interno di report tecnici.

---

# ⚙️ Architettura del progetto

Il codice è organizzato in moduli indipendenti, ciascuno dedicato a una specifica fase dell'attività investigativa.

L'architettura segue un approccio modulare per separare:

* acquisizione e organizzazione dei dati;
* hashing e verifica dell'integrità;
* normalizzazione temporale;
* parsing e analisi dei dataset;
* identificazione degli IoC;
* generazione dei report.

---

# 1️⃣ Profilazione Digitale

## `Crea profilo digitale`

### 🔎 Descrizione

Il modulo permette di creare un profilo digitale strutturato a partire da informazioni preliminari raccolte durante una fase di ricognizione OSINT.

L'analista può inserire informazioni quali:

* nome e cognome;
* indirizzi email;
* username e handle social;
* URL;
* domini;
* numeri di telefono;
* IBAN;
* altre informazioni identificative rilevanti.

I dati vengono organizzati e normalizzati in una struttura facilmente consultabile.

### 🎯 Scopo investigativo

Il modulo consente di trasformare informazioni raccolte durante una fase di **passive reconnaissance** in un profilo strutturato.

Questo permette all'analista di:

* organizzare le informazioni raccolte;
* ridurre la duplicazione dei dati;
* mantenere una struttura uniforme;
* preparare i dati per successive attività investigative;
* facilitare la produzione di report tecnici.

### 📥 Esempio di input

```text
Soggetto: Mario Rossi
Email: mario.rossi@mail.com
Twitter: @marior
Sito: https://rossi-investigazioni.it
```

### 📤 Esempio di output

```markdown
# Profilo Digitale — Mario Rossi

- Email: mario.rossi@mail.com
- Handle: @marior
- URL: https://rossi-investigazioni.it
- Dominio: rossi-investigazioni.it
```

---

# 2️⃣ Verifica della Catena di Custodia

## `Verifica catena di custodia`

### 🔐 Descrizione

Il modulo permette di analizzare un file o una directory e generare automaticamente le principali informazioni necessarie alla verifica dell'integrità del reperto digitale.

Per ogni elemento vengono raccolti:

* nome del file;
* percorso;
* dimensione;
* timestamp e metadati disponibili;
* hash **SHA-256**;
* hash **MD5**.

Gli hash possono essere utilizzati per verificare che il contenuto di un reperto non sia stato modificato durante le fasi di analisi.

### 🎯 Scopo investigativo

La verifica dell'integrità costituisce un elemento fondamentale nelle attività di **Digital Forensics**.

Il calcolo delle impronte crittografiche consente di:

* identificare univocamente un file;
* confrontare il reperto originale con copie successive;
* rilevare eventuali modifiche;
* documentare lo stato del reperto;
* supportare la gestione della **Chain of Custody**.

> **Nota:** il calcolo degli hash supporta la verifica tecnica dell'integrità del dato, ma non costituisce da solo una garanzia giuridica della validità probatoria del reperto. La validità forense dipende anche dalle procedure di acquisizione, conservazione e documentazione adottate.

### 📥 Esempio di input

```text
Percorso: reperto_01.docx
```

### 📤 Esempio di output

```markdown
# Catena di Custodia — Inventario

- File: reperto_01.docx
- SHA256: 3f785e1a...
- MD5: 5d41402a...
- Dimensione: 152 KB
```

---

# 3️⃣ Generazione della Timeline Investigativa

## `Crea timeline`

### 🕒 Descrizione

Il modulo permette di raccogliere eventi provenienti da diverse fonti e costruire una timeline cronologica unificata.

Gli eventi possono essere acquisiti tramite:

* input manuale;
* file CSV;
* file JSON.

I timestamp vengono analizzati e normalizzati in **UTC**, utilizzando il formato:

```text
YYYY-MM-DDTHH:MM:SSZ
```

Gli eventi vengono successivamente ordinati cronologicamente.

### 🎯 Scopo investigativo

La timeline rappresenta uno degli strumenti principali nell'analisi di un incidente informatico.

La normalizzazione temporale consente di correlare eventi provenienti da fonti differenti, ad esempio:

* server;
* workstation;
* firewall;
* sistemi di autenticazione;
* account email;
* applicazioni;
* sistemi di logging.

Questo permette di ricostruire più facilmente la sequenza degli eventi e identificare possibili relazioni tra le diverse attività osservate.

### 📥 Esempio di input

```text
2025-08-28 15:30:00 | Accesso sospetto da IP 192.168.1.10 | Log server
2025-08-28 15:45:00 | Reset password account Rossi | Gmail
```

### 📤 Esempio di output

```markdown
# Timeline Investigativa

| Data Orig.           | UTC                  | Evento                    | Fonte      |
|-----------------------|----------------------|---------------------------|------------|
| 2025-08-28 15:30:00   | 2025-08-28T13:30:00Z | Accesso sospetto...       | Log server |
| 2025-08-28 15:45:00   | 2025-08-28T13:45:00Z | Reset password...         | Gmail      |
```

---

# 4️⃣ Dataset Triage & IoC Parsing

## `Analizza dataset sospetto`

### 🧪 Descrizione

Il modulo effettua una scansione ricorsiva di directory e file di testo alla ricerca di pattern potenzialmente rilevanti dal punto di vista investigativo.

L'analisi utilizza:

* **Regular Expressions (RegEx)**;
* validazione tramite algoritmi specifici;
* parsing di file di testo;
* classificazione degli elementi individuati;
* analisi ricorsiva delle directory.

Tra gli elementi che possono essere individuati:

* indirizzi IPv4;
* indirizzi email;
* domini;
* URL;
* stringhe simili a API key;
* token;
* IBAN;
* numeri di carta potenzialmente validi;
* credenziali in chiaro;
* altri pattern potenzialmente riconducibili a informazioni sensibili.

Per determinati pattern numerici può essere utilizzato l'**algoritmo di Luhn** come ulteriore controllo di validità.

### 🎯 Scopo investigativo

Il modulo è pensato come strumento di **triage preliminare**.

L'obiettivo non è stabilire automaticamente che un elemento sia malevolo, ma ridurre il volume di dati da analizzare manualmente evidenziando rapidamente gli elementi potenzialmente rilevanti.

Può essere particolarmente utile nell'analisi preliminare di:

* dump di dati;
* log;
* file di configurazione;
* esportazioni di database;
* dataset compromessi;
* raccolte di file provenienti da un incidente di sicurezza.

### 📥 Esempio di input

```text
Percorso: /dump_cartella/
```

### 📤 Esempio di output

```markdown
# Dataset Triage Report

- Root: dump_cartella
- Elementi analizzati: 42

### dump1.txt

- MIME: text/plain
- Email: mario@esempio.it
- IBAN IT: IT60X0542811101000000123456
- Secret-like: api_key=ABCD1234...
- Preview: `Login: mario | Pwd: Segreto123`
```

---

# 🧩 Funzionalità principali

| Modulo                   | Funzionalità                                          |
| ------------------------ | ----------------------------------------------------- |
| 👤 Profilazione Digitale | Organizzazione delle informazioni OSINT               |
| 🔐 Chain of Custody      | Hash SHA-256 / MD5 e metadati                         |
| 🕒 Timeline              | Normalizzazione e ordinamento degli eventi            |
| 🧪 Dataset Triage        | Scansione ricorsiva dei file                          |
| 🌐 IoC Parsing           | Identificazione di IP, domini, URL e altri indicatori |
| 🔑 Secret Detection      | Individuazione di stringhe potenzialmente sensibili   |
| 🪪 PII Detection         | Individuazione di informazioni personali              |
| 💳 Luhn Validation       | Validazione preliminare di sequenze numeriche         |

---

# 🛠️ Requisiti

Il progetto è sviluppato utilizzando **Python standard**, senza dipendenze esterne obbligatorie.

### Requisiti minimi

* Python **3.9+**
* Windows / Linux / macOS
* Terminale / Command Prompt / PowerShell

La scelta di utilizzare principalmente la **Python Standard Library** permette di mantenere il progetto:

* leggero;
* portabile;
* facilmente installabile;
* semplice da distribuire;
* privo di dipendenze complesse.

---

# 🚀 Installazione

Clonare il repository:

```bash
git clone https://github.com/USERNAME/osint-dashboard.git
```

Entrare nella directory del progetto:

```bash
cd osint-dashboard
```

Avviare l'applicazione:

```bash
python main.py
```

Su alcuni sistemi può essere necessario utilizzare:

```bash
python3 main.py
```

---

# 🖥️ Utilizzo

All'avvio viene mostrato il menu principale del toolkit.

Esempio:

```text
========================================
     OSINT & DIGITAL INVESTIGATION
              DASHBOARD
========================================

[1] Crea profilo digitale
[2] Verifica catena di custodia
[3] Crea timeline
[4] Analizza dataset sospetto
[0] Esci

Seleziona un'opzione:
```

L'utente può quindi selezionare il modulo desiderato e seguire le istruzioni mostrate dal programma.

---

# 📂 Struttura del progetto

Una possibile organizzazione del repository è:

```text
osint-dashboard/
│
├── main.py
├── README.md
│
├── modules/
│   ├── __init__.py
│   ├── profile.py
│   ├── custody.py
│   ├── timeline.py
│   └── triage.py
│
├── data/
│   └── samples/
│
├── reports/
│
└── tests/
    └── ...
```

La struttura modulare permette di aggiungere successivamente nuovi componenti senza modificare in maniera significativa il funzionamento dei moduli esistenti.

---

# 🔬 Tecnologie utilizzate

Il progetto utilizza principalmente componenti della **Python Standard Library**.

Tra le tecnologie e i concetti utilizzati:

* Python 3;
* `hashlib`;
* `os`;
* `pathlib`;
* `re`;
* `json`;
* `csv`;
* `datetime`;
* Regular Expressions;
* SHA-256;
* MD5;
* algoritmo di Luhn;
* parsing di dati strutturati;
* normalizzazione temporale;
* file system traversal.

---

# 🛡️ Aspetti di sicurezza

Il toolkit è progettato per attività di **analisi autorizzata**, ricerca, formazione e digital forensics.

Le funzionalità di individuazione di credenziali, token, API key, PII e altri dati sensibili devono essere utilizzate esclusivamente su dati per i quali si dispone di una valida autorizzazione.

Il progetto non è progettato per:

* ottenere accesso non autorizzato a sistemi;
* bypassare sistemi di autenticazione;
* effettuare intrusioni;
* sottrarre informazioni;
* compromettere account o infrastrutture.

Il modulo di triage ha inoltre finalità di **individuazione preliminare**: un pattern identificato dal sistema non implica necessariamente che il dato sia valido, attivo o malevolo e deve essere verificato manualmente.

---

# 📊 Esempio di Workflow Investigativo

Un possibile workflow utilizzando il toolkit è:

```text
                    ┌─────────────────────┐
                    │   Raccolta OSINT    │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ Profilazione digitale│
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ Acquisizione reperti │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ Chain of Custody     │
                    │ SHA-256 / MD5        │
                    └──────────┬──────────┘
                               │
                  ┌────────────┴────────────┐
                  ▼                         ▼
        ┌───────────────────┐     ┌───────────────────┐
        │ Dataset Triage    │     │ Analisi Timeline  │
        │ IoC / PII / Logs  │     │ Eventi / Timestamp│
        └─────────┬─────────┘     └─────────┬─────────┘
                  │                         │
                  └────────────┬────────────┘
                               ▼
                    ┌─────────────────────┐
                    │ Correlazione eventi │
                    │ e indicatori        │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ Report investigativo│
                    └─────────────────────┘
```

---

# 📈 Possibili sviluppi futuri

Il progetto può essere ulteriormente esteso introducendo nuove funzionalità.

### 🔎 OSINT

* ricerca automatizzata di username;
* correlazione tra domini e sottodomini;
* analisi DNS;
* WHOIS lookup;
* raccolta di informazioni pubbliche da fonti autorizzate;
* integrazione con API OSINT.

### 🌐 Network Intelligence

* parsing di PCAP;
* estrazione di IP e domini;
* analisi DNS;
* correlazione con blacklist e threat intelligence;
* classificazione degli indicatori.

### 🧪 Digital Forensics

* analisi dei metadati dei file;
* parsing di log Windows;
* analisi di Event Log;
* estrazione di artefatti;
* supporto a immagini disco;
* generazione automatica di report forensi.

### 📊 Reporting

* esportazione JSON;
* esportazione CSV;
* report Markdown;
* report HTML;
* dashboard web;
* visualizzazione grafica delle timeline.

### 🛡️ Threat Intelligence

Possibile integrazione futura con piattaforme e database di Threat Intelligence per arricchire automaticamente gli IoC individuati.

---

# 🎓 Collegamento con la tesi

Il progetto costituisce una componente pratica della tesi di laurea triennale in **Ingegneria Informatica**:

> **“Criminologia Informatica e OSINT: Tecniche di Investigazione Digitale”**

La realizzazione del toolkit permette di applicare concretamente alcuni dei concetti affrontati nell'ambito della ricerca:

* Open Source Intelligence;
* digital investigation;
* digital forensics;
* raccolta e preservazione delle evidenze;
* analisi di log;
* correlazione temporale;
* Indicatori di Compromissione;
* identificazione di dati sensibili;
* automazione delle attività investigative.

Il progetto rappresenta quindi un esempio pratico di come tecniche di programmazione e metodologie investigative possano essere combinate per costruire uno strumento di supporto all'analisi digitale.

---

# ⚠️ Disclaimer

Questo progetto è stato sviluppato con finalità **didattiche, accademiche e di ricerca**.

Le informazioni e gli strumenti forniti devono essere utilizzati esclusivamente su sistemi, file e dataset per i quali l'utente dispone di una specifica autorizzazione.

L'autore non si assume responsabilità per utilizzi impropri o non autorizzati del software.

---

# 👨‍💻 Autore

**Salvo Orlando**

Laurea in Ingegneria Informatica

Progetto sviluppato come componente pratica della tesi:

> **Criminologia Informatica e OSINT: Tecniche di Investigazione Digitale**

---

# 📜 Licenza

Il progetto può essere distribuito secondo i termini della licenza scelta dall'autore.

Se non è ancora stata scelta una licenza, si consiglia di aggiungere un file `LICENSE` al repository prima della pubblicazione definitiva.
