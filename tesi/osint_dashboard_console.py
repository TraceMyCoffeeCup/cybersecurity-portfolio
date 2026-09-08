#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OSINT Dashboard (Console)
=========================

Mini–toolkit investigativo per tesi "Criminologia Informatica & OSINT".

Funzioni principali:
  1) Crea profilo digitale            → Estrae indicatori (email, telefoni, IP, URL, handle) e genera un profilo JSON/Markdown.
  2) Verifica catena di custodia      → Calcola hash (SHA256/MD5) di file o directory, produce inventario e verifica record precedenti.
  3) Crea timeline                    → Unifica eventi da input manuale/CSV/JSON, normalizza fuso orario e salva CSV/JSON/Markdown.
  4) Analizza dataset sospetto        → Triage: identifica tipo file, cerca PII/IOC, segreti e indicatori, stima rischi e crea report.

Note legali/etiche (da includere in tesi):
  - Usa solo fonti e file per cui hai titolo legale all'analisi. Rispetta GDPR e norme su riservatezza dei dati.
  - Mantieni una catena di custodia documentata (hash, timestamp, operatore, note) per garantire integrità probatoria.

Dipendenze: solo standard library. (Facoltativo: Pillow per EXIF, se presente.)
"""

from __future__ import annotations
import os
import re
import sys
import csv
import json
import time
import uuid
import hashlib
import getpass
import mimetypes
import datetime as dt
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Iterable

try:
    from zoneinfo import ZoneInfo  # Py3.9+
except Exception:  # pragma: no cover
    ZoneInfo = None  # type: ignore

# --- Config ---------------------------------------------------------------
APP_NAME = "OSINT Dashboard"
OUTPUT_DIR = Path("outputs")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# --- Utility --------------------------------------------------------------

def now_iso() -> str:
    return dt.datetime.utcnow().replace(tzinfo=dt.timezone.utc).isoformat()


def slugify(s: str) -> str:
    s = s.strip().lower()
    s = re.sub(r"[^a-z0-9-_]+", "-", s)
    s = re.sub(r"-+", "-", s).strip("-")
    return s or str(uuid.uuid4())


def sha256_hex(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def md5_hex(path: Path) -> str:
    h = hashlib.md5()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def safe_read_text(path: Path, max_bytes: int = 2_000_000) -> str:
    try:
        data = path.read_bytes()[:max_bytes]
        return data.decode("utf-8", errors="ignore")
    except Exception:
        return ""


def first_bytes(path: Path, n: int = 8) -> bytes:
    try:
        with path.open("rb") as f:
            return f.read(n)
    except Exception:
        return b""


def guess_type(path: Path) -> str:
    # Signature-based quick checks
    sig = first_bytes(path, 8)
    if sig.startswith(b"%PDF"):
        return "application/pdf"
    if sig.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if sig.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if sig.startswith(b"PK\x03\x04"):
        return "application/zip"
    # Fallback to mimetypes
    t, _ = mimetypes.guess_type(str(path))
    return t or "application/octet-stream"


# --- Regex patterns (PII/IOC/Secrets) ------------------------------------
RE_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
RE_URL = re.compile(r"https?://[\w.-]+(?:/[\w\-._~:/?#[\]@!$&'()*+,;=%]*)?", re.I)
RE_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
RE_IPV6 = re.compile(r"\b([0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}\b", re.I)
RE_HANDLE = re.compile(r"(?:(?<=\s)|^)@([A-Za-z0-9_\.]{2,30})\b")
RE_IT_PHONE = re.compile(r"\b(?:\+39\s?)?(?:3\d{2}|0\d{1,3})[\s.-]?\d{5,8}\b")
RE_IBAN_IT = re.compile(r"\bIT\d{2}[A-Z]\d{10}[0-9A-Z]{12}\b")
RE_HASH_MD5 = re.compile(r"\b[a-f0-9]{32}\b", re.I)
RE_HASH_SHA1 = re.compile(r"\b[a-f0-9]{40}\b", re.I)
RE_HASH_SHA256 = re.compile(r"\b[a-f0-9]{64}\b", re.I)
RE_JWT = re.compile(r"\beyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b")
RE_SECRET_TOKENS = re.compile(r"(?i)\b(?:api[_-]?key|secret|token|bearer|pwd|password|passwd|client[_-]?secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9\-_.=]{8,})")
RE_PRIVKEY = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")
RE_ENV_KV = re.compile(r"(?m)^([A-Z0-9_]{3,40})=(.+)$")

# Credit card (Luhn) candidate
RE_PAN = re.compile(r"\b(?:\d[ -]*?){13,19}\b")


def luhn_check(num: str) -> bool:
    digits = [int(d) for d in re.sub(r"\D", "", num)]
    if len(digits) < 13:
        return False
    total = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


# --- 1) Crea profilo digitale -------------------------------------------

def create_digital_profile() -> None:
    print("\n=== CREA PROFILO DIGITALE ===")
    subject = input("Soggetto/alias (es. 'MarioRossi' o azienda): ").strip() or "soggetto"
    base_id = slugify(subject)
    print("\nIncolla qualunque info testuale (bio, descrizione, note, handle, URL, email).\nTermina con una riga vuota.")
    chunks: List[str] = []
    while True:
        line = input()
        if not line.strip():
            break
        chunks.append(line)
    text = "\n".join(chunks)

    indicators = extract_indicators(text)

    profile = {
        "id": base_id,
        "subject": subject,
        "created_utc": now_iso(),
        "operator": getpass.getuser(),
        "indicators": indicators,
        "notes": text[:1000],
    }

    # Save JSON + Markdown
    stem = f"profile_{base_id}_{int(time.time())}"
    (OUTPUT_DIR / f"{stem}.json").write_text(json.dumps(profile, indent=2, ensure_ascii=False))
    (OUTPUT_DIR / f"{stem}.md").write_text(render_profile_md(profile))

    print(f"\nProfilo creato e salvato in: {OUTPUT_DIR / (stem + '.json')}\nAnteprima indicatori:")
    for k, v in indicators.items():
        if not v:
            continue
        sample = ", ".join(list(v)[:5])
        print(f"  - {k}: {len(v)} trovati → {sample}")


def extract_indicators(text: str) -> Dict[str, List[str]]:
    def uniq(iterable: Iterable[str], key=lambda x: x) -> List[str]:
        seen = set()
        out = []
        for item in iterable:
            k = key(item)
            if k not in seen:
                seen.add(k)
                out.append(item)
        return out

    emails = uniq(RE_EMAIL.findall(text))
    urls = uniq(RE_URL.findall(text))
    handles = uniq([f"@{h}" for h in RE_HANDLE.findall(text)])
    ipv4s = uniq(RE_IPV4.findall(text))
    ipv6s = uniq(RE_IPV6.findall(text))
    phones = uniq(RE_IT_PHONE.findall(text))
    iban_it = uniq(RE_IBAN_IT.findall(text))

    domains = []
    from urllib.parse import urlparse
    for u in urls:
        try:
            p = urlparse(u)
            if p.hostname:
                domains.append(p.hostname.lower())
        except Exception:
            pass
    domains = sorted(set(domains))

    return {
        "emails": emails,
        "urls": urls,
        "domains": domains,
        "handles": handles,
        "ipv4": ipv4s,
        "ipv6": ipv6s,
        "phones_it": phones,
        "iban_it": iban_it,
    }


def render_profile_md(profile: Dict) -> str:
    ind = profile.get("indicators", {})
    def list_md(title: str, items: List[str]) -> str:
        if not items:
            return f"### {title}\n- (nessuno)\n"
        buf = [f"### {title}"]
        for x in items:
            buf.append(f"- {x}")
        return "\n".join(buf) + "\n"

    parts = [
        f"# Profilo Digitale — {profile.get('subject')}\n",
        f"- ID: `{profile.get('id')}`\n- Creato (UTC): {profile.get('created_utc')}\n- Operatore: {profile.get('operator')}\n",
        "## Indicatori\n",
        list_md("Email", ind.get("emails", [])),
        list_md("Handle", ind.get("handles", [])),
        list_md("URL", ind.get("urls", [])),
        list_md("Domini", ind.get("domains", [])),
        list_md("IPv4", ind.get("ipv4", [])),
        list_md("IPv6", ind.get("ipv6", [])),
        list_md("Telefoni (IT)", ind.get("phones_it", [])),
        list_md("IBAN (IT)", ind.get("iban_it", [])),
        "## Note\n",
        f"{profile.get('notes','')[:2000]}\n",
    ]
    return "\n".join(parts)


# --- 2) Verifica catena di custodia -------------------------------------

def chain_of_custody() -> None:
    print("\n=== CATENA DI CUSTODIA ===")
    print("1) Registra nuovo inventario\n2) Verifica contro record precedente")
    choice = input("Scelta [1/2]: ").strip() or "1"
    if choice == "1":
        path_str = input("Percorso file o directory da inventariare: ").strip()
        path = Path(path_str)
        if not path.exists():
            print("Percorso non trovato.")
            return
        operator = input("Operatore/annotatore (facoltativo): ").strip() or getpass.getuser()
        note = input("Note (facoltative): ").strip()
        records = inventory_path(path, operator=operator, note=note)
        if not records:
            print("Nessun file indicizzato.")
            return
        bundle = {
            "case_id": str(uuid.uuid4()),
            "root_path": str(path.resolve()),
            "created_utc": now_iso(),
            "operator": operator,
            "note": note,
            "items": records,
        }
        stem = f"custody_{slugify(path.name)}_{int(time.time())}"
        (OUTPUT_DIR / f"{stem}.json").write_text(json.dumps(bundle, indent=2, ensure_ascii=False))
        save_custody_csv_md(stem, bundle)
        print(f"\nInventario creato: {OUTPUT_DIR / (stem + '.json')} ({len(records)} file)")
    else:
        prev = input("Percorso JSON di catena di custodia precedente: ").strip()
        p = Path(prev)
        if not p.exists():
            print("File JSON non trovato.")
            return
        bundle = json.loads(p.read_text())
        mismatches = verify_custody(bundle)
        if not mismatches:
            print("\nVERIFICA OK: nessuna discrepanza sugli hash.")
        else:
            print("\nATTENZIONE: discrepanze riscontrate:")
            for item in mismatches:
                print(f" - {item}")


def inventory_path(root: Path, operator: str, note: str = "") -> List[Dict]:
    files: List[Path] = []
    if root.is_file():
        files = [root]
    else:
        for dirpath, _, filenames in os.walk(root):
            for fn in filenames:
                p = Path(dirpath) / fn
                try:
                    if p.is_file():
                        files.append(p)
                except Exception:
                    pass
    items: List[Dict] = []
    for i, file in enumerate(sorted(files)):
        try:
            st = file.stat()
            items.append({
                "item_id": i + 1,
                "path": str(file.resolve()),
                "size": st.st_size,
                "mtime": dt.datetime.fromtimestamp(st.st_mtime, tz=dt.timezone.utc).isoformat(),
                "ctime": dt.datetime.fromtimestamp(st.st_ctime, tz=dt.timezone.utc).isoformat(),
                "atime": dt.datetime.fromtimestamp(st.st_atime, tz=dt.timezone.utc).isoformat(),
                "mime": guess_type(file),
                "sha256": sha256_hex(file),
                "md5": md5_hex(file),
                "operator": operator,
                "note": note,
            })
        except Exception as e:
            print(f"[ERRORE] {file}: {e}")
    return items


def save_custody_csv_md(stem: str, bundle: Dict) -> None:
    # CSV
    csv_path = OUTPUT_DIR / f"{stem}.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["item_id", "path", "size", "mime", "sha256", "md5", "mtime", "ctime", "atime", "operator", "note"])
        for it in bundle["items"]:
            writer.writerow([it[k] for k in [
                "item_id", "path", "size", "mime", "sha256", "md5", "mtime", "ctime", "atime", "operator", "note"
            ]])
    # Markdown
    md_path = OUTPUT_DIR / f"{stem}.md"
    lines = [
        f"# Catena di Custodia — Inventario\n",
        f"- Case ID: `{bundle['case_id']}`\n- Root: `{bundle['root_path']}`\n- Creato (UTC): {bundle['created_utc']}\n- Operatore: {bundle['operator']}\n- Note: {bundle.get('note','')}\n",
        "\n| # | Path | Size | MIME | SHA256 | MD5 | mtime (UTC) |\n|---:|---|---:|---|---|---|---|\n",
    ]
    for it in bundle["items"]:
        lines.append(
            f"| {it['item_id']} | `{it['path']}` | {it['size']} | {it['mime']} | `{it['sha256'][:12]}…` | `{it['md5'][:12]}…` | {it['mtime']} |"
        )
    md_path.write_text("\n".join(lines))


def verify_custody(bundle: Dict) -> List[str]:
    mismatches = []
    for it in bundle.get("items", []):
        p = Path(it["path"])
        if not p.exists():
            mismatches.append(f"MANCANTE: {p}")
            continue
        cur = sha256_hex(p)
        if cur != it.get("sha256"):
            mismatches.append(f"HASH DIVERSO: {p} (prev {it.get('sha256')[:12]}…, now {cur[:12]}…)")
    return mismatches


# --- 3) Crea timeline ----------------------------------------------------

def create_timeline() -> None:
    print("\n=== CREA TIMELINE ===")
    print("1) Inserimento manuale\n2) Import CSV\n3) Import JSON")
    choice = input("Scelta [1/2/3]: ").strip() or "1"
    events: List[Dict] = []
    if choice == "1":
        print("Inserisci eventi nel formato: YYYY-MM-DD HH:MM:SS | EVENTO | SORGENTE (riga vuota per finire)")
        while True:
            line = input("» ")
            if not line.strip():
                break
            events.append(parse_event_line(line))
    elif choice == "2":
        path = Path(input("Percorso CSV: ").strip())
        if not path.exists():
            print("CSV non trovato.")
            return
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            reader = csv.DictReader(f)
            # Heuristics for columns
            candidates = {k.lower(): k for k in reader.fieldnames or []}
            ts_col = candidates.get("timestamp") or candidates.get("time") or candidates.get("date") or list(candidates.values())[0]
            ev_col = candidates.get("event") or candidates.get("evento") or list(candidates.values())[1 if len(candidates)>1 else 0]
            src_col = candidates.get("source") or candidates.get("sorgente") or (list(candidates.values())[2] if len(candidates)>2 else ev_col)
            for row in reader:
                events.append(normalize_event(row.get(ts_col, ""), row.get(ev_col, ""), row.get(src_col, "")))
    else:
        path = Path(input("Percorso JSON: ").strip())
        if not path.exists():
            print("JSON non trovato.")
            return
        data = json.loads(path.read_text())
        for e in data:
            events.append(normalize_event(e.get("timestamp",""), e.get("event",""), e.get("source","")))

    # Normalizza fuso orario (facoltativo)
    tz_off = input("Offset fuso orario degli input (es. +02:00, invio per nessuno): ").strip()
    tzinfo = parse_offset(tz_off) if tz_off else None
    for e in events:
        e["timestamp_utc"] = to_utc_iso(e.get("timestamp"), tzinfo)

    # Ordina e de-duplica
    seen = set()
    cleaned: List[Dict] = []
    for e in sorted(events, key=lambda x: x.get("timestamp_utc") or x.get("timestamp") or ""):
        key = (e.get("timestamp_utc"), e.get("event"), e.get("source"))
        if key not in seen:
            seen.add(key)
            cleaned.append(e)

    if not cleaned:
        print("Nessun evento valido.")
        return

    stem = f"timeline_{int(time.time())}"
    (OUTPUT_DIR / f"{stem}.json").write_text(json.dumps(cleaned, indent=2, ensure_ascii=False))
    save_timeline_csv_md(stem, cleaned)
    print(f"\nTimeline salvata: {OUTPUT_DIR / (stem + '.csv')} ({len(cleaned)} eventi)")


def parse_event_line(line: str) -> Dict:
    parts = [p.strip() for p in line.split("|")]
    ts = parts[0] if parts else ""
    ev = parts[1] if len(parts) > 1 else ""
    src = parts[2] if len(parts) > 2 else "manual"
    return normalize_event(ts, ev, src)


def normalize_event(ts: str, ev: str, src: str) -> Dict:
    return {"timestamp": ts.strip(), "event": ev.strip(), "source": src.strip() or "manual"}


def parse_offset(offset: str) -> dt.timezone:
    m = re.match(r"^([+-])(\d{2}):(\d{2})$", offset)
    if not m:
        return dt.timezone.utc
    sign = 1 if m.group(1) == "+" else -1
    hours = int(m.group(2))
    minutes = int(m.group(3))
    return dt.timezone(dt.timedelta(hours=sign * hours, minutes=sign * minutes))


def to_utc_iso(ts: str, tzinfo: Optional[dt.tzinfo]) -> Optional[str]:
    ts = ts.strip()
    if not ts:
        return None
    fmts = ["%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M:%S", "%d/%m/%Y %H:%M:%S", "%d/%m/%Y %H:%M"]
    for fmt in fmts:
        try:
            d = dt.datetime.strptime(ts, fmt)
            if tzinfo:
                d = d.replace(tzinfo=tzinfo)
            return d.astimezone(dt.timezone.utc).isoformat()
        except Exception:
            continue
    return None


def save_timeline_csv_md(stem: str, events: List[Dict]) -> None:
    # CSV
    csv_path = OUTPUT_DIR / f"{stem}.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "timestamp_utc", "event", "source"])
        for e in events:
            writer.writerow([e.get("timestamp"), e.get("timestamp_utc"), e.get("event"), e.get("source")])
    # Markdown
    md_path = OUTPUT_DIR / f"{stem}.md"
    lines = ["# Timeline\n", "| Data Orig. | UTC | Evento | Fonte |\n|---|---|---|---|\n"]
    for e in events:
        lines.append(f"| {e.get('timestamp','')} | {e.get('timestamp_utc','')} | {e.get('event','').replace('|','/')} | {e.get('source','')} |")
    md_path.write_text("\n".join(lines))


# --- 4) Analizza dataset sospetto ----------------------------------------

def analyze_suspicious_dataset() -> None:
    print("\n=== ANALISI DATASET SOSPETTO ===")
    path_str = input("Percorso file o directory: ").strip()
    path = Path(path_str)
    if not path.exists():
        print("Percorso non trovato.")
        return

    targets: List[Path] = []
    if path.is_file():
        targets = [path]
    else:
        print("(Suggerimento: per directory grandi verranno campionati i primi 500 file)")
        for dirpath, _, filenames in os.walk(path):
            for fn in filenames:
                fp = Path(dirpath) / fn
                if fp.is_file():
                    targets.append(fp)
            if len(targets) > 500:
                break

    findings: List[Dict] = []
    for fp in targets:
        try:
            mime = guess_type(fp)
            size = fp.stat().st_size
            item = {"path": str(fp), "mime": mime, "size": size}
            content_snippet = ""
            text = ""
            is_text_like = mime.startswith("text/") or any(fp.suffix.lower() in ext for ext in [".txt", ".csv", ".log", ".json", ".xml", ".env", ".ini", ".cfg", ".md", ".yml", ".yaml"])
            if is_text_like and size <= 2_000_000:
                text = safe_read_text(fp)
                content_snippet = text[:200]
                item.update(scan_text(text))
                # ENV kvs
                env_pairs = RE_ENV_KV.findall(text)
                if env_pairs:
                    item["env_keys"] = list({k for k, _ in env_pairs})
            else:
                # Binary quick checks
                item["sha256"] = sha256_hex(fp)
                if fp.suffix.lower() in {".jpg", ".jpeg", ".png"}:
                    try:
                        from PIL import Image
                        im = Image.open(fp)
                        exif = getattr(im, "_getexif", lambda: None)()
                        if exif:
                            item["exif_present"] = True
                    except Exception:
                        pass
            item["preview"] = content_snippet
            findings.append(item)
        except Exception as e:
            findings.append({"path": str(fp), "error": str(e)})

    risk_summary = summarize_risks(findings)
    report = {
        "created_utc": now_iso(),
        "root": str(path.resolve()),
        "total_items": len(targets),
        "risk_summary": risk_summary,
        "findings": findings,
    }

    stem = f"dataset_triage_{slugify(path.name)}_{int(time.time())}"
    (OUTPUT_DIR / f"{stem}.json").write_text(json.dumps(report, indent=2, ensure_ascii=False))
    save_dataset_md(stem, report)
    print(f"\nReport creato: {OUTPUT_DIR / (stem + '.md')} — {len(findings)} elementi analizzati")


def scan_text(text: str) -> Dict:
    out: Dict[str, object] = {}
    # Basic indicators
    emails = list(sorted(set(RE_EMAIL.findall(text))))
    urls = list(sorted(set(RE_URL.findall(text))))
    ipv4 = list(sorted(set(RE_IPV4.findall(text))))
    ipv6 = list(sorted(set(RE_IPV6.findall(text))))
    handles = list(sorted({f"@{h}" for h in RE_HANDLE.findall(text)}))
    phones = list(sorted(set(RE_IT_PHONE.findall(text))))
    iban = list(sorted(set(RE_IBAN_IT.findall(text))))
    md5s = list(sorted(set(RE_HASH_MD5.findall(text))))
    sha1s = list(sorted(set(RE_HASH_SHA1.findall(text))))
    sha256s = list(sorted(set(RE_HASH_SHA256.findall(text))))
    jwts = list(sorted(set(RE_JWT.findall(text))))
    secrets = list(sorted({m.group(1) for m in RE_SECRET_TOKENS.finditer(text)}))

    # PAN with Luhn
    pans: List[str] = []
    for cand in RE_PAN.findall(text):
        if luhn_check(cand):
            pans.append(re.sub(r"\D", "", cand)[:16] + "…")
    pans = list(sorted(set(pans)))

    out.update({
        "emails": emails,
        "urls": urls,
        "ipv4": ipv4,
        "ipv6": ipv6,
        "handles": handles,
        "phones_it": phones,
        "iban_it": iban,
        "hash_md5": md5s,
        "hash_sha1": sha1s,
        "hash_sha256": sha256s,
        "jwt_tokens": jwts,
        "secrets_like": secrets,
        "pan_candidates": pans,
    })
    return out


def summarize_risks(findings: List[Dict]) -> Dict[str, int]:
    risk = {
        "emails": 0,
        "phones": 0,
        "iban": 0,
        "secrets": 0,
        "jwt": 0,
        "pan": 0,
        "hashes": 0,
        "ip": 0,
        "urls": 0,
    }
    for it in findings:
        if it.get("emails"): risk["emails"] += len(it["emails"])  # type: ignore
        if it.get("phones_it"): risk["phones"] += len(it["phones_it"])  # type: ignore
        if it.get("iban_it"): risk["iban"] += len(it["iban_it"])  # type: ignore
        if it.get("secrets_like"): risk["secrets"] += len(it["secrets_like"])  # type: ignore
        if it.get("jwt_tokens"): risk["jwt"] += len(it["jwt_tokens"])  # type: ignore
        if it.get("pan_candidates"): risk["pan"] += len(it["pan_candidates"])  # type: ignore
        hashes = sum(len(it.get(k, [])) for k in ("hash_md5","hash_sha1","hash_sha256"))
        risk["hashes"] += hashes
        ips = len(it.get("ipv4", [])) + len(it.get("ipv6", []))
        risk["ip"] += ips
        if it.get("urls"): risk["urls"] += len(it["urls"])  # type: ignore
    return risk


def save_dataset_md(stem: str, report: Dict) -> None:
    md = [
        f"# Dataset Triage Report\n",
        f"- Root: `{report['root']}`\n- Creato (UTC): {report['created_utc']}\n- Elementi: {report['total_items']}\n",
        "## Rischi sintetici (conteggi grezzi)\n",
        "| Emails | Phones | IBAN | Secrets | JWT | PAN | Hashes | IP | URLs |\n|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n",
        "| {emails} | {phones} | {iban} | {secrets} | {jwt} | {pan} | {hashes} | {ip} | {urls} |\n".format(**report["risk_summary"]) ,
        "\n## Findings\n",
    ]
    for it in report["findings"]:
        path = it.get("path", "")
        md.append(f"### {path}\n")
        if it.get("error"):
            md.append(f"- ERRORE: {it['error']}\n")
            continue
        md.append(f"- MIME: {it.get('mime','')}\n- Size: {it.get('size','')}\n")
        for key in ["emails","handles","urls","ipv4","ipv6","phones_it","iban_it","jwt_tokens","secrets_like","pan_candidates","hash_md5","hash_sha1","hash_sha256","env_keys"]:
            vals = it.get(key)
            if vals:
                sample = ", ".join(map(str, list(vals)[:10]))
                md.append(f"- {key}: {len(vals)} (esempi: {sample})\n")
        if it.get("preview"):
            snip = str(it["preview"]).replace("\n"," ")
            if len(snip) > 160:
                snip = snip[:160] + "…"
            md.append(f"- Preview: `{snip}`\n")
        if it.get("sha256"):
            md.append(f"- SHA256: `{it['sha256']}`\n")
        md.append("")
    (OUTPUT_DIR / f"{stem}.md").write_text("\n".join(md))


# --- Menu principale ------------------------------------------------------

def main() -> None:
    print(f"\n{APP_NAME} — Console Toolkit\n")
    while True:
        print("Seleziona un modulo:")
        print("  1) Crea profilo digitale")
        print("  2) Verifica catena di custodia")
        print("  3) Crea timeline")
        print("  4) Analizza dataset sospetto")
        print("  0) Esci")
        choice = input("\nScelta: ").strip()
        if choice == "1":
            create_digital_profile()
        elif choice == "2":
            chain_of_custody()
        elif choice == "3":
            create_timeline()
        elif choice == "4":
            analyze_suspicious_dataset()
        elif choice == "0":
            print("Bye.")
            break
        else:
            print("Scelta non valida. Riprova.")
        print("\n—" * 30 + "\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrotto dall'utente.")
