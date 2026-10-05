#!/usr/bin/env python3
"""Windows Security Log Analyzer.

Triagem de eventos do Windows (Security log) com foco em SOC Nível 1:

* 4625 - falha de logon  -> força bruta e password spraying
* 4624 - logon com sucesso -> sucesso após ataque (comprometimento provável)
* 4688 - criação de processo -> comandos suspeitos

Cada detecção é mapeada ao MITRE ATT&CK. Usa apenas a biblioteca padrão.
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

# Nomes alternativos aceitos para cada campo (comparação sem diferenciar maiúsculas).
FIELD_ALIASES = {
    "time": ("timecreated", "time", "timestamp", "date"),
    "event_id": ("eventid", "id", "event_id"),
    "host": ("computer", "host", "machinename"),
    "target_user": ("targetusername", "username", "user"),
    "subject_user": ("subjectusername",),
    "ip": ("ipaddress", "sourceip", "ip", "sourcenetworkaddress"),
    "logon_type": ("logontype",),
    "process": ("newprocessname", "process", "processname"),
    "command_line": ("commandline", "command_line"),
    "parent": ("parentprocessname", "parent"),
}


@dataclass
class Event:
    time: datetime
    event_id: int
    host: str = ""
    user: str = ""
    ip: str = ""
    logon_type: str = ""
    process: str = ""
    command_line: str = ""
    parent: str = ""


@dataclass
class Finding:
    severity: str
    title: str
    technique: str
    description: str
    evidence: list = field(default_factory=list)
    recommendation: str = ""


# --------------------------------------------------------------------------- #
# Leitura dos logs
# --------------------------------------------------------------------------- #
def parse_time(value: str) -> datetime:
    """Converte texto ISO 8601 em datetime sem fuso (normalizado para UTC)."""
    text = value.strip().replace("Z", "+00:00")
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def _pick(row: dict, key: str) -> str:
    lowered = {k.lower().strip(): v for k, v in row.items() if k}
    for alias in FIELD_ALIASES[key]:
        value = lowered.get(alias)
        if value not in (None, ""):
            return str(value).strip()
    return ""


def _clean(value: str) -> str:
    return "" if value in ("-", "::1", "127.0.0.1") else value


def row_to_event(row: dict) -> Event | None:
    event_id_text = _pick(row, "event_id")
    time_text = _pick(row, "time")
    if not event_id_text.isdigit() or not time_text:
        return None
    event_id = int(event_id_text)
    # Em 4688 o usuário está em SubjectUserName; em 4624/4625, em TargetUserName.
    user = _pick(row, "subject_user") if event_id == 4688 else _pick(row, "target_user")
    return Event(
        time=parse_time(time_text),
        event_id=event_id,
        host=_pick(row, "host"),
        user=_clean(user),
        ip=_clean(_pick(row, "ip")),
        logon_type=_pick(row, "logon_type"),
        process=_pick(row, "process"),
        command_line=_pick(row, "command_line"),
        parent=_pick(row, "parent"),
    )


def load_events(path: str) -> list[Event]:
    """Lê CSV, JSON (lista) ou JSON Lines exportado do Windows."""
    file = Path(path)
    if file.suffix.lower() == ".csv":
        with file.open(newline="", encoding="utf-8-sig") as handle:
            rows = list(csv.DictReader(handle))
    else:
        raw = file.read_text(encoding="utf-8-sig").strip()
        if raw.startswith("["):
            rows = json.loads(raw)
        else:
            rows = [json.loads(line) for line in raw.splitlines() if line.strip()]
    events = [e for e in (row_to_event(r) for r in rows) if e]
    return sorted(events, key=lambda e: e.time)


# --------------------------------------------------------------------------- #
# Detecções: 4625 / 4624
# --------------------------------------------------------------------------- #
def detect_password_attacks(events, threshold=5, spray_users=5,
                            window=timedelta(minutes=5)):
    """Força bruta (T1110.001) e password spraying (T1110.003) em eventos 4625.

    Retorna (achados, ataques) onde ``ataques`` mapeia IP -> dados do ataque,
    usado depois para correlacionar com logons bem-sucedidos.
    """
    failures = defaultdict(list)
    for event in events:
        if event.event_id == 4625 and event.ip:
            failures[event.ip].append(event)

    findings, attacks = [], {}
    for ip, fails in failures.items():
        best_brute = best_spray = None
        for i, start in enumerate(fails):
            chunk = [e for e in fails[i:] if e.time - start.time <= window]
            users = Counter(e.user for e in chunk)
            top_user, top_count = users.most_common(1)[0]
            if top_count >= threshold and (not best_brute or top_count > best_brute[0]):
                best_brute = (top_count, top_user, chunk[0].time, chunk[-1].time)
            if len(users) >= spray_users and (not best_spray or len(users) > best_spray[0]):
                best_spray = (len(users), len(chunk), chunk[0].time, chunk[-1].time, set(users))

        if best_brute:
            count, user, first, last = best_brute
            findings.append(Finding(
                "HIGH", f"Força bruta contra '{user}' a partir de {ip}", "T1110.001",
                f"{count} falhas de logon (4625) para a mesma conta em até "
                f"{int(window.total_seconds() // 60)} min.",
                [f"IP de origem: {ip}", f"Conta alvo: {user}", f"Janela: {first} a {last}"],
                f"Bloquear {ip} no firewall, revisar a conta '{user}' e habilitar MFA/bloqueio por tentativas.",
            ))
            attacks.setdefault(ip, {"first": first, "users": set()})["users"].add(user)
        if best_spray:
            n_users, n_fails, first, last, users = best_spray
            findings.append(Finding(
                "HIGH", f"Password spraying a partir de {ip}", "T1110.003",
                f"{n_fails} falhas contra {n_users} contas diferentes pelo mesmo IP em poucos minutos.",
                [f"IP de origem: {ip}", f"Contas visadas: {', '.join(sorted(users))}",
                 f"Janela: {first} a {last}"],
                f"Bloquear {ip}, verificar se alguma das contas teve logon bem-sucedido e forçar troca de senhas fracas.",
            ))
            info = attacks.setdefault(ip, {"first": first, "users": set()})
            info["first"] = min(info["first"], first)
            info["users"] |= users
    return findings, attacks


def detect_success_after_attack(events, attacks):
    """Logon bem-sucedido (4624) vindo de um IP que atacou: provável comprometimento."""
    findings = []
    for event in events:
        info = attacks.get(event.ip)
        if event.event_id == 4624 and info and event.time >= info["first"]:
            targeted = event.user in info["users"]
            findings.append(Finding(
                "CRITICAL", f"Logon bem-sucedido de {event.ip} após ataque de senhas",
                "T1078 (após T1110)",
                "Um IP que fez tentativas de adivinhar senhas conseguiu autenticar. "
                "Tratar a conta como comprometida.",
                [f"Hora: {event.time}", f"Conta: {event.user}"
                 + (" (estava entre as contas atacadas)" if targeted else ""),
                 f"Tipo de logon: {event.logon_type or 'n/d'}", f"Host: {event.host or 'n/d'}"],
                f"Escalar ao analista sênior, isolar o host {event.host or ''}, "
                f"redefinir a senha de '{event.user}', encerrar sessões e revisar atividade posterior.",
            ))
    return findings


# --------------------------------------------------------------------------- #
# Detecções: 4688
# --------------------------------------------------------------------------- #
PROCESS_RULES = [
    ("PowerShell com comando codificado", r"powershell.*\s-(?:e|enc|encodedcommand)\s+[A-Za-z0-9+/=]{10,}", "HIGH", "T1059.001"),
    ("Download via certutil", r"certutil.*-urlcache", "HIGH", "T1105"),
    ("Download via bitsadmin", r"bitsadmin.*/transfer", "MEDIUM", "T1197"),
    ("Reconhecimento: whoami com privilégios", r"whoami(?:\.exe)?\s+/(?:all|priv|groups)", "MEDIUM", "T1033"),
    ("Criação de usuário local", r"net1?\s+user\s+\S+\s+\S+\s+/add", "HIGH", "T1136.001"),
    ("Adição ao grupo Administradores", r"net1?\s+localgroup\s+administrators\s+\S+\s+/add", "HIGH", "T1098"),
    ("Ferramenta de roubo de credenciais", r"mimikatz|sekurlsa|lsadump", "CRITICAL", "T1003"),
    ("Dump do LSASS via comsvcs", r"comsvcs(?:\.dll)?.*minidump", "CRITICAL", "T1003.001"),
    ("Cópia dos hives SAM/SYSTEM", r"reg(?:\.exe)?\s+save\s+hklm\\(?:sam|system|security)", "HIGH", "T1003.002"),
    ("Tarefa agendada criada", r"schtasks.*/create", "MEDIUM", "T1053.005"),
    ("Remoção de shadow copies", r"vssadmin.*delete\s+shadows", "CRITICAL", "T1490"),
]
OFFICE_PARENTS = ("winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe")
SHELLS = ("cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe")


def detect_suspicious_processes(events):
    findings = []
    for event in events:
        if event.event_id != 4688:
            continue
        text = f"{event.process} {event.command_line}".lower()
        evidence = [f"Hora: {event.time}", f"Host: {event.host or 'n/d'}",
                    f"Usuário: {event.user or 'n/d'}", f"Processo: {event.process}",
                    f"Linha de comando: {event.command_line or 'n/d'}"]
        for title, pattern, severity, technique in PROCESS_RULES:
            if re.search(pattern, text, re.IGNORECASE):
                findings.append(Finding(
                    severity, title, technique,
                    "Criação de processo (4688) com padrão associado a atividade maliciosa.",
                    evidence, "Validar com o usuário/host, coletar o processo pai e escalar se não for atividade legítima."))
        parent = event.parent.lower().rsplit("\\", 1)[-1]
        child = event.process.lower().rsplit("\\", 1)[-1]
        if parent in OFFICE_PARENTS and child in SHELLS:
            findings.append(Finding(
                "HIGH", f"Aplicativo Office iniciou {child}", "T1204.002",
                "Documento do Office abrindo um interpretador de comandos é típico de macro maliciosa.",
                evidence + [f"Processo pai: {event.parent}"],
                "Isolar o host, obter o documento de origem e verificar o e-mail que o entregou."))
    return findings


# --------------------------------------------------------------------------- #
# Análise completa e relatório
# --------------------------------------------------------------------------- #
def analyze(events, threshold=5, spray_users=5, window_minutes=5):
    window = timedelta(minutes=window_minutes)
    findings, attacks = detect_password_attacks(events, threshold, spray_users, window)
    findings += detect_success_after_attack(events, attacks)
    findings += detect_suspicious_processes(events)
    return sorted(findings, key=lambda f: SEVERITY_ORDER[f.severity])


def to_markdown(findings, total_events):
    counts = Counter(f.severity for f in findings)
    lines = ["# Relatório de Triagem - Logs do Windows", "",
             f"Eventos analisados: **{total_events}** | Achados: **{len(findings)}**", "",
             "| Severidade | Quantidade |", "|---|---|"]
    lines += [f"| {s} | {counts[s]} |" for s in SEVERITY_ORDER if counts[s]]
    for i, f in enumerate(findings, 1):
        lines += ["", f"## {i}. [{f.severity}] {f.title}", "",
                  f"**MITRE ATT&CK:** {f.technique}", "", f.description, ""]
        lines += [f"- {e}" for e in f.evidence]
        lines += ["", f"**Recomendação:** {f.recommendation}"]
    if not findings:
        lines += ["", "Nenhum achado com as regras atuais."]
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description="Triagem de logs de segurança do Windows (4624/4625/4688).")
    parser.add_argument("arquivo", help="CSV ou JSON exportado do Security log")
    parser.add_argument("--threshold", type=int, default=5, help="falhas na mesma conta para força bruta (padrão 5)")
    parser.add_argument("--spray-users", type=int, default=5, help="contas distintas para password spraying (padrão 5)")
    parser.add_argument("--window", type=int, default=5, help="janela em minutos (padrão 5)")
    parser.add_argument("--format", choices=("md", "json"), default="md")
    parser.add_argument("-o", "--output", help="salvar relatório em arquivo")
    args = parser.parse_args(argv)

    events = load_events(args.arquivo)
    findings = analyze(events, args.threshold, args.spray_users, args.window)
    if args.format == "json":
        output = json.dumps([asdict(f) for f in findings], ensure_ascii=False, indent=2)
    else:
        output = to_markdown(findings, len(events))
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"Relatório salvo em {args.output} ({len(findings)} achados)")
    else:
        print(output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
