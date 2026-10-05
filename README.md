# Windows Security Log Analyzer

Ferramenta em Python para **triagem de logs de segurança do Windows** no estilo SOC Nível 1. Lê eventos exportados do *Security log* e aponta ataques de senha, comprometimento de contas e comandos suspeitos, com mapeamento ao **MITRE ATT&CK** e recomendação de resposta.

Sem dependências externas: apenas Python 3.9+.

## O que detecta

| Evento | Detecção | MITRE ATT&CK | Severidade |
|---|---|---|---|
| 4625 | Força bruta (várias falhas na mesma conta, mesmo IP) | T1110.001 | Alta |
| 4625 | Password spraying (um IP, várias contas) | T1110.003 | Alta |
| 4624 | Logon bem-sucedido de IP que atacou antes | T1078 | **Crítica** |
| 4688 | PowerShell codificado, certutil/bitsadmin, criação de usuário, dump de credenciais, shadow copies, tarefas agendadas e outros | T1059.001, T1105, T1136.001, T1003, T1490, T1053.005 | Média a crítica |
| 4688 | Office (Word/Excel/Outlook) abrindo cmd/PowerShell | T1204.002 | Alta |

## Instalação e uso

```bash
git clone https://github.com/josuemdea8-pixel/windows-log-analyzer.git
cd windows-log-analyzer
python windows_log_analyzer.py samples/security_sample.csv
```

Opções:

```text
--threshold N     falhas na mesma conta para força bruta (padrão 5)
--spray-users N   contas distintas para password spraying (padrão 5)
--window MIN      janela de tempo em minutos (padrão 5)
--format md|json  formato do relatório (padrão md)
-o ARQUIVO        salva o relatório em arquivo
```

## Como exportar os logs (PowerShell como administrador)

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625,4688} -MaxEvents 5000 |
ForEach-Object {
  $x = [xml]$_.ToXml(); $d = @{}
  $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
  [pscustomobject]@{
    TimeCreated=$_.TimeCreated.ToString('o'); EventID=$_.Id; Computer=$_.MachineName
    TargetUserName=$d['TargetUserName']; SubjectUserName=$d['SubjectUserName']
    IpAddress=$d['IpAddress']; LogonType=$d['LogonType']
    NewProcessName=$d['NewProcessName']; CommandLine=$d['CommandLine']
    ParentProcessName=$d['ParentProcessName']
  }
} | Export-Csv security.csv -NoTypeInformation -Encoding UTF8
```

> O campo `CommandLine` do evento 4688 só é registrado se a política *"Incluir linha de comando em eventos de criação de processo"* estiver habilitada.

Também são aceitos arquivos JSON (lista) e JSON Lines com os mesmos nomes de campos.

## Exemplo de resultado

Com `samples/security_sample.csv` (dados **fictícios**, IPs de documentação RFC 5737), a ferramenta encontra 8 achados, incluindo um logon crítico após força bruta RDP. Veja o relatório completo em [`samples/example_report.md`](samples/example_report.md).

## Testes

```bash
python -m unittest discover -s tests -v
```

12 testes cobrem limiares, janela de tempo, falsos positivos, correlação 4625→4624, regras de processo e o fluxo completo com o arquivo de amostra.

## Limitações

- Regras baseadas em padrões de texto e limiares: ajuste `--threshold`, `--spray-users` e `--window` ao seu ambiente.
- Não consulta reputação de IP (próximo passo: integrar com AbuseIPDB).
- Ferramenta educacional, não substitui um SIEM/EDR.

## Próximos passos

- Eventos 4720/4732 (criação de conta e mudança de grupo) e 1102 (log apagado).
- Exportação de regras no formato Sigma.
- Enriquecimento de IPs com threat intelligence.

## Autor

Josué Moreira, Analista SOC Júnior, Belém/PA.
