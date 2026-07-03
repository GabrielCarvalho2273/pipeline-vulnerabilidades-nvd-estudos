# Pipeline de Vulnerabilidades via NVD API

Pipeline de coleta, priorização e alerta de vulnerabilidades (CVEs), usando a API do NVD (National Vulnerability Database). Monitora um conjunto de ativos de exemplo, calcula um score de risco contextual (não só CVSS puro) e gera relatórios e alertas por email.

## O que o pipeline faz

1. **Coleta** — busca CVEs publicadas para os ativos monitorados via API do NVD, com checkpoint de execução (não perde progresso entre execuções)
2. **Classificação** — categoriza cada CVE por criticidade com base no score CVSS
3. **Priorização de risco** — calcula um score de risco real, combinando:
   - Peso do ativo afetado
   - Criticidade (CVSS)
   - Exposição a execução remota de código (RCE)
   - Aging (tempo desde a publicação)
   - **Nível de explorabilidade em 3 camadas** (ver abaixo)
4. **Alerta** — envia email automático quando novas vulnerabilidades relevantes são encontradas
5. **Relatório** — gera planilha Excel formatada, ordenada por risco, pronta para leitura

## Detecção de explorabilidade em 3 níveis

Um dos pontos centrais do projeto: nem toda CVE com CVSS alto é uma prioridade real. O pipeline cruza a criticidade com sinais de exploração ativa, em ordem de confiabilidade:

1. **KEV da CISA** (peso mais alto) — fonte oficial curada por analistas, indicando exploração confirmada em ambiente real
2. **Confirmação por texto** — regex sobre a descrição da CVE buscando termos como "actively exploited", "in the wild", "PoC público", "Metasploit"
3. **Alta explorabilidade** — padrões de classes de vulnerabilidade historicamente fáceis de explorar (buffer overflow, privilege escalation, command injection, etc.)

Essa cascata evita que uma CVE crítica mas teórica seja tratada com a mesma urgência de uma que já está sendo explorada de verdade.

## Arquivos

- `1hora.py` — monitoramento contínuo (roda em loop, verifica novidades periodicamente, envia alerta por email)
- `vulnerabilidades_semestral.py` — varredura histórica ampla (últimos 120 dias), para levantamento inicial da base
- `organizar_vuln.py` — gera o relatório quinzenal formatado a partir da base consolidada, aplicando o cálculo de risco e a formatação visual no Excel

## Tecnologias

- Python 3
- nvdlib (API do NVD)
- pandas / openpyxl (processamento e formatação de planilhas)
- python-dotenv (variáveis de ambiente)
- smtplib (alertas por email)

## Configuração

Crie um arquivo `.env` na raiz do projeto (não é versionado) com:
```
NVD_API_KEY=sua_chave_aqui
EMAIL_REMETENTE=seu_email@gmail.com
EMAIL_SENHA=sua_senha_de_app
EMAIL_DESTINO=email_para_receber_alertas@gmail.com
```

A chave da API do NVD pode ser solicitada gratuitamente em nvd.nist.gov/developers/request-an-api-key.

## Como rodar

```bash
pip install nvdlib pandas openpyxl python-dotenv colorama tqdm
python vulnerabilidades_semestral.py   # levantamento inicial (roda uma vez)
python 1hora.py                         # monitoramento contínuo
python organizar_vuln.py                # gera o relatório quinzenal formatado
```

## Segurança

Credenciais e chaves de API são carregadas via variáveis de ambiente (`.env`, fora do controle de versão), nunca hardcoded no código-fonte.

## Sobre
Projeto desenvolvido como parte do meu aprendizado em segurança da informação e gestão de vulnerabilidades, com apoio de IA (Claude/Gemini) como ferramenta de estudo. Feedbacks são bem-vindos.
