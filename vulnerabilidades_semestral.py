import nvdlib
import pandas as pd
from datetime import datetime, timedelta, timezone
import time
import os
from colorama import Fore, Style, init
from dotenv import load_dotenv

load_dotenv()

init(autoreset=True)

API_KEY = os.getenv("NVD_API_KEY") 

ARQUIVO = "vulnerabilidades_semestre.xlsx"
ativos = ["Windows Server", "Elasticsearch", "ChromeOS", "Tor Browser", "Aruba"]

# --- AJUSTE 3: PERFORMANCE E CONSISTÊNCIA ---
agora_execucao = datetime.now(timezone.utc)
data_inicio = agora_execucao - timedelta(days=120)

dados = []
vistos = set()

def classificar_cvss(score):
    if score is None: return "N/A"
    try:
        s = float(score)
        if s >= 9.0: return "Crítico"
        elif s >= 7.0: return "Alto"
        elif s >= 4.0: return "Médio"
        else: return "Baixo"
    except: return "N/A"

for ativo in ativos:
    print(f"\n🔎 {Fore.CYAN}Iniciando varredura histórica para: {ativo}")
    data_atual = data_inicio
    intervalo = timedelta(days=7)

    while data_atual < agora_execucao:
        data_proxima = min(data_atual + intervalo, agora_execucao)
        inicio_str = data_atual.strftime("%Y-%m-%d %H:%M")
        fim_str = data_proxima.strftime("%Y-%m-%d %H:%M")

        print(f"📅 {Fore.YELLOW}Intervalo: {inicio_str} → {fim_str}")

        try:
            resultados = nvdlib.searchCVE(
                keywordSearch=ativo,
                key=API_KEY,
                pubStartDate=inicio_str,
                pubEndDate=fim_str
            )
            
            time.sleep(6)

            # --- AJUSTE 2: PROTEÇÃO RESULTADOS VAZIOS ---
            if not resultados:
                print(f"{Fore.GREEN}✔ Intervalo concluído (limpo): {inicio_str}")
                data_atual = data_proxima
                continue

            for cve in resultados:
                chave = (cve.id, ativo)
                if chave in vistos: continue
                vistos.add(chave)

                score = None
                if hasattr(cve, "score") and cve.score and len(cve.score) > 1:
                    score = cve.score[1]
                elif hasattr(cve, "v31score"):
                    score = cve.v31score

                descricao = "Sem descrição"
                if hasattr(cve, "descriptions") and cve.descriptions:
                    val = cve.descriptions[0].value
                    descricao = val[:300] + ("..." if len(val) > 300 else "")

                dados.append({
                    "Data Identificação": agora_execucao, # Consistente
                    "Data Publicação CVE": getattr(cve, "published", None),
                    "Ativo": ativo,
                    "CVE": cve.id,
                    "CVSS Score": score,
                    "Criticidade": classificar_cvss(score),
                    "Descrição": descricao
                })
            
            # --- AJUSTE 5: DEBUG MELHORADO ---
            print(f"{Fore.GREEN}✔ Intervalo concluído: {inicio_str} | Encontradas: {len(resultados)}")
            
        except Exception as e:
            print(f"{Fore.RED}❌ Erro no intervalo {inicio_str}: {e}")
            time.sleep(10)

        data_atual = data_proxima

# --- GERAÇÃO DO EXCEL ---
if dados:
    df = pd.DataFrame(dados)
    
    # --- AJUSTE 4: PROTEÇÃO CONTRA DUPLICATAS ---
    df = df.drop_duplicates(subset=["CVE", "Ativo"])

    df["Data Identificação"] = pd.to_datetime(df["Data Identificação"]).dt.tz_localize(None)
    df["Data Publicação CVE"] = pd.to_datetime(df["Data Publicação CVE"], errors='coerce').dt.tz_localize(None)

    ordem_criticidade = {"Crítico": 4, "Alto": 3, "Médio": 2, "Baixo": 1, "N/A": 0}
    df["Prioridade"] = df["Criticidade"].map(ordem_criticidade)
    df = df.sort_values(by=["Prioridade", "Data Identificação"], ascending=[False, False])
    df = df.drop(columns=["Prioridade"])

    try:
        df.to_excel(ARQUIVO, index=False)
        print(f"\n{Fore.GREEN}✅ Tudo pronto! Arquivo consolidado: {ARQUIVO}")
    except PermissionError:
        print(f"\n{Fore.RED}❌ FECHE O EXCEL!")