import nvdlib
import pandas as pd
from datetime import datetime, timedelta, timezone
import time
import os
from tqdm import tqdm
from colorama import Fore, Style, init
import smtplib
from email.mime.text import MIMEText
from dotenv import load_dotenv


load_dotenv()

init(autoreset=True)

# --- CONFIGURAÇÕES ---
API_KEY = os.getenv("NVD_API_KEY")
EMAIL_REMETENTE = os.getenv("EMAIL_REMETENTE")
EMAIL_SENHA = os.getenv("EMAIL_SENHA")
EMAIL_DESTINO = os.getenv("EMAIL_DESTINO")

ARQUIVO_HISTORICO = "vulnerabilidades_semestre.xlsx" 
ARQUIVO_CONTROLE = 'ultima_execucao.txt'
INTERVALO_SEGUNDOS = 3600 
SMTP_SERVIDOR = "smtp.gmail.com"
SMTP_PORTA = 587

ativos = ["Windows Server", "Elasticsearch", "ChromeOS", "Tor Browser", "Aruba"]

def enviar_email_alerta(vulnerabilidades):
    if not vulnerabilidades:
        return
    
    LIMITE_EMAIL = 15
    vulns_para_enviar = vulnerabilidades[:LIMITE_EMAIL]
    
    corpo = f"🚨 {len(vulnerabilidades)} NOVAS VULNERABILIDADES DETECTADAS 🚨\n\n"
    
    for v in vulns_para_enviar:
        descricao = str(v.get('Descrição', 'Sem descrição'))[:150]

        corpo += (
            f"Ativo: {v['Ativo']}\n"
            f"CVE: {v['CVE']}\n"
            f"Criticidade: {v['Criticidade']}\n"
            f"Score: {v['CVSS Score']}\n"
            f"Data Publicação: {v.get('Data Publicação CVE')}\n"
            f"Descrição: {descricao}...\n"
            f"{'-'*50}\n"
        )

    if len(vulnerabilidades) > LIMITE_EMAIL:
        corpo += f"\n... e mais {len(vulnerabilidades) - LIMITE_EMAIL} vulnerabilidades. Verifique a planilha completa!"

    msg = MIMEText(corpo)
    msg['Subject'] = f"🚨 Alerta de Vulnerabilidades ({len(vulnerabilidades)} novas)"
    msg['From'] = EMAIL_REMETENTE
    msg['To'] = EMAIL_DESTINO

    try:
        servidor = smtplib.SMTP(SMTP_SERVIDOR, SMTP_PORTA)
        servidor.starttls()
        servidor.login(EMAIL_REMETENTE, EMAIL_SENHA)
        servidor.send_message(msg)
        servidor.quit()
        print(f"{Fore.GREEN}📧 Email enviado com sucesso!")
    except Exception as e:
        print(f"{Fore.RED}❌ Erro ao enviar email: {e}")

# --- FUNÇÕES DE MEMÓRIA (CHECKPOINT) ---
def obter_data_inicio():
    if os.path.exists(ARQUIVO_CONTROLE):
        with open(ARQUIVO_CONTROLE, 'r') as f:
            data_str = f.read().strip()
            try:
                return datetime.fromisoformat(data_str)
            except ValueError:
                pass
    return datetime.now(timezone.utc) - timedelta(hours=12)

def atualizar_data_execucao(data_agora):
    with open(ARQUIVO_CONTROLE, 'w') as f:
        f.write(data_agora.isoformat())

# --- FUNÇÕES DE PROCESSAMENTO ---
def classificar_cvss(score):
    if score is None: return "N/A"
    try:
        s = float(score)
        if s >= 9.0: return "Crítico"
        elif s >= 7.0: return "Alto"
        elif s >= 4.0: return "Médio"
        else: return "Baixo"
    except: return "N/A"

def buscar_vulnerabilidades_nvd(data_inicio, data_fim):
    lista_encontrada = []
    vistos = set()
    sucesso_total = True # Flag para garantir a integridade do checkpoint

    print(f"\n{Fore.BLUE}{'='*60}")
    print(f"{Fore.BLUE}🔍 VARREDURA: {data_inicio.strftime('%Y-%m-%d %H:%M')} até {data_fim.strftime('%Y-%m-%d %H:%M')}")
    print(f"{Fore.BLUE}{'='*60}\n")

    for ativo in tqdm(ativos, desc="Verificando Ativos"):
        tentativas = 3
        while tentativas > 0:
            try:
                intervalo = timedelta(days=7)
                data_atual = data_inicio

                while data_atual < data_fim:
                    data_proxima = min(data_atual + intervalo, data_fim)

                    inicio_api = data_atual.strftime("%Y-%m-%d %H:%M")
                    fim_api = data_proxima.strftime("%Y-%m-%d %H:%M")

                    tqdm.write(f"📅 {ativo} | {inicio_api} → {fim_api}")

                    resultados = nvdlib.searchCVE(
                        keywordSearch=ativo,
                        key=API_KEY,
                        pubStartDate=inicio_api,
                        pubEndDate=fim_api
                    )
                    
                    # ⏱️ Pausa de Rate Limit IMEDIATAMENTE após bater na API
                    time.sleep(6)

                    for cve in resultados:
                        chave = (cve.id, ativo)
                        if chave in vistos:
                            continue
                        vistos.add(chave)

                        score = None
                        if hasattr(cve, "score") and cve.score and len(cve.score) > 1:
                            score = cve.score[1]
                        elif hasattr(cve, "v31score"):
                            score = cve.v31score
                        
                        # Extração de Descrição Padronizada
                        descricao = "Sem descrição"
                        if hasattr(cve, "descriptions") and cve.descriptions:
                            val = cve.descriptions[0].value
                            descricao = val[:300] + ("..." if len(val) > 300 else "")
                        
                        lista_encontrada.append({
                            "Data Identificação": datetime.now(timezone.utc),
                            "Data Publicação CVE": getattr(cve, "published", None),
                            "Ativo": ativo,
                            "CVE": cve.id,
                            "CVSS Score": score,
                            "Criticidade": classificar_cvss(score),
                            "Descrição": descricao
                        })
                    
                    data_atual = data_proxima # Avança o intervalo

                break # Sai do loop de tentativas se deu tudo certo com este ativo

            except Exception as e:
                tentativas -= 1
                if tentativas > 0:
                    tqdm.write(f"{Fore.RED}⚠️ Falha em {ativo}: {e}. Nova tentativa em 10s...")
                    time.sleep(10)
                else:
                    tqdm.write(f"{Fore.RED}❌ Erro persistente em {ativo}. Pulando ativo e segurando o checkpoint.")
                    sucesso_total = False # Se falhou de vez, não atualiza o checkpoint global
    
    return lista_encontrada, sucesso_total

def executar_monitoramento():
    agora = datetime.now(timezone.utc)
    data_inicio = obter_data_inicio()
    
    if (agora - data_inicio).days > 120:
        print(f"{Fore.YELLOW}⚠️ Aviso: Intervalo maior que 120 dias detectado. Ajustando para o limite da API.")
        data_inicio = agora - timedelta(days=120)
    
    # Agora a função retorna a lista E a flag de segurança
    novas_descobertas, sucesso_total = buscar_vulnerabilidades_nvd(data_inicio, agora)
    
    df_antigo = pd.DataFrame()
    cves_existentes = set()
    
    if os.path.exists(ARQUIVO_HISTORICO):
        try:
            df_antigo = pd.read_excel(ARQUIVO_HISTORICO)
            cves_existentes = set(zip(df_antigo['CVE'].astype(str), df_antigo['Ativo'].astype(str)))
        except Exception as e:
            print(f"{Fore.RED}Erro ao ler Excel: {e}")

    vulnerabilidades_para_alertar = [
        item for item in novas_descobertas
        if (item['CVE'], item['Ativo']) not in cves_existentes
    ]

    print(f"\n{Fore.MAGENTA}{'-'*60}")
    if vulnerabilidades_para_alertar:
        print(f"{Fore.GREEN}✨ SUCESSO! {len(vulnerabilidades_para_alertar)} novas CVEs encontradas.")
        enviar_email_alerta(vulnerabilidades_para_alertar)
        
        df_novos = pd.DataFrame(vulnerabilidades_para_alertar)
        df_final = pd.concat([df_antigo, df_novos], ignore_index=True)

        df_final["Data Identificação"] = pd.to_datetime(df_final["Data Identificação"], errors='coerce').dt.tz_localize(None)
        df_final["Data Publicação CVE"] = pd.to_datetime(df_final["Data Publicação CVE"], errors='coerce').dt.tz_localize(None)

        ordem_criticidade = {"Crítico": 4, "Alto": 3, "Médio": 2, "Baixo": 1, "N/A": 0}
        df_final["Prioridade"] = df_final["Criticidade"].map(ordem_criticidade)

        df_final = df_final.sort_values(by=["Prioridade", "Data Identificação"], ascending=[False, False])
        df_final = df_final.drop(columns=["Prioridade"])
        
        try:
            arquivo_temp = "temp_vulnerabilidades.xlsx"
            df_final.to_excel(arquivo_temp, index=False)
            os.replace(arquivo_temp, ARQUIVO_HISTORICO)
            print(f"{Fore.GREEN}💾 Arquivo {ARQUIVO_HISTORICO} atualizado.")
            
            # Atualiza o checkpoint APENAS se nenhum ativo foi pulado devido a erros da API
            if sucesso_total:
                atualizar_data_execucao(agora)
            else:
                print(f"{Fore.YELLOW}⚠️ Dados salvos, mas o Checkpoint de tempo não foi atualizado devido a falhas de conexão anteriores.")

        except PermissionError:
            print(f"{Fore.RED}❌ ERRO: Feche o arquivo Excel para salvar os dados!")
    else:
        print(f"{Fore.WHITE}☕ Varredura concluída. Sem novidades no momento.")
        if sucesso_total:
            atualizar_data_execucao(agora)
        else:
            print(f"{Fore.YELLOW}⚠️ Checkpoint não atualizado devido a falhas de conexão em alguns ativos.")
    
    print(f"{Fore.MAGENTA}{'-'*60}\n")

# --- LOOP PRINCIPAL ---
print(f"{Fore.CYAN}🚀 SISTEMA DE MONITORAMENTO INICIALIZADO")

try:
    while True:
        executar_monitoramento()

        proxima = datetime.now() + timedelta(seconds=INTERVALO_SEGUNDOS)
        print(f"\n{Fore.BLUE}🕒 Próxima execução: {proxima.strftime('%H:%M:%S')}")
        print(f"{Fore.BLUE}😴 Próxima busca em {INTERVALO_SEGUNDOS//60} minutos...")

        for i in range(INTERVALO_SEGUNDOS, 0, -1):
            if i > 60:
                if i % 60 == 0:
                    print(f"\r⏳ Aguardando: {i//60} min restantes...      ", end="", flush=True)
            else:
                print(f"\r⏳ Aguardando: {i} seg restantes...      ", end="", flush=True)

            time.sleep(1)

except KeyboardInterrupt:
    print(f"{Fore.YELLOW}\n🛑 Sistema encerrado manualmente.")