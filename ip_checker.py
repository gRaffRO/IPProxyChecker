import requests
import pandas as pd
from datetime import datetime
import os

class IPChecker:
    def __init__(self, api_key):
        self.api_key = api_key
        self.latest_df = pd.DataFrame()
        self.latest_df_raw = []
        
    def check_ip(self, ip):
        url = f"https://ipqualityscore.com/api/json/ip/{self.api_key}/{ip}"
        try:
            session = requests.Session()
            adapter = requests.adapters.HTTPAdapter(max_retries=3)
            session.mount('https://', adapter)
            
            response = session.get(url, timeout=30)
            if response.status_code != 200:
                return self._error_response(ip, f"Eroare API: {response.status_code}")
                
            data = response.json()
            if "success" in data and not data["success"]:
                return self._error_response(ip, f"Eroare API: {data.get('message', 'Necunoscută')}")
                
            return {
                # Secțiunea 1: Informații de bază
                "IP": ip,
                "Țară": data.get("country_code", ""),
                "Oraș": data.get("city", ""),
                "ISP": data.get("ISP", ""),
                "Organizație": data.get("organization", ""),
                
                # Secțiunea 2: Securitate
                "Proxy/VPN": data.get("proxy", False),
                "VPN": data.get("vpn", False),
                "TOR": data.get("tor", False),
                "Bot Status": data.get("bot_status", False),
                
                # Secțiunea 3: Risc
                "Scor Fraudă": data.get("fraud_score", 0),
                "Abuz Recent": data.get("recent_abuse", False),
                "Crawler": data.get("crawler", False)
            }
        except requests.exceptions.Timeout:
            return self._error_response(ip, "Timeout - API nu a răspuns la timp")
        except requests.exceptions.RequestException as e:
            return self._error_response(ip, f"Eroare conexiune: {str(e)}")
        except Exception as e:
            return self._error_response(ip, f"Eroare neașteptată: {str(e)}")

    def _error_response(self, ip, error_message):
        return {
            "IP": ip,
            "Țară": "",
            "Oraș": "",
            "ISP": error_message,
            "Organizație": "",
            "Proxy/VPN": False,
            "VPN": False,
            "TOR": False,
            "Bot Status": False,
            "Scor Fraudă": 0,
            "Abuz Recent": False,
            "Crawler": False
        }

    def process_ips(self, single_ip=None, multi_ip=None, file=None):
        self.latest_df = pd.DataFrame()
        self.latest_df_raw = []
        results = []

        if single_ip:
            results.append(self.check_ip(single_ip.strip()))
        elif multi_ip:
            ip_lines = [line.strip() for line in multi_ip.strip().splitlines() if line.strip()]
            if len(ip_lines) > 20:
                return None, "too_many_ips"
            self.latest_df_raw = ip_lines
            results = [self.check_ip(ip.split(":")[0]) for ip in ip_lines]
        elif file:
            content = file.read().decode("utf-8")
            self.latest_df_raw = [line.strip() for line in content.splitlines() if line.strip()]
            ip_lines = [line.strip().split(":")[0] for line in content.splitlines() if line.strip()]
            results = [self.check_ip(ip) for ip in ip_lines]

        if results:
            for entry in results:
                country = entry.get("Țară", "")
                if country:
                    entry["Țară"] = f"<img src='https://flagcdn.com/16x12/{country.lower()}.png' alt='{country}' style='margin-right:4px;'> {country}"

            self.latest_df = pd.DataFrame(results)
            timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
            os.makedirs("scans", exist_ok=True)
            self.latest_df.to_csv(f"scans/scan_{timestamp}.csv", index=False)

        return results, None

    def create_html_table(self, results):
        if not results:
            return None
            
        df = pd.DataFrame(results)
        
        # Definim secțiunile și coloanele lor
        sections = {
            "Informații de bază": ["IP", "Țară", "Oraș", "ISP", "Organizație"],
            "Securitate": ["Proxy/VPN", "VPN", "TOR", "Bot Status"],
            "Risc": ["Scor Fraudă", "Abuz Recent", "Crawler"]
        }
        
        # Începem construirea tabelului HTML
        html = ['<table class="data">']
        
        # Adăugăm header-ul principal cu secțiuni
        html.append('<thead>')
        html.append('<tr class="section-header">')
        for section, cols in sections.items():
            html.append(f'<th colspan="{len(cols)}">{section}</th>')
        html.append('</tr>')
        
        # Adăugăm sub-header-ul cu numele coloanelor
        html.append('<tr>')
        for section, cols in sections.items():
            for col in cols:
                html.append(f'<th>{col}</th>')
        html.append('</tr>')
        html.append('</thead>')
        
        # Adăugăm corpul tabelului
        html.append('<tbody>')
        for _, row in df.iterrows():
            html.append('<tr>')
            for section, cols in sections.items():
                for col in cols:
                    value = row[col]
                    
                    # Determinăm clasa CSS pentru celulă
                    css_class = ""
                    if col == "Scor Fraudă":
                        score = float(value) if isinstance(value, (int, float)) else 0
                        if score <= 10:
                            css_class = "score-green"
                        elif score <= 30:
                            css_class = "score-yellow"
                        elif score <= 50:
                            css_class = "score-orange"
                        else:
                            css_class = "score-red"
                    elif col in ["Proxy/VPN", "VPN", "TOR", "Bot Status", "Abuz Recent", "Crawler"] and str(value).lower() == "true":
                        css_class = "vpn-tor"
                    
                    # Formatăm valoarea pentru afișare
                    if isinstance(value, bool):
                        display_value = "Da" if value else "Nu"
                    else:
                        display_value = str(value) if pd.notna(value) else "-"
                    
                    # Construim celula cu sau fără clasă CSS
                    if css_class:
                        html.append(f'<td class="{css_class}">{display_value}</td>')
                    else:
                        html.append(f'<td>{display_value}</td>')
            
            html.append('</tr>')
        html.append('</tbody></table>')
        
        return ''.join(html)

    def filter_results(self, filter_type):
        if filter_type == 'score_lt_50':
            return self.latest_df[self.latest_df['Scor Fraudă'] < 50]
        elif filter_type == 'no_proxy':
            return self.latest_df[self.latest_df['Proxy/VPN'] == False]
        elif filter_type == 'no_tor':
            return self.latest_df[self.latest_df['TOR'] == False]
        elif filter_type == 'no_tor_vpn':
            return self.latest_df[(self.latest_df['TOR'] == False) & (self.latest_df['Proxy/VPN'] == False)]
        elif filter_type == 'clean_proxies':
            return self.latest_df[(self.latest_df['Scor Fraudă'] < 40) &
                                (self.latest_df['TOR'] == False) &
                                (self.latest_df['VPN'] == False) &
                                (self.latest_df['Proxy/VPN'] == False) &
                                (self.latest_df['Abuz Recent'] == False)]
        return None

    def generate_csv(self, df):
        if 'IP' in df.columns:
            original_lines = []
            for ip in df['IP']:
                for line in self.latest_df_raw:
                    if line.startswith(ip):
                        original_lines.append(line)
                        break
            df_out = pd.DataFrame({'Proxy': original_lines})
        else:
            df_out = df

        return df_out.to_csv(index=False, header=False)