from flask import Flask, request, render_template, send_file, jsonify
import pandas as pd
from ip_checker import IPChecker
import io
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
ip_checker = IPChecker(os.getenv('API_KEY', 'YOUR_API_KEY'))

@app.route('/reset', methods=['POST'])
def reset_data():
    ip_checker.latest_df = pd.DataFrame()
    ip_checker.latest_df_raw = []
    return render_template('index.html', table=None)

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    table = None
    if request.method == 'POST':
        single_ip = request.form.get("single_ip")
        multi_ip = request.form.get("multi_ip")
        file = request.files.get('file')
        
        results, error = ip_checker.process_ips(single_ip, multi_ip, file)
        
        if error == "too_many_ips":
            return render_template('index.html', 
                table="<p style='color:red;text-align:center;'>Ai introdus mai mult de 20 de IP-uri. Te rugăm folosește un fișier .txt pentru încărcare.</p>")
        
        if results:
            table = ip_checker.create_html_table(results)
            # Salvăm rezultatele în DataFrame pentru folosire ulterioară
            if isinstance(results, list):
                ip_checker.latest_df = pd.DataFrame(results)
                ip_checker.latest_df_raw = results
    
    # Dacă există date salvate, le afișăm
    elif ip_checker.latest_df_raw:
        table = ip_checker.create_html_table(ip_checker.latest_df_raw)
    
    return render_template('index.html', table=table)

@app.route('/filter')
def filter_results():
    if ip_checker.latest_df.empty:
        return "<p>Nu există date pentru filtrare. Vă rugăm să verificați mai întâi niște adrese IP.</p>"
        
    filters = {
        'proxy': request.args.get('proxy') == 'true',
        'proxy_value': request.args.get('proxy_value') == 'true',
        'vpn': request.args.get('vpn') == 'true',
        'vpn_value': request.args.get('vpn_value') == 'true',
        'tor': request.args.get('tor') == 'true',
        'tor_value': request.args.get('tor_value') == 'true',
        'bot': request.args.get('bot') == 'true',
        'bot_value': request.args.get('bot_value') == 'true',
        'fraud_score': request.args.get('fraud_score') == 'true',
        'fraud_score_value': int(request.args.get('fraud_score_value', 50)),
        'abuse': request.args.get('abuse') == 'true',
        'abuse_value': request.args.get('abuse_value') == 'true',
        'crawler': request.args.get('crawler') == 'true',
        'crawler_value': request.args.get('crawler_value') == 'true'
    }
    
    df = ip_checker.latest_df.copy()
    
    if filters['proxy']:
        df = df[df['Proxy/VPN'] == filters['proxy_value']]
    if filters['vpn']:
        df = df[df['VPN'] == filters['vpn_value']]
    if filters['tor']:
        df = df[df['TOR'] == filters['tor_value']]
    if filters['bot']:
        df = df[df['Bot Status'] == filters['bot_value']]
    if filters['fraud_score']:
        df = df[df['Scor Fraudă'] <= filters['fraud_score_value']]
    if filters['abuse']:
        df = df[df['Abuz Recent'] == filters['abuse_value']]
    if filters['crawler']:
        df = df[df['Crawler'] == filters['crawler_value']]
    
    if df.empty:
        return "<p>Nu există rezultate care să corespundă filtrelor selectate.</p>"
        
    return ip_checker.create_html_table(df.to_dict('records'))

@app.route('/download')
def download_filtered():
    if ip_checker.latest_df.empty:
        return "Nu există date pentru descărcare. Vă rugăm să verificați mai întâi niște adrese IP.", 404
        
    filters = {
        'proxy': request.args.get('proxy') == 'true',
        'proxy_value': request.args.get('proxy_value') == 'true',
        'vpn': request.args.get('vpn') == 'true',
        'vpn_value': request.args.get('vpn_value') == 'true',
        'tor': request.args.get('tor') == 'true',
        'tor_value': request.args.get('tor_value') == 'true',
        'bot': request.args.get('bot') == 'true',
        'bot_value': request.args.get('bot_value') == 'true',
        'fraud_score': request.args.get('fraud_score') == 'true',
        'fraud_score_value': int(request.args.get('fraud_score_value', 50)),
        'abuse': request.args.get('abuse') == 'true',
        'abuse_value': request.args.get('abuse_value') == 'true',
        'crawler': request.args.get('crawler') == 'true',
        'crawler_value': request.args.get('crawler_value') == 'true'
    }
    
    df = ip_checker.latest_df.copy()
    
    if filters['proxy']:
        df = df[df['Proxy/VPN'] == filters['proxy_value']]
    if filters['vpn']:
        df = df[df['VPN'] == filters['vpn_value']]
    if filters['tor']:
        df = df[df['TOR'] == filters['tor_value']]
    if filters['bot']:
        df = df[df['Bot Status'] == filters['bot_value']]
    if filters['fraud_score']:
        df = df[df['Scor Fraudă'] <= filters['fraud_score_value']]
    if filters['abuse']:
        df = df[df['Abuz Recent'] == filters['abuse_value']]
    if filters['crawler']:
        df = df[df['Crawler'] == filters['crawler_value']]
    
    if df.empty:
        return "Nu există rezultate care să corespundă filtrelor selectate", 404
        
    csv_data = ip_checker.generate_csv(df)
    return send_file(
        io.BytesIO(csv_data.encode()),
        mimetype='text/csv',
        as_attachment=True,
        download_name='filtered_proxies.csv'
    )

if __name__ == '__main__':
    app.run(debug=True, port=5050)
