import subprocess
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Define your known open ports
known_open_ports = {
    '192.168.1.1': [22, 80, 443],
    '192.168.1.2': [22, 3306],
    # Add more IPs and their known open ports here
}

# Function to perform a quick scan
def quick_scan(ip):
    result = subprocess.run(['nmap', '-p-', '--min-rate=1000', '-T4', ip], stdout=subprocess.PIPE, text=True)
    return result.stdout

# Function to perform a deep scan
def deep_scan(ip, ports):
    ports_str = ','.join(map(str, ports))
    result = subprocess.run(['nmap', '-A', '-p', ports_str, ip], stdout=subprocess.PIPE, text=True)
    return result.stdout

# Function to extract open ports from Nmap scan result
def extract_open_ports(scan_result):
    open_ports = []
    for line in scan_result.split('\n'):
        if '/tcp' in line and 'open' in line:
            port = int(line.split('/')[0])
            open_ports.append(port)
    return open_ports

# Function to compare open ports with known open ports
def compare_ports(ip, scanned_ports, known_ports):
    if set(scanned_ports) != set(known_ports):
        return True
    return False

# Function to send an email alert
def send_email_alert(ip, scanned_ports, known_ports):
    sender = 'your_email@example.com'
    receiver = 'your_email@example.com'
    subject = f"Alert: Port discrepancy detected on {ip}"
    body = f"Scanned open ports: {scanned_ports}\nKnown open ports: {known_ports}"
    
    msg = MIMEMultipart()
    msg['From'] = sender
    msg['To'] = receiver
    msg['Subject'] = subject
    
    msg.attach(MIMEText(body, 'plain'))
    
    with smtplib.SMTP('smtp.example.com', 587) as server:
        server.starttls()
        server.login(sender, 'your_password')
        server.sendmail(sender, receiver, msg.as_string())

# Main script
def main():
    for ip, known_ports in known_open_ports.items():
        quick_scan_result = quick_scan(ip)
        open_ports = extract_open_ports(quick_scan_result)
        
        if open_ports:
            deep_scan_result = deep_scan(ip, open_ports)
            deep_open_ports = extract_open_ports(deep_scan_result)
            
            if compare_ports(ip, deep_open_ports, known_ports):
                send_email_alert(ip, deep_open_ports, known_ports)

if __name__ == "__main__":
    main()
