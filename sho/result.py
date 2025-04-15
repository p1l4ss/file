import json


with open('results.json', 'r') as file:
    data = json.load(file)


for item in data:
    ip = item.get('ip')
    services = item.get('services')
    for service in services:
        port = service.split('/')[0]  # Tách port trước dấu '/'
        ip_port = f"{ip}:{port}"  # Ghép ip với port

        # Hiển thị kết quả
        print(f"{ip_port}")

# python3 result.py > ip-port.txt