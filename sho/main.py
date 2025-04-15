import json
import shodan
from censys.search import CensysHosts
from censys.common.exceptions import CensysException
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

SHODAN_API_KEY = '3tj9ovMyEtTxhWOhTiEK4GcwNkVSj3B8'
CENSYS_API_ID = '66b963d6-b582-4043-9d9e-974a03aba783'
CENSYS_API_SECRET = 'BCK00BtK32KYS2vyYXG3higXFFW5EX3D'

def get_shodan_data(hostname):
    api = shodan.Shodan(SHODAN_API_KEY)
    try:
        results = api.search('ip:' + hostname) 
        if results['matches']:
            extracted_data = []
            for result in results['matches']:
                data = {
                    'ip': result.get('ip_str'),
                    'port': result.get('port'),
                    'org': result.get('org'),
                    'hostnames': result.get('hostnames'),
                    'domain': result.get('domain'),
                    'asn': result.get('asn'),
                    'isp': result.get('isp')
                }
                extracted_data.append(data)
            
            return extracted_data
        else:
            return []
    except shodan.APIError as e:
        error_message = f'Error fetching data for hostname {hostname} from Shodan: {e}'
        print(json.dumps({"error": error_message}, indent=4))
        return []

def get_censys_data(hostname):
    censys_hosts = CensysHosts(api_id=CENSYS_API_ID, api_secret=CENSYS_API_SECRET)
    try:
        results = censys_hosts.search(hostname)
        if results:
            extracted_data = []
            for result in results:
                
                for item in result:
                    data = {
                        'ip': item.get('ip'),
                        'location': item.get('location', {}).get('country'),
                        'services': item.get('services', []),
                        'autonomous_system': item.get('autonomous_system', [])
                    }
                    extracted_data.append(data)
                            
            return extracted_data
        else:
            print(json.dumps({"message": f"No results found for {hostname}"}, indent=4))
            return []
    except CensysException as e:
        error_message = f'Error fetching data for hostname {hostname} from Censys: {e}'
        print(json.dumps({"error": error_message}, indent=4))
        return []

def process_hostname(hostname):
    shodan_data = get_shodan_data(hostname)
    censys_data = get_censys_data(hostname)
    return merge_data(shodan_data, censys_data)

def get_combined_data(hostnames, max_threads=10):
    combined_data = []
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        future_to_hostname = {executor.submit(process_hostname, hostname): hostname for hostname in hostnames}
        for future in as_completed(future_to_hostname):
            hostname = future_to_hostname[future]
            try:
                data = future.result()
                combined_data.extend(data)
            except Exception as exc:
                print(f'{hostname} generated an exception: {exc}')
    return combined_data


# Updated merge_data function to merge ports and also combine other relevant fields
# Updated merge_data function to merge Shodan and Censys data properly

def merge_data(shodan_data, censys_data):
    merged_data = {}
    
    # Xử lý dữ liệu Censys
    for item in censys_data:
        ip = item['ip']
        merged_data[ip] = item
        
        # Kiểm tra và chuyển đổi services thành array nếu cần
        if 'services' in merged_data[ip]:
            if not isinstance(merged_data[ip]['services'], list):
                merged_data[ip]['services'] = [merged_data[ip]['services']]
            
            # Chuyển đổi mỗi service thành định dạng "port/service_name"
            merged_data[ip]['services'] = [
                f"{service.get('port', '')}/{service.get('service_name', 'UNKNOWN')}"
                for service in merged_data[ip]['services']
            ]
    
    # Xử lý dữ liệu Shodan
    for item in shodan_data:
        ip = item['ip']
        if ip not in merged_data:
            merged_data[ip] = item
            merged_data[ip]['services'] = []
        else:
            for key, value in item.items():
                if key != 'port':
                    merged_data[ip][key] = value
        
        # Kiểm tra và thêm port từ Shodan vào services nếu chưa tồn tại
        port = item.get('port')
        if port is not None:
            port_str = str(port)
            port_service = f"{port_str}/{item.get('product', 'UNKNOWN')}"
            
            if 'services' not in merged_data[ip]:
                merged_data[ip]['services'] = []
            
            # Kiểm tra xem port đã tồn tại trong services chưa
            port_exists = any(service.startswith(f"{port_str}/") for service in merged_data[ip]['services'])
            
            if not port_exists:
                merged_data[ip]['services'].append(port_service)
    
    return list(merged_data.values())



def main():
    parser = argparse.ArgumentParser(description="Fetch and combine data from Shodan and Censys")
    parser.add_argument("-f", "--file", required=True, help="File containing list of IPs (one IP per line)")
    parser.add_argument("-o", "--output", help="Output file to save JSON results")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads to use (default: 10)")
    args = parser.parse_args()

    # Đọc danh sách IP từ file
    try:
        with open(args.file, 'r') as f:
            hostnames = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Error: File {args.file} not found")
        return
    except Exception as e:
        print(f"Error reading file: {e}")
        return

    if not hostnames:
        print("Error: No IPs found in the input file")
        return

    combined_data = get_combined_data(hostnames, max_threads=args.threads)
    print(json.dumps(combined_data, indent=4))

    if args.output:
        with open(args.output, 'w') as f:
            json.dump(combined_data, f, indent=4)
        print(f"Results saved to {args.output}")

if __name__ == "__main__":
    main()

# Example usage:
# python3 main.py -f public_ips.txt -t 10 -o results.json