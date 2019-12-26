import subprocess
import sys
import ipaddress
import threading
import re
import time
from datetime import datetime
from multiprocessing import Queue


# Verifie que oui.txt est present sinon on le recupere
try:
    file = open('oui.txt', encoding='utf-8', mode='r')
    file.close()
except FileNotFoundError:
    try:
        import requests
        print('[-] Le fichier "oui.txt" est manquant!')
        print('[+] Telechargement du fichier..')
        data = requests.get('http://standards-oui.ieee.org/oui.txt')
        data = data.content.decode('utf-8')
        file = open('oui.txt', encoding='utf-8', mode='w')
        file.write(data)
        file.close()
        print('[+] Ecriture dans "oui.txt"..')
    except (ImportError, ModuleNotFoundError):
        print('[-] La librairie requests est necessaire pour telecharger le fichier requis!')
        print('[-] Telecharger manuellement "oui.txt" depuis: http://standards-oui.ieee.org/oui.txt')
        exit(1)
    pass

# Recuperation et formatage de l'adresse
try:
    ip = sys.argv[1]
except IndexError:
    try:
        ip = input('[>] Adresse IP: ')
        ipaddress.ip_address(ip)
    except ValueError:
        print('[-] Adresse IP invalide!')
        exit(1)

ip = ip.split('.')
ip.pop(-1)
ip = '.'.join(ip)+'.0/24'
ip = ipaddress.ip_network(ip)
iplist = [str(x) for x in ip.hosts()]

# Nombre de threads souhaiter
try:
    thnumber = int(sys.argv[2])
except (IndexError, ValueError):
    thnumber = 8
    print(f'[+] Threads par defaut: {thnumber}')
# list stockant les appareils en ligne
online = []

# list stockant les ip en cours de traitement pour que les threads ne traite
# pas la meme IP
handled = []

# enregistrement horodatage
dt = datetime.now()

# instanciation de la queue pour les jobs
q = Queue()
for addr in iplist:
    q.put(addr)


def worker():
    while True:
        addr = q.get()  # on recupere un job contenant une addresse
        
        if addr is None:  # on retourne si il y a plus rien
            return
        if addr in handled:  # on passe un tour si l'ip est deja
            continue  # en cours de traitement
        
        handled.append(addr)
        cmd = f'ping -n 1 -w 1000 {addr}'
        try:
            proc = subprocess.check_output(cmd)  # on lance un process de ping
            print(f'[+] {addr}')
        except subprocess.CalledProcessError:
            continue
        
        # recuperation de la MAC address
        cmd = f'arp -a {addr}'
        mac = None
        vendor = None
        try:
            proc = subprocess.check_output(cmd)
            mac = re.findall(r"(?:\w{2}-?:?){6}", str(proc),
                             re.MULTILINE | re.IGNORECASE)
            mac = mac.pop().upper()
            print(f'[+] {mac}')
            try:
                file = open("oui.txt", encoding="utf-8", mode="r")
                lines = file.readlines()
                ouimac = mac[0:8].split(':')
                ouimac = '-'.join(ouimac)
                for line in lines:
                    if ouimac in line:
                        vendor = line[16:].lstrip()
                        vendor = vendor.rstrip("\n")
                        break
                file.close()
            except FileNotFoundError:
                print('[-] Fichier "oui.txt" manquant!')
                pass

        except (subprocess.CalledProcessError, ValueError, IndexError) as err:
            print(f'[-] {addr} impossible de recuperer la MAC: [{err}]')
            continue

        if mac is not None:
            if vendor is not None:
                online.append((addr, mac, vendor))
            else:
                online.append((addr, mac, 'Inconnu'))
        else:
            online.append((addr, 'Inconnu', 'Inconnu'))


# Lancement des threads
threads = [threading.Thread(target=worker) for _i in range(thnumber)]
for thread in threads:
    thread.start()
    q.put(None)

for thread in threads:
    thread.join()

print('[+] Classement par ordre croissant des adresses..')
# Classement croissant des addresses
online = sorted(online, key=lambda x: ipaddress.ip_address(x[0]))
time.sleep(1)

# Ecriture du fichier de log
log = dt.strftime("%d%m%y_%I%M%p")
log = f'scan_{log}.txt'
print(f'[+] Ecriture du resultat dans "{log}"..')
with open(log, encoding="utf-8", mode="w") as file:
    content = ''
    for item in online:
        content = content + f'Adresse:\t{item[0]}\n'
        try:
            content = content + f'MAC:\t\t{item[1]}\n'
        except IndexError:
            pass
        try:
            content = content + f'Fabricant:\t{item[2]}\n'
        except IndexError:
            pass

        content = content + '\n'

    content = content + '\n---EOF---'
    file.write(content)
time.sleep(1)
print('[+] Fin du script.')
input('[>] Appuyez sur Entree pour quitter..')
