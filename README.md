### Installation

- brew install suricata
- suricata --build-info

### Configure Suricata

- nano /usr/local/etc/suricata/suricata.yaml
    - Find af-packet and change it to pcap for Mac.
    - Set the correct interface (e.g., en0).
    - Set HOME_NET: "[your-network]"
    - Set EXTERNAL_NET: "!$HOME_NET"

- Create your custome rule file
    - touch /usr/local/var/lib/suricata/rules/custom.rules

- Add the following rules:-
    <pre>
    alert icmp any any -> $EXTERNAL_NET any (msg:"ICMP Echo Request detected"; itype:8; sid:1000001; rev:1;)
    alert icmp $EXTERNAL_NET any -> any any (msg:"ICMP Echo Reply detected"; itype:0; sid:1000002; rev:1;)
    alert tcp any any -> any any (msg:"Nmap Stealth Scan Detected"; flags:S; threshold: type threshold, track by_src, count 5, seconds 10; sid:100003;)
    </pre>

- Include your custom rule file in suricata.yaml
    rule-files:
        - suricata.rules
        - custom.rules

### Start Suricata

- sudo suricata -T -c /usr/local/etc/suricata/suricata.yaml # validate config
- sudo suricata -c /usr/local/etc/suricata/suricata.yaml -i en0

### Observe Logs

<pre>
1. ICMP Traffic

ping -c3 example.com

MacBook-Air-2:snort-lab anish$ tail -f /usr/local/var/log/suricata/fast.log 
02/10/2025-15:16:05.148075  [**] [1:1000001:1] ICMP Echo Request detected [**] [Classification: (null)] [Priority: 3] {ICMP} 192.168.29.79:8 -> 23.192.228.84:0
02/10/2025-15:16:05.412339  [**] [1:1000002:1] ICMP Echo Reply detected [**] [Classification: (null)] [Priority: 3] {ICMP} 23.192.228.84:0 -> 192.168.29.79:0
02/10/2025-15:16:06.148540  [**] [1:1000001:1] ICMP Echo Request detected [**] [Classification: (null)] [Priority: 3] {ICMP} 192.168.29.79:8 -> 23.192.228.84:0
02/10/2025-15:16:06.409697  [**] [1:1000002:1] ICMP Echo Reply detected [**] [Classification: (null)] [Priority: 3] {ICMP} 23.192.228.84:0 -> 192.168.29.79:0
02/10/2025-15:16:07.153850  [**] [1:1000001:1] ICMP Echo Request detected [**] [Classification: (null)] [Priority: 3] {ICMP} 192.168.29.79:8 -> 23.192.228.84:0
02/10/2025-15:16:07.411949  [**] [1:1000002:1] ICMP Echo Reply detected [**] [Classification: (null)] [Priority: 3] {ICMP} 23.192.228.84:0 -> 192.168.29.79:0
</pre>

<pre>
2. Bad Traffic

MacBook-Air-2:suricate-lab anish$ curl http://testmynids.org/uid/index.html
uid=0(root) gid=0(root) groups=0(root)

MacBook-Air-2:snort-lab anish$ tail -f /usr/local/var/log/suricata/fast.log 
02/10/2025-15:16:48.363157  [**] [1:2100498:7] GPL ATTACK_RESPONSE id check returned root [**] [Classification: Potentially Bad Traffic] [Priority: 2] {TCP} 108.158.61.48:80 -> 192.168.29.79:51733
</pre>

<pre>
3. NMAP Stealth Scan

MacBook-Air-2:suricate-lab anish$ sudo nmap -Pn -sS -p- 192.168.79.29

MacBook-Air-2:snort-lab anish$ tail -f /usr/local/var/log/suricata/fast.log 
02/10/2025-15:18:09.494544  [**] [1:100001:0] Nmap Stealth Scan Detected [**] [Classification: (null)] [Priority: 3] {TCP} 192.168.29.79:53256 -> 192.168.79.29:23
02/10/2025-15:18:09.494568  [**] [1:100001:0] Nmap Stealth Scan Detected [**] [Classification: (null)] [Priority: 3] {TCP} 192.168.29.79:53256 -> 192.168.79.29:22
02/10/2025-15:18:11.512608  [**] [1:100001:0] Nmap Stealth Scan Detected [**] [Classification: (null)] [Priority: 3] {TCP} 192.168.29.79:53258 -> 192.168.79.29:22
02/10/2025-15:18:11.512908  [**] [1:100001:0] Nmap Stealth Scan Detected [**] [Classification: (null)] [Priority: 3] {TCP} 192.168.29.79:53258 -> 192.168.79.29:80
02/10/2025-15:18:12.517324  [**] [1:100001:0] Nmap Stealth Scan Detected [**] [Classification: (null)] [Priority: 3] {TCP} 192.168.29.79:53256 -> 192.168.79.29:199
02/10/2025-15:18:12.517148  [**] [1:100001:0] Nmap Stealth Scan Detected [**] [Classification: (null)] [Priority: 3] {TCP} 192.168.29.79:53256 -> 192.168.79.29:554
02/10/2025-15:18:13.518298  [**] [1:100001:0] Nmap Stealth Scan Detected [**] [Classification: (null)] [Priority: 3] {TCP} 192.168.29.79:53258 -> 192.168.79.29:113
02/10/2025-15:18:13.518525  [**] [1:100001:0] Nmap Stealth Scan Detected [**] [Classification: (null)] [Priority: 3] {TCP} 192.168.29.79:53258 -> 192.168.79.29:8080
02/10/2025-15:18:14.527358  [**] [1:100001:0] Nmap Stealth Scan Detected [**] [Classification: (null)] [Priority: 3] {TCP} 192.168.29.79:53256 -> 192.168.79.29:111
...
...
...
</pre>
