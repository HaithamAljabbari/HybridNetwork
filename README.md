<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>All-in-One Network Tool</title>
</head>
<body>

<h1>All-in-One Network Tool</h1>

<p>This tool is a comprehensive network utility built using <strong>Scapy</strong> to provide various network-related features, such as <strong>packet sniffing</strong>, <strong>ARP spoofing</strong>, <strong>DNS spoofing</strong>, <strong>ARP scanning</strong>, <strong>port scanning</strong>, and <strong>Wi-Fi deauthentication</strong>. It allows users to perform network attacks and discovery tasks from a single command-line interface.</p>

<h2>Features</h2>
<ul>
    <li><strong>Packet Sniffing</strong> - Capture and display live network traffic.</li>
    <li><strong>ARP Spoofing</strong> - Perform an ARP poisoning attack to hijack network traffic.</li>
    <li><strong>DNS Spoofing</strong> - Hijack DNS queries and respond with forged IP addresses.</li>
    <li><strong>ARP Network Scan</strong> - Discover devices on the local network using ARP requests.</li>
    <li><strong>Port Scanning</strong> - Scan for open TCP ports on a target device.</li>
    <li><strong>Wi-Fi Deauthentication</strong> - Perform a deauthentication attack on a target device, forcing it off a Wi-Fi network.</li>
</ul>

<h2>Requirements</h2>
<ul>
    <li>Python 3.x</li>
    <li>Scapy</li>
    <li>Administrator/root privileges to run certain attacks.</li>
</ul>

<p>Install <strong>Scapy</strong> using:</p>
<pre><code>pip install scapy</code></pre>

<h2>How to Use</h2>
<p>Run the script using the command line and choose the specific feature you want by passing the appropriate flags. Below are the commands you can use, along with the description of what each command does and the expected results.</p>

<h3>1. Packet Sniffing</h3>
<h4>Command:</h4>
<pre><code>python all_in_one_tool.py --sniff</code></pre>
<h4>Description:</h4>
<p>This command captures live network traffic on the local interface and displays a summary of each packet.</p>
<h4>Expected Result:</h4>
<p>The tool will print a summary of the captured packets, including source and destination IP addresses, protocols, and packet types.</p>
<pre><code>Ether / IP / TCP 192.168.1.5:52664 &gt; 192.168.1.1:80 S
Ether / IP / UDP 192.168.1.10:53 &gt; 192.168.1.1:53
...</code></pre>

<h3>2. ARP Spoofing</h3>
<h4>Command:</h4>
<pre><code>python all_in_one_tool.py --arp-spoof &lt;target_ip&gt; &lt;spoof_ip&gt;</code></pre>
<h4>Example:</h4>
<pre><code>python all_in_one_tool.py --arp-spoof 192.168.1.10 192.168.1.1</code></pre>
<h4>Description:</h4>
<p>Performs an ARP spoofing attack where the tool tells the target machine (e.g., <code>192.168.1.10</code>) that the attacker’s machine is the router (e.g., <code>192.168.1.1</code>). This places the attacker in a <strong>Man-in-the-Middle (MITM)</strong> position to intercept traffic.</p>
<h4>Expected Result:</h4>
<p>The tool continuously sends ARP responses to the target, associating the attacker's MAC address with the router’s IP address.</p>
<pre><code>Sent ARP response: 192.168.1.10 is-at 192.168.1.1
Sent ARP response: 192.168.1.10 is-at 192.168.1.1
...</code></pre>

<h3>3. DNS Spoofing</h3>
<h4>Command:</h4>
<pre><code>python all_in_one_tool.py --dns-spoof</code></pre>
<h4>Description:</h4>
<p>Hijacks DNS queries on the local network and responds with a spoofed IP address. All DNS queries are answered with the attacker's chosen IP (set to <code>1.2.3.4</code> by default).</p>
<h4>Expected Result:</h4>
<p>The tool will capture DNS requests and respond with a fake IP address (<code>1.2.3.4</code>) for any domain requested.</p>
<pre><code>Received DNS request for example.com -> 1.2.3.4
Received DNS request for google.com -> 1.2.3.4
...</code></pre>

<h3>4. ARP Network Scan</h3>
<h4>Command:</h4>
<pre><code>python all_in_one_tool.py --arp-scan &lt;network_range&gt;</code></pre>
<h4>Example:</h4>
<pre><code>python all_in_one_tool.py --arp-scan 192.168.1.0/24</code></pre>
<h4>Description:</h4>
<p>Sends ARP requests to the specified network range to discover live hosts. This helps in mapping out devices on the local network by retrieving their IP and MAC addresses.</p>
<h4>Expected Result:</h4>
<p>A list of discovered devices will be printed with their IP and MAC addresses.</p>
<pre><code>Host: 192.168.1.1 | MAC: 00:11:22:33:44:55
Host: 192.168.1.10 | MAC: aa:bb:cc:dd:ee:ff
...</code></pre>

<h3>5. TCP Port Scanning</h3>
<h4>Command:</h4>
<pre><code>python all_in_one_tool.py --scan-ports &lt;target_ip&gt; &lt;ports&gt;</code></pre>
<h4>Example:</h4>
<pre><code>python all_in_one_tool.py --scan-ports 192.168.1.5 22,80,443</code></pre>
<h4>Description:</h4>
<p>Performs a TCP SYN scan on the target IP to identify open ports. The tool will send SYN packets to the specified ports and display the open ports based on the response.</p>
<h4>Expected Result:</h4>
<p>The tool will show which ports are open on the target IP.</p>
<pre><code>Port 22 is open
Port 80 is open
Port 443 is closed</code></pre>

<h3>6. Wi-Fi Deauthentication Attack</h3>
<h4>Command:</h4>
<pre><code>python all_in_one_tool.py --deauth &lt;target_mac&gt; &lt;gateway_mac&gt; &lt;interface&gt;</code></pre>
<h4>Example:</h4>
<pre><code>python all_in_one_tool.py --deauth ff:ff:ff:ff:ff:ff 00:11:22:33:44:55 wlan0mon</code></pre>
<h4>Description:</h4>
<p>Sends deauthentication packets to a target device (identified by <code>target_mac</code>), disconnecting it from the Wi-Fi network. This attack is aimed at forcing the target off the network by pretending to be the router (<code>gateway_mac</code>).</p>
<h4>Expected Result:</h4>
<p>The target device will be disconnected from the Wi-Fi network repeatedly until the attack is stopped.</p>
<pre><code>Sent Deauth to ff:ff:ff:ff:ff:ff
Sent Deauth to ff:ff:ff:ff:ff:ff
...</code></pre>

<h2>Legal Disclaimer</h2>
<p>This tool is intended for educational purposes only. Performing network attacks on networks or devices without authorization is illegal and can lead to serious consequences. Always ensure that you have proper authorization before using these techniques on any network or device.</p>
<p>By using this tool, you agree that you take full responsibility for your actions.</p>

<h2>Conclusion</h2>
<p>This All-in-One Network Tool provides multiple network security and penetration testing capabilities in a single script. It's highly customizable and can be extended with additional features for more advanced use cases. The tool is intended for ethical hacking, penetration testing, and learning about network security.</p>

</body>
</html>
