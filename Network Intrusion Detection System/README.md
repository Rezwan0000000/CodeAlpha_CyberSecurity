# 🛡️ Snort-Based Network Intrusion Detection System (NIDS)

A complete guide and implementation for setting up a **Network Intrusion Detection System** using **Snort**. This project is designed for beginner to advanced security analysts, SOC engineers, and CTF participants who want to monitor, detect, and respond to suspicious or malicious network activity in real-time using open-source tools.

---

## ⚙️ Features

- ✅ Install and configure **Snort** on Linux
- ✅ Write, customize, and manage **Snort rules**
- ✅ Perform **live traffic monitoring**
- ✅ Trigger **alerts** for suspicious network activity
- ✅ Implement **manual or automated response mechanisms**
- ✅ Optional: **Visualize detections** using dashboards like the ELK Stack
- ✅ Designed for real-world **forensics, training, or CTF scenarios**

---

## 🐍 Installation

### 🐧 Snort on Ubuntu/Debian

sudo apt update
sudo apt install snort
<img width="975" height="434" alt="image" src="https://github.com/user-attachments/assets/7660d59d-6aba-498a-afb0-3600bbfa1b68" />

sudo nano snote.lua
<img width="894" height="303" alt="image" src="https://github.com/user-attachments/assets/9cc187b2-3814-404b-9f04-c45e49fd1ec1" />

sudo nano /etc/snort/rules/local.
<img width="975" height="147" alt="image" src="https://github.com/user-attachments/assets/3ddcb1f4-4a01-45ea-824c-19774fea5e35" />

sudo nano local.rules

alert icmp any any -> any any (msg:"Suspicious ICMP detected!"; sid:1000001; rev:1;)
<img width="975" height="423" alt="image" src="https://github.com/user-attachments/assets/7defc057-ac20-4400-abce-c48673c0aacd" />

include $RULE_PATH/local.rules

snort -c /etc/snort/snort.lua -i eth0 -A alert_fast
<img width="624" height="376" alt="image" src="https://github.com/user-attachments/assets/ec3a0bd1-df85-4e96-861e-240a49223bd7" />

. # Project Root
├── rules/ # Custom rules
│ └── local.rules
├── logs/ # Alert logs
│ └── alert # Snort alert file
├── scripts/ # Optional automation
│ └── block_on_alert.sh
└── README.md # This doc
## 📚 References

- 📘 [Snort Official Documentation](https://docs.snort.org/)
- ✍️ [Snort Rules Language](https://www.snort.org/faq/readme-rules)
- 🔄 [Snort Community Rules](https://www.snort.org/downloads)
- 🧪 [Test My IDS Project](http://testmyids.com/) — For safe alert-triggering traffic

---

## ✅ Status

This Snort-based NIDS implementation is tested on:

- 🐧 Ubuntu 20.04+
- 🧪 Snort 2.x / 3.x
- 🧰 VirtualBox/VMs for sandboxed analysis

Perfect for:

- 🎯 Academic Labs and CTF Challenges
- 🔍 SOC Analyst Practice and Training
- 🛡️ Real-World Blue Team/Red Team Simulations

---

## 🤝 Contributing

You are welcome to contribute by:

- Adding more Snort example rules
- Integrating notification automation
- Building dashboard templates
- Sharing attack simulation or test PCAPs

---

## 📄 License

**MIT License**  
Free to use for personal, educational, and professional security projects.

---

## 🙏 Acknowledgements

- 🙌 [Snort by Cisco](https://www.snort.org/)
- 💬 Community contributors in NSM/Blue Team space
- 🎯 CTF challenges inspiring realistic detection rules

> ⚠️ **Security Note:** Snort is an IDS — it detects, but does not block by default.  
> 💡 Combine with firewall tools like `iptables` or `fail2ban` for active defense.

---
