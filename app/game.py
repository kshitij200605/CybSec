from flask import Flask, render_template, request, redirect, url_for, session
app = Flask(__name__)
app.secret_key = 'cyber_game_secret_key_for_session'
story = {
    "intro": {
        "text": "Welcome to CYBSEC. Do you choose to train as a Thief or a Cop?",
        "choices": [("Thief", "red_choice"), ("Cop", "blue_1")]
    },
    "red_choice": {
        "text": "You are a hacker and your team is on a heist of a bank in Tokyo. What would you like to do to help your team complete the heist?",
        "choices": []
    },
    "red_scan_intro": {
        "text": "🧠 INTRO TO NMAP:<br><br>"
                "'nmap' is a powerful tool to find open ports.<br><br>"
                "Your target is: <strong>192.168.56.101</strong><br><br>"
                "Hint: Ports to look for — <strong>80 [HTTP]</strong>, <strong>22 [SSH]</strong><br><br>"
                "Try:<br>"
                "- <code>nmap 192.168.56.101</code> → Basic scan<br>"
                "- <code>nmap -p 80 192.168.56.101</code> → Specific port<br>"
                "- <code>nmap -sS 192.168.56.101</code> → Stealth scan",
        "choices": [("Start Scanning", "red_terminal")]
    },
    "red_terminal": {
        "text": "🖥️ Terminal Loaded. Type your commands below:",
        "choices": [] 
    },
    "red_next_prompt": {
        "text": "✅ Port 22 is open. SSH is running on the target system.<br><br>"
                "🧠 Ready to move on to password cracking?",
        "choices": [("Yes", "red_hydra_intro")]
    },
    "red_hydra_intro": {
        "text": "🔐 <strong>INTRO TO HYDRA</strong><br><br>"
                "Hydra is a brute‑force tool used to crack login credentials on services like SSH.<br><br>"
                "Example syntax:<br>"
                "- <code>hydra -l users.txt -p rockyou.txt ssh://192.168.56.101</code><br><br>"
                "You've gathered some potential usernames: <strong>ayumi</strong>, <strong>benji</strong>, <strong>sakura</strong>.<br>"
                "Try using a password from it that relates to them.<br><br>"
                "🎯 Your task: Crack SSH login to continue.",
        "choices": [("Start Password Cracking", "red_hydra_terminal")]
    },
    "red_hydra_terminal": {
        "text": "🖥️ Hydra Loaded. Type your brute-force command:",
        "choices": []
    },
    "red_mission_complete": {
        "text": "✅ Tokyo Heist - Stage 1 Complete!<br><br>"
                "Hydra cracked the SSH login.<br>"
                "Match found: <strong>ayumi : Tokyo@2025!</strong><br><br>"
                "🚨 Investigation Report:<br>"
                "Ayumi has been arrested for aiding the attackers.<br><br>"
                "What do you want to do next?",
        "choices": [("Join the Cop Team 👮", "blue_1"), ("Continue as Thief 🕵️", "red_sqlmap_intro")]
    },

    # --- BLUE TEAM SCENES ---
    "blue_1": {
        "text": "A hospital in Berlin is under ransomware attack. What's your first move?",
        "choices": []
    },
    "blue_isolate_intro": {
    "text": "🛡️ <strong>ISOLATION BASICS: Cut the Threat Before It Spreads</strong><br><br>"
            "In incident response, isolating a compromised system prevents malware from spreading laterally.<br><br>"
            "🔍 Let's break down the core tools and actions:<br><br>"
            "🔸 <code>ifconfig</code><br>"
            "- A command for network configuration.<br>"
            "- Can be used to disable network interfaces (e.g., 'eth0').<br>"
            "- ✅ Effect: Disconnects the system from the network to stop data exfiltration.<br><br>"
            "🔸 <code>iptables</code><br>"
            "- A powerful firewall rule manager in Linux.<br>"
            "- Can be used to block incoming or outgoing traffic from specific IPs or subnets.<br>"
            "- ✅ Effect: Blocks potentially infected or malicious network connections.<br><br>"
            "🔸 <code>systemctl</code><br>"
            "- Manages system services.<br>"
            "- Can be used to stop services that might be exploited (e.g., a web server like Apache).<br>"
            "- ✅ Effect: Disables services which may be exploited.<br><br>"
            "🎯 <strong>Mission:</strong> Use isolation commands to secure the infected host. Timing matters in real-life response!",
    "choices": [("Run Isolation Commands", "blue_isolate_terminal")]
},
    "blue_isolate_terminal": {
        "text": "💻 Terminal ready. Type your command to isolate the system:",
        "choices": []
    },
    "blue_isolated_success": {
        "text": "✅ System isolated successfully! All network connections blocked.<br><br>"
                "Next step: you can now <strong>Check Logs</strong> to trace the ransomware.",
        "choices": [("Proceed to Check Logs", "blue_logs_intro"), ("Back to main menu", "intro")]
    },
     "blue_logs_intro": {
    "text": "🧠 <strong>LOG ANALYSIS: Learn Before You Hunt</strong><br><br>"
            "As a cyber defender, reading logs is key to tracing an attacker.<br><br>"
            "🔍 Let's understand the tools you'll use:<br><br>"
            "🔸 <code>tail</code><br>"
            "- Displays the last part of a file.<br>"
            "- Useful for viewing recent log entries (e.g., 'tail -n 50 /var/log/syslog').<br><br>"
            "🔸 <code>grep</code><br>"
            "- Searches text using patterns.<br>"
            "- Great for finding specific keywords like 'Failed' in authentication logs ('/var/log/auth.log').<br><br>"
            "🧠 These commands help identify suspicious logins or malware traces.<br><br>"
            "🎯 <strong>Mission:</strong> Use these tools to analyze and discover malicious activity.",
    "choices": [("Start Log Investigation", "blue_logs_terminal")]
},
    "blue_logs_terminal": {
        "text": "💻 Log console loaded. Type your log command:",
        "choices": []
    },
    "blue_logs_success": {
        "text": "✅ Investigation complete! You discovered suspicious IP <strong>203.0.113.42</strong>.<br><br>"
                "Mission accomplished — great job, Cyber Cop!",
        "choices": [("Back to main menu", "intro")]
    }
}
def calculate_progress_and_badges(sess):
    progress = sum(bool(sess.get(k)) for k in [
        'scan_complete', 'crack_complete', 'isolated_complete', 'logs_complete'
    ])
    badges = []
    if sess.get('scan_complete'):
        badges.append("Port Scanner")
    if sess.get('crack_complete'):
        badges.append("Password Cracker")
    if sess.get('isolated_complete'):
        badges.append("Firewall Defender")
    if sess.get('logs_complete'):
        badges.append("Log Hunter")
    return progress, badges

@app.route('/')
def index():
    session.clear()
    session.update({
        'scene': 'intro',
        'scan_complete': False,
        'crack_complete': False,
        'isolated_complete': False,
        'logs_complete': False
    })
    return redirect(url_for('scene'))

@app.route('/scene', methods=['GET', 'POST'])
def scene():
    current = session.get('scene')
    command_output = ""
    target_ip = "192.168.56.101"

    # Prevent re-entering intro scenes
    if current == "red_scan_intro" and session.get('scan_complete'):
        session['scene'] = "red_next_prompt" if not session.get('crack_complete') else "red_mission_complete"
        return redirect(url_for('scene'))
    if current == "red_hydra_intro" and session.get('crack_complete'):
        session['scene'] = "red_mission_complete"
        return redirect(url_for('scene'))
    if current == "blue_isolate_intro" and session.get('isolated_complete'):
        session['scene'] = "blue_isolated_success"
        return redirect(url_for('scene'))
    if current == "blue_logs_intro" and session.get('logs_complete'):
        session['scene'] = "blue_logs_success"
        return redirect(url_for('scene'))

    if request.method == 'POST':
        cmd = request.form.get('user_command', '').strip()
    #RED TEAM
        if current == "red_terminal":
            if cmd in [f"nmap {target_ip}", f"nmap -p 22 {target_ip}", f"nmap -sS {target_ip}"]:
                session['scan_complete'] = True
                session['scene'] = "red_next_prompt"
                return redirect(url_for('scene'))
            command_output = f"❌ Invalid command. Try scanning {target_ip}."
        elif current == "red_hydra_terminal":
            correct = f"hydra -l ayumi -p Tokyo@2025! ssh://{target_ip}"
            if cmd == correct:
                session['crack_complete'] = True
                session['scene'] = "red_mission_complete"
                return redirect(url_for('scene'))
            # Provide helpful feedback
            if "hydra -l" in cmd and "ssh://" in cmd:
                if "Tokyo@2025!" in cmd:
                    command_output = "❌ Correct password—but username not from the hint list!"
                else:
                    command_output = "❌ Username good, password wrong—remember the hint!"
            else:
                command_output = "❌ Invalid Hydra input. Format: hydra -l [user] -p [pass] ssh://[IP]"
        elif current == "red_sqlmap_terminal":
            if "sqlmap" in cmd and "--dump" in cmd:
                session['scene'] = "red_sqlmap_success"
                return redirect(url_for('scene'))
            else:
                command_output = "❌ Incorrect syntax or insufficient flags. Try using '--dump' to extract data."
    #BLUE TEAM
        elif current == "blue_isolate_terminal":
            if cmd in ["ifconfig eth0 down", "iptables -A INPUT -s 192.168.1.0/24 -j DROP", "systemctl stop apache2"]:
                session['isolated_complete'] = True
                session['scene'] = "blue_isolated_success"
                return redirect(url_for('scene'))
            command_output = "❌ Not correct. Try isolating the network or stopping a service."
        elif current == "blue_logs_terminal":
            if "tail" in cmd or "grep" in cmd:
                session['logs_complete'] = True
                session['scene'] = "blue_logs_success"
                return redirect(url_for('scene'))
            command_output = "❌ Try tail or grep to analyze logs."
        else:
            # Scene choice buttons
            nxt = request.form.get('choice')
            if nxt:
                session['scene'] = nxt
                return redirect(url_for('scene'))

    # Update dynamic choices
    if current == "red_choice":
        ch = [
            ("Scan Open Ports ✅" if session.get('scan_complete') else "Scan Open Ports", "red_scan_intro"),
            ("Try Passwords ✅" if session.get('crack_complete') else "Try Passwords", "red_hydra_intro")
        ]
        if session.get('scan_complete') and session.get('crack_complete'):
            ch.append(("Proceed to Next Stage ✅", "red_mission_complete"))
        story["red_choice"]["choices"] = ch

    if current == "blue_1":
        story["blue_1"]["choices"] = [
            ("Isolate system ✅" if session.get('isolated_complete') else "Isolate system",
             "blue_isolated_success" if session.get('isolated_complete') else "blue_isolate_intro"),
            ("Check logs ✅" if session.get('logs_complete') else "Check logs",
             "blue_logs_success" if session.get('logs_complete') else "blue_logs_intro")
        ]

    # Determine hints and template context
    show_terminal = current in ["red_terminal", "red_hydra_terminal",
                                "blue_isolate_terminal", "blue_logs_terminal"]
    hints = {
        "red_terminal": "💡 Use Nmap to scan open ports on the 192.168.56.101 IP.",
        "red_hydra_terminal": "💡 Use Hydra: hydra -l users -p passwords ssh://192.168.56.101   " 
                                "   Users: sakura,benji,ayumi      Passwords:Admin@2025!,Tokyo@2025!,Admin@Tokyo!",
        "blue_isolate_terminal": "💡 Cut network or stop services: ifconfig, iptables, systemctl.",
        "blue_logs_terminal": "💡 Inspect logs using tail or grep."
    }
    guide_text = hints.get(current, "")

    progress, badges = calculate_progress_and_badges(session)
    scene_data = story.get(current, {"text": "Invalid scene!", "choices": []})

    return render_template("scene.html",
                           text=scene_data["text"].replace("\n", "<br>"),
                           choices=scene_data["choices"],
                           show_terminal=show_terminal,
                           guide_text=guide_text,
                           target_ip=target_ip,
                           command_output=command_output,
                           progress=progress,
                           badges=badges)

if __name__ == '__main__':
    app.run(debug=True)
