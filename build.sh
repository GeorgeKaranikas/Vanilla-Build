#!/bin/bash

sudo apt update
sudo apt upgrade
sudo apt update && sudo apt install -y bloodhound

sudo apt install -y golang
export GOROOT=/usr/lib/go
export GOPATH=$HOME/go
export PATH=$GOPATH/bin:$GOROOT/bin:$PATH

cd ~/Documents && mkdir Windows_privs && sudo git clone https://github.com/giuliano108/SeBackupPrivilege
cd ~/Documents/Windows_privs && sudo git clone https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1
cd ~/Documents/Windows_privs && sudo git clone https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC
cd ~/Documents && sudo wget https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/privesc/Invoke-BypassUAC.ps1
cd ~/Documents && git clone https://github.com/jpillora/chisel.git && cd chisel && go build
cd ~/Documents && sudo git clone https://github.com/ropnop/kerbrute.git && cd kerbrute && sudo make all
cd ~/Documents/Windows_privs && wget https://raw.githubusercontent.com/ohpe/juicy-potato/master/CLSID/GetCLSID.ps1 -o  JuicyPotato_GetCLSid.ps1
cd ~/Documents && wget https://raw.githubusercontent.com/juliourena/plaintext/master/Scripts/cookieextractor.py -o Firefox_cookieeextractor.py
cd ~/Documents && git clone https://github.com/Mebus/cupp.git
cd ~/Documents && wget https://raw.githubusercontent.com/dpgg101/CVE-2019-10945/main/CVE-2019-10945.py
cd ~/Documents && git clone https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits.git && cd CVE-2022-0847-DirtyPipe-Exploits && bash compile.sh
cd ~/Documents && wget https://raw.githubusercontent.com/dafthack/DomainPasswordSpray/master/DomainPasswordSpray.ps1
sudo apt install eyewitness
cd ~/Documents && git clone https://github.com/unode/firefox_decrypt
cd ~/Documents && wget https://raw.githubusercontent.com/Kevin-Robertson/Inveigh/master/Inveigh.ps1
cd ~/Documents && wget https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1
cd ~/Documents && git clone https://github.com/Kevin-Robertson/Invoke-TheHash
cd ~/Documents/Windows_privs && wget https://github.com/ohpe/juicy-potato/releases/download/v0.1/JuicyPotato.exe
cd ~/Documents && wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64
cd ~/Documents && wget https://github.com/AlessandroZ/LaZagne/releases/download/v2.4.5/LaZagne.exe
cd ~/Documents && wget https://raw.githubusercontent.com/AlessandroZ/LaZagne/master/Linux/laZagne.py
cd ~/Documents && wget https://github.com/carlospolop/PEASS-ng/releases/download/20230917-ec588706/winPEASx64.exe
cd ~/Documents && wget https://github.com/carlospolop/PEASS-ng/releases/download/20230917-ec588706/linpeas.sh
cd ~/Documents && sudo git clone https://github.com/whotwagner/logrotten.git && cd logrotten && gcc logrotten.c -o logrotten
cd ~/Documents && mkdir mimikatz &&cd mimikatz && wget https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip && unzip   mimikatz_trunk.zip  
cd ~/Documents && sudo git clone https://github.com/huntergregal/mimipenguin.git
cd ~/Documents && wget https://raw.githubusercontent.com/haseebT/mRemoteNG-Decrypt/master/mremoteng_decrypt.py
cd ~/Documents && wget https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerUp/PowerUp.ps1
cd ~/Documents && wget https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerView/powerview.ps1
cd ~/Documents/Windows_privs && wget https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe
cd ~/Documents && mkdir Proxifier &&cd Proxifier && wget https://www.proxifier.com/download/#win
cd ~/Documents && wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64
cd ~/Documents && wget https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1
cd ~/Documents && sudo git clone https://github.com/utoni/ptunnel-ng.git
cd ~/Documents &&mkdir Pwnkit && sudo git clone https://github.com/arthepsy/CVE-2021-4034.git && cd CVE-2021-4034 && gcc cve-2021-4034-poc.c -o poc
cd ~/Documents && sudo https://github.com/klsecservices/rpivot
cd ~/Documents && mkdir Rubeus_1.6.4 &&cd Rubeus_1.6.4 &&wget https://github.com/GhostPack/Rubeus/archive/refs/tags/1.6.4.zip && unzip 1.6.4.zip
cd ~/Documents && wget https://github.com/BloodHoundAD/BloodHound/raw/master/Collectors/SharpHound.exe
cd ~/Documents && wget https://github.com/tevora-threat/SharpView/blob/master/Compiled/SharpView.exe
cd ~/Documents && wget https://github.com/rasta-mouse/Sherlock/raw/master/Sherlock.ps1
cd ~/Documents && mkdir SocksOverRDP &&cd SocksOverRDP && wget https://github.com/nccgroup/SocksOverRDP/releases/download/v1.0/SocksOverRDP-x64.zip
cd ~/Documents && sudo git clone https://github.com/TheRook/subbrute.git >> /dev/null 2>&1 && cd subbrute && echo "ns1.inlanefreight.com" > ./resolvers.txt && 
cd ~/Documents && wget https://github.com/BloodHoundAD/BloodHound/raw/master/Collectors/SharpHound.ps1
cd ~/Documents && sudo git clone https://github.com/mgeeky/tomcatWarDeployer
cd ~/Documents && sudo git clone https://github.com/urbanadventurer/username-anarchy
cd ~/Documents && wget https://raw.githubusercontent.com/AonCyberLabs/Windows-Exploit-Suggester/master/windows-exploit-suggester.py
cd ~/Documents && sudo sudo apt install gobuster

