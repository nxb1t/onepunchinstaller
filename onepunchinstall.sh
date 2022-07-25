#!/bin/bash

### Colors ###
ESC=$(printf '\033') RESET="${ESC}[0m" BLACK="${ESC}[1;30m" RED="${ESC}[1;31m"
GREEN="${ESC}[1;32m" YELLOW="${ESC}[1;33m" BLUE="${ESC}[1;34m" MAGENTA="${ESC}[1;35m"
CYAN="${ESC}[1;36m" WHITE="${ESC}[1;37m" DEFAULT="${ESC}[1;39m"
GREEN_BG="${ESC}[1;42m"

### Color Functions ##
greenprint() { printf "${GREEN}%s${RESET}\n" "$1"; }
blueprint() { printf "${BLUE}%s${RESET}\n" "$1"; }
redprint() { printf "${RED}%s${RESET}\n" "$1"; }
yellowprint() { printf "${YELLOW}%s${RESET}\n" "$1"; }
magentaprint() { printf "${MAGENTA}%s${RESET}\n" "$1"; }
cyanprint() { printf "${CYAN}%s${RESET}\n" "$1"; }

banner() {
	echo "${RED}
 ⠀⠀⠀⠀⣠⣶⡾⠏⠉⠙⠳⢦⡀⠀⠀⠀⢠⠞⠉⠙⠲⡀⠀
 ⠀⠀⠀⣴⠿⠏⠀⠀⠀⠀⠀⠀⢳⡀ ⠀⡏⠀⠀⠀⠀⠀⢷
 ⠀⠀⢠⣟⣋⡀⢀⣀⣀⡀⠀⣀⡀⣧⠀⢸⠀      ⡇
 ⠀⠀⢸⣯⡭⠁⠸⣛⣟⠆⡴⣻⡲⣿⠀⣸⠀ v1.0 ⡇
 ⠀⠀⣟⣿⡭⠀⠀⠀⠀⠀⢱⠀⠀⣿⠀⢹⠀⠀⠀⠀⠀  ⡇
 ⠀⠀⠙⢿⣯⠄⠀⠀⠀⢀⡀⠀⠀⡿⠀⠀⡇⠀⠀⠀ ⠀⡼
 ⠀⠀⠀⠀⠹⣶⠆⠀⠀⠀⠀⠀⡴⠃⠀⠀⠘⠤⣄ ⣠⠞⠀
 ⠀⠀⠀⠀⠀⢸⣷⡦⢤⡤⢤⣞⣁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
 ⠀⠀⢀⣤⣴⣿⣏⠁⠀⠀⠸⣏⢯⣷⣖⣦⡀⠀⠀⠀⠀⠀⠀
 ⢀⣾⣽⣿⣿⣿⣿⠛⢲⣶⣾⢉⡷⣿⣿⠵⣿⠀⠀⠀⠀⠀⠀
 ⣼⣿⠍⠉⣿⡭⠉⠙⢺⣇⣼⡏⠀⠀⠀⣄⢸⠀⠀⠀⠀⠀⠀
 ⣿⣿⣧⣀⣿………⣀⣰⣏⣘⣆⣀⠀⠀ ${RESET}"
	
	echo -e "$(greenprint ' OnePunchInstaller r3l04d3d')"
	echo -e "$(magentaprint ' Developer : D3v1LaL')"
	echo -e "$(magentaprint ' Contributor : nxb1t')"
}

list_tools() {
 	echo -ne "
 CATEGORY : PENTEST TOOLS
 --------------------

 aircrack-ng [ desc : wifi pentesting tool ]
 dirbuster   [ desc : directory bruteforcer ]
 enum4linux  [ desc : Linux enumeration tool ]
 hping3      [ desc : TCP/IP packet sender and analyzer ]
 johnny      [ desc : johntheripper GUI Front-end ]
 nikto       [ desc : web server scanner ]
 ropper      [ desc : binary info viewer ]
 sqlmap      [ desc : automatic sqlinjection takeover ]
 dirsearch   [ desc : directory bruteforcer ]
 fcrackzip   [ desc : zip password cracking tool ]
 hydra       [ desc : web services bruteforcer ]
 joomscan    [ desc : joomla vulnerability scanner ]
 nmap        [ desc : fast network scanner ]
 setoolkit   [ desc : social engineering pentesting framework ]
 tcpflow     [ desc : Network traffic analyzer ]
 zenmap      [ desc : nmap GUI Front-End ]
 arp-scan    [ desc : Local Network hosts scanner ]
 crunch	     [ desc : wordlist generator ]
 dnsenum     [ desc : DNS enumeration tool ]
 gobuster    [ desc : website URI bruteforcer ]
 linenum.sh  [ desc : Linux enumeration tool ]
 pdfcrack    [ desc : PDF file password cracker ]
 recon-ng    [ desc : web reconnaissance tool ]
 wordlists   [ desc : Rockyou wordlist ]
 dnsmap      [ desc : subdomain finder ]
 hashcat     [ desc : hash cracker ]
 john	     [ desc : hash cracker ]
 metasploit-framework [ desc : exploits framework ]
 peda 	     [ desc : gdb script for exploit developement ]
 gdb	     [ desc : GNU debugger ]
 ROPGadget   [ desc : ROP gadget finder ]
 radare2     [ desc : disassembler and debugger ]
 unix-privesc-check [ desc : unix privilege escalation checker ]
 wordpresscan  [ desc : wordpress scanner ]
 wpscan	       [ desc : wordpress scanner ]
 pwntools      [ desc : scripts for binary exploitation ]

 CATEGORY : DFIR TOOLS 
 -----------------

 autopsy    [ desc : TSK GUI Front-End ]
 volatility [ desc : RAM Analyzer ]
 testdisk   [ desc : data recovery tool ]
 apktool    [ desc : android apk manipulating tool ]
 ghidra     [ desc : dicompiler and disassembler ]
 ALEAPP     [ desc : android artifacts parser ]
 iLEAPP     [ desc : iOS artifacts parser ]
 MobSF      [ desc : Mobile app and malware analyser ]
 binwalk    [ desc : File carving tool ]
 foremost   [ desc : File carving tool ]
 Vol-GUI    [ desc : Volatility 2 GUI Front-end ]
 pngcheck   [ desc : PNG structure validator ]
 zbar-tools [ desc : QR Code utilities ]
 audacity   [ desc : Audio editor ]
 steghide   [ desc : hide message inside JPG and WAV files ]
 stegseek   [ desc : steghide password cracker ]
 sonic-visualiser [ desc : Advanced Audio Analyser ]
 peepdf     [ desc : PDF analysis tool ]
 oletools   [ desc : OLE Files (MSWord, etc) analysis tool ]
 wireshark  [ desc : Network traffic analyzer ]
 scapy      [ desc : Network packet manipulation program ]
 jadx       [ desc : Java bytecode decompiler ]
 dex2jar    [ desc : convert dex files to jar ]
 stegsnow   [ desc : whitespace steganography tool ]
 stegsolve.jar [ desc : RGB plane steganography solver ]
 zsteg      [ desc : PNG steganography tool ]
 stegolsb   [ desc : LSB steganography tool ]
 exiftool   [ desc : exif info viewer ]
 bulk_extractor [ desc : File carving tool ]
"
}

install_pentest_dependencies() {

	sudo apt-get -y update
	sudo apt install -y python3 python2
	sudo apt install -y cmake make perl ruby ruby-bundler g++ golang-go qtbase5-dev
	sudo apt install -y p7zip-full gnupg2
	sudo apt install -y gpgv2 autoconf bison git-core libapr1 libaprutil1 libcurl4-openssl-dev libgmp3-dev libgmp-dev libpcap-dev libpq-dev libreadline6-dev libsqlite3-dev libssl-dev libsvn1 libtool libxml2 libxml2-dev libxslt-dev libxslt1-dev libyaml-dev ruby-dev locate ncurses-dev openssl postgresql postgresql-contrib wget xsel zlib1g zlib1g-dev
	sleep 1
	echo "${GREEN_BG} PENTEST Dependencies Installed ${RESET}"
}

install_dfir_dependencies() {

	sudo apt-get -y update
	sudo apt install -y python2 python2.7-dev libpython2-dev curl
	sudo apt install -y build-essential git libdistorm3-dev yara libraw1394-11 libcapstone-dev capstone-tool tzdata wget curl
	curl https://bootstrap.pypa.io/pip/2.7/get-pip.py --output get-pip.py
	sudo python2 get-pip.py
	rm get-pip.py
	sudo python2 -m pip install -U setuptools wheel
	sudo apt install -y openjdk-11-jre-headless openjdk-11-jdk-headless ruby ruby-bundler p7zip-full gnupg2
	sudo apt install -y python3 python3-dev libpython3-dev python3-pip python3-setuptools python3-wheel python3-tk python3-venv
	sudo apt install -y gpgv2 autoconf automake build-essential flex libexpat1-dev libssl-dev libtool libxml2-utils make pkg-config libewf-dev git-core libapr1 libaprutil1 libcurl4-openssl-dev libgmp3-dev libgmp-dev libpcap-dev libpq-dev libreadline6-dev libsqlite3-dev libssl-dev libsvn1 libtool libxml2 libxml2-dev libxslt-dev libxslt1-dev libyaml-dev ruby-dev locate ncurses-dev openssl wget xsel zlib1g zlib1g-dev
	sleep 1
	echo "${GREEN_BG}Installing the BellSoft Java 8 JRE for Autopsy${RESET}"
	wget -q -O - https://download.bell-sw.com/pki/GPG-KEY-bellsoft | sudo apt-key add -
	echo "deb [arch=amd64] https://apt.bell-sw.com/ stable main" | sudo tee /etc/apt/sources.list.d/bellsoft.list
	sudo apt update
	sudo apt-get install -y bellsoft-java8-full
	
	wget "http://archive.ubuntu.com/ubuntu/pool/universe/p/pygtk/python-gtk2_2.24.0-5.1ubuntu2_amd64.deb" -O python-gtk2.deb
	sudo apt install -y ./python-gtk2.deb
	rm python-gtk2.deb

	sudo apt install -y binwalk
  	sudo apt remove -y --purge sleuthkit libtsk19
        echo -e "${GREEN_BG}Installed binwalk ${RESET}"
        sleep 1

	wget "https://github.com/sleuthkit/sleuthkit/releases/download/sleuthkit-4.11.1/sleuthkit-java_4.11.1-1_amd64.deb" -O sleuthkit-java.deb
	sudo apt install -y ./sleuthkit-java.deb
	rm sleuthkit-java.deb
	sleep 1
	echo "$GREEN_BG} DFIR Dependencies Installed ${RESET}"
}

install_pentest_tools() {

	echo -e "$(yellowprint ' Proceeding to install PENTEST tools')"
	echo -e "$(blueprint ' Tools from github are installed to $HOME/tools/ Directory')"
	if [[ ! -d "$HOME/tools" ]]
	then
		mkdir $HOME/tools
	fi
	echo -e "$(yellowprint ' Moving to tools directory ')"
	cd $HOME/tools
	sleep 1
	
	sudo apt install -y nmap
	echo -e "${GREEN_BG}Installed nmap ${RESET}"
	sleep 1
	
	sudo apt install -y alien
	wget "https://nmap.org/dist/zenmap-7.92-1.noarch.rpm"
	sudo alien "zenmap-7.92-1.noarch.rpm"
	sudo apt install -y ./zenmap_7.92-2_all.deb
	rm zenmap_7.92-2_all.deb 
	rm zenmap-7.92-1.noarch.rpm
	echo -e "${GREEN_BG}Insatlled zenmap ${RESET}"
	sleep 1
	
	sudo apt install -y arp-scan
	echo -e "${GREEN_BG}Installed arp-scan ${RESET}"
	sleep 1
	
	sudo apt install -y recon-ng
	echo -e "${GREEN_BG}Installed recon-ng ${RESET}"
	sleep 1
	
	sudo apt install -y hping3
	echo -e "${GREEN_BG}Installed hping3 ${RESET}"
	sleep 1
	
	sudo apt install -y aircrack-ng
	echo -e "${GREEN_BG}Installed aircrack-ng ${RESET}"
	sleep 1
	
	sudo apt install -y john
	echo -e "${GREEN_BG}Installed john ${RESET}"
	sleep 1
	
	sudo apt install -y crunch
	echo -e "${GREEN_BG}Installed crunch ${RESET}"
	sleep 1
	
	sudo apt install -y hashcat
	echo -e "${GREEN_BG}Installed hashcat ${RESET}"
	sleep 1
	
	sudo apt install -y pdfcrack
	echo -e "${GREEN_BG}Installed pdfcrack ${RESET}"
	sleep 1
	
	sudo apt install -y fcrackzip
	echo -e "${GREEN_BG}Installed fcrackzip ${RESET}"
	sleep 1
	
	sudo apt install -y hydra
	echo -e "${GREEN_BG}Installed hydra ${RESET}"
	sleep 1
	
	sudo apt install -y gdb
	echo -e "${GREEN_BG}Installed gdb ${RESET}"
	sleep 1
	
	wget "https://github.com/radareorg/radare2/releases/download/5.7.4/radare2_5.7.4_amd64.deb" -O radare2.deb
	sudo apt install -y ./radare2.deb
	rm radare2.deb
	echo -e "${GREEN_BG}Installed radare2 ${RESET}"
	sleep 1
	
	pip2 install ROPGadget
	pip3 install ROPGadget
	echo -e "${GREEN_BG}Installed ROPGadget ${RESET}"
	sleep 1
	
	pip2 install ropper
	pip3 install ropper
	echo -e "${GREEN_BG}Installed ropper ${RESET}"
	sleep 1
	
	sudo apt install -y tcpflow
	echo -e "${GREEN_BG}Installed tcpflow ${RESET}"
	sleep 1
	
	sudo gem install wpscan
	echo -e "${GREEN_BG}Installed wpscan ${RESET}"
	sleep 1
	
	pip3 install pwn
	echo -e "${GREEN_BG}Installed pwntools ${RESET}"
	sleep 1
	
	echo -e "$(yellowprint ' Cloning Github Repositories and installing them')"
	
	if [[ ! -d peda ]]
	then
		git clone https://github.com/longld/peda
		echo "source $HOME/tools/peda/peda.py" >> ~/.gdbinit
	fi
	echo -e "${GREEN_BG}Installed peda ${RESET}"
	sleep 1

	if [[ ! -d zsteg ]]
	then
		git clone https://github.com/zed-0xff/zsteg
		cd zsteg/bin
		sudo gem install zsteg
	fi
	cd $HOME/tools
	echo -e "${GREEN_BG}Installed zsteg ${RESET}"
	sleep 1
	
	if [[ ! -d nikto ]]
	then
		git clone https://github.com/sullo/nikto
		head -n 20 nikto/README.md | tail -n 6
	fi
	echo -e "${GREEN_BG}Installed nikto ${RESET}"
	sleep 1

	if [[ ! -f unix-privesc-check.sh ]]
	then
		wget https://raw.githubusercontent.com/pentestmonkey/unix-privesc-check/1_x/unix-privesc-check
		mv unix-privesc-check unix-privesc-check.sh
		chmod +x unix-privesc-check.sh
	fi
	echo -e "${GREEN_BG}Installed unix-privesc-check ${RESET}"
	sleep 1
	
	if [[ ! -d joomscan ]]
	then
		git clone https://github.com/rezasp/joomscan.git
	fi
	echo -e "${GREEN_BG}Installed Joomscan ${RESET}"
	sleep 1

	if [[ ! -d dirsearch ]]
	then
		git clone https://github.com/maurosoria/dirsearch
	fi
	echo -e "${GREEN_BG}Installed Dirsearch \e[0m"
	sleep 1
	if [[ ! -d GitTools ]]
	then
		git clone https://github.com/internetwache/GitTools
	fi
	echo -e "${GREEN_BG}Installed GitTools ${RESET}"
	sleep 1
	
		if [[ ! -f LinEnum.sh ]]
	then
		wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
		chmod +x LinEnum.sh
	fi
	echo -e "${GREEN_BG}Installed LinEnum ${RESET}"
	sleep 1

	if [[ ! -d DNSenum  ]]
	then
		git clone https://github.com/theMiddleBlue/DNSenum
	fi
	echo -e "${GREEN_BG}Installed DNSenum ${RESET}"
	sleep 1
	
	if [[ ! -d dnsmap ]]
	then
		git clone https://github.com/makefu/dnsmap/
		cd dnsmap
		gcc -Wall dnsmap.c -o dnsmap
		sudo cp dnsmap /usr/bin/
	fi
	cd $HOME/tools
	echo -e "${GREEN_BG}Installed dnsmap ${RESET}"
	sleep 1

	if [[ ! -f enum4linux.pl  ]]
	then
		wget https://raw.githubusercontent.com/portcullislabs/enum4linux/master/enum4linux.pl
		chmod +x enum4linux.pl
	fi
	echo -e "${GREEN_BG}Installed Enum4Linux ${RESET}"
	sleep 1

	if [[ ! -d setoolkit  ]]
	then
    	git clone https://github.com/trustedsec/social-engineer-toolkit/ setoolkit/
		cd setoolkit
		pip3 install -r requirements.txt
		sudo python3 setup.py
	fi
	echo -e "${GREEN_BG}Installed setoolkit ${RESET}"
	sleep 1
	cd $HOME/tools

	if [[ ! -d sqlmap-dev  ]]
	then
    	git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev
	fi
	echo -e "${GREEN_BG}Installed SQLmap ${RESET}"
	sleep 1
	
	if [[ ! -d Wordpresscan  ]]
	then
    	git clone https://github.com/swisskyrepo/Wordpresscan
		cd Wordpresscan
		pip2 install -r requirements.txt
	fi
	echo -e "${GREEN_BG}Installed Wordpresscan ${RESET}"
	sleep 1
	cd $HOME/tools

	if [[ ! -d johnny  ]]
	then
    	git clone  https://github.com/shinnok/johnny.git && cd johnny
		git checkout v2.2
		export QT_SELECT=qt5
		qmake && make -j$(nproc)
	fi
	cd $HOME/tools
	echo -e "${GREEN_BG}Installed Johnny ${RESET}"
	sleep 1
	
	if [[ ! -d gobuster  ]]
	then
    	mkdir gobuster
		cd gobuster
		wget https://github.com/OJ/gobuster/releases/download/v3.1.0/gobuster-linux-amd64.7z
		7z x gobuster-linux-amd64.7z
		mv gobuster-linux-amd64/gobuster .
		rm -r gobuster-linux-amd64
		chmod +x gobuster
	fi
	echo -e "${GREEN_BG}Installed Gobuster ${RESET}"
	cd $HOME/tools
	sleep 1

	if [[ ! -d DirBuster  ]]
	then
    	wget "http://downloads.sourceforge.net/project/dirbuster/DirBuster%20%28jar%20%2B%20lists%29/1.0-RC1/DirBuster-1.0-RC1.tar.bz2?r=http%3A%2F%2Fsourceforge.net%2Fprojects%2Fdirbuster%2Ffiles%2FDirBuster%2520%2528jar%2520%252B%2520lists%2529%2F1.0-RC1%2F&ts=1370262745&use_mirror=nchc" -O DirBuster-1.0-RC1.tar.bz2
    	tar -xjvf DirBuster-1.0-RC1.tar.bz2
		mv DirBuster-1.0-RC1 DirBuster
		rm DirBuster-1.0-RC1.tar.bz2
	fi
	echo -e "${GREEN_BG}Installed Dirbuster ${RESET}"
	sleep 1
	
	cd $HOME/tools

	if [[ ! -d wordlist ]]
	then
		mkdir wordlist
		cd wordlist
		wget https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt
		git clone https://github.com/daviddias/node-dirbuster
		mkdir dirbuster
		cd node-dirbuster/lists/
		mv * ../../dirbuster
		cd ../.. && sudo rm -r node-dirbuster
		cd $HOME/tools
	fi
	echo -e "${GREEN_BG}Installed Wordlists ${RESET}"
	sleep 1

	echo -e "${GREEN_BG}Installing Metasploit Framework ${RESET}"
	curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && \
  	chmod 755 msfinstall && ./msfinstall
	echo -e "${GREEN_BG}Installed Metasploit Framework ${RESET}"
	echo -e "$(yellowprint ' When Opening msfconole (Metasploit) for the first, type `no` when asked for creating msfdb ')"
	cd $HOME/tools
	sleep 1
	
	
}

install_dfir_tools() {

	echo -e "$(yellowprint ' Proceeding to install DFIR tools')"
	echo -e "$(blueprint ' Tools from github are installed to $HOME/tools/ Directory')"
	if [[ ! -d "$HOME/tools" ]]
	then
		mkdir $HOME/tools
	fi
	echo -e "$(yellowprint ' Moving to tools directory ')"
	cd $HOME/tools
	sleep 1
	
	sudo apt install -y wireshark-qt tshark
	echo -e "${GREEN_BG}Installed wireshark ${RESET}"
	sleep 1
	
	sudo apt install -y foremost
	echo -e "${GREEN_BG}Installed foremost ${RESET}"
	sleep 1
	
	sudo apt install -y pngcheck
	echo -e "${GREEN_BG}Installed pngcheck ${RESET}"
	sleep 1
	
	pip2 install oletools
	echo -e "${GREEN_BG}Installed oletools ${RESET}"
	sleep 1
	
	pip2 install peepdf
	echo -e "${GREEN_BG}Installed peepdf ${RESET}"
	sleep 1
	
	sudo apt install -y steghide
	echo -e "${GREEN_BG}Installed steghide ${RESET}"
	sleep 1
	wget "https://github.com/RickdeJager/stegseek/releases/download/v0.6/stegseek_0.6-1.deb" -O stegseek.deb
	sudo apt install -y ./stegseek.deb
	rm stegseek.deb
	echo -e "${GREEN_BG}Installed stegseek ${RESET}"
	sleep 1
	
	sudo apt install -y sonic-visualiser
	echo -e "${GREEN_BG}Installed sonic-visualiser ${RESET}"
	
	sleep 1
	sudo apt install -y stegsnow
	echo -e "${GREEN_BG}Installed stegsnow ${RESET}"
	sleep 1
	
	sudo apt install -y testdisk
	echo -e "${GREEN_BG}Installed testdisk ${RESET}"
	sleep 1
	
	sudo apt install -y audacity
	echo -e "${GREEN_BG}Installed audacity ${RESET}"
	sleep 1
	
	pip3 install scapy
	echo -e "${GREEN_BG}Installed scapy ${RESET}"
	sleep 1
	
	pip3 install stego-lsb
	echo -e "${GREEN_BG}Installed stegolsb ${RESET}"
	sleep 1

	sudo apt install exiftool
	echo -e "${GREEN_BG}Installed exiftool ${RESET}"
	sleep 1

	echo -e "$(yellowprint ' Cloning Github Repositories and installing them')"
	
	python2 -m pip install -U distorm3 yara pycrypto pillow openpyxl ujson pytz ipython capstone
    	sudo python2 -m pip install yara
    	sudo ln -s /usr/local/lib/python2.7/dist-packages/usr/lib/libyara.so /usr/lib/libyara.so
	git clone https://github.com/AdityaSec/Vol-GUI
	cd Vol-GUI
	git clone https://github.com/volatilityfoundation/volatility
	cd volatility; sudo python2 setup.py install; cd ..
	git clone https://github.com/superponible/volatility-plugins plugins
	echo -e "${GREEN_BG}Volatility 2 (vol.py) and Vol-GUI installed ${RESET}"
	cd $HOME/tools
    	sleep 1

    	python3 -m pip install -U distorm3 yara pycrypto pillow openpyxl ujson pytz ipython capstone
    	python3 -m pip install -U git+https://github.com/volatilityfoundation/volatility3.git
	echo -e "${GREEN_BG}Volatility 3 (volshell) installed  ${RESET}"
	sleep 1


	if [[ ! -f stegsolve.jar ]]
	then
		wget https://github.com/eugenekolo/sec-tools/raw/master/stego/stegsolve/stegsolve/stegsolve.jar
	fi
	echo -e "${GREEN_BG}Installed stegsolve.jar ${RESET}"
	sleep 1

	if [[ ! -d ghidra_installer ]]
	then
		git clone https://github.com/nxb1t/ghidra_installer
		cd ghidra_installer
		bash ./install-ghidra.sh
	fi
	cd $HOME/tools
	echo -e "${GREEN_BG}Installed ghidra ${RESET}"
	sleep 1
	
	if [[ ! -d dex2jar-2.0 ]]
	then
		wget https://sourceforge.net/projects/dex2jar/files/latest/download
		unzip download
		rm download
	fi
	echo -e "${GREEN_BG}Installed Dex2jar ${RESET}"
	sleep 1
	
	if [[ ! -d MobSF ]]
	then
		git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF MobSF
		cd MobSF
		bash ./setup.sh
	fi
	cd $HOME/tools
	echo -e "${GREEN_BG}Installed MobSF ${RESET}"
	sleep 1

	if [[ ! -d autopsy-4.19.2 ]]
	then
		wget "https://github.com/sleuthkit/autopsy/releases/download/autopsy-4.19.2/autopsy-4.19.2.zip" -O autopsy.zip
		unzip autopsy.zip
		rm autopsy.zip
		cd "autopsy-4.19.2"
		bash ./unix_setup.sh
		sudo echo -n "
[Desktop Entry]
Name=Autopsy
Comment=Autopsy Digital Forensics Framework
Exec=/home/nxb1t/Tools/autopsy/bin/autopsy
Terminal=False
Type=Application
Icon=$HOME/tools/autopsy-4.19.2/icon.ico
Categories=Forensics" > /usr/share/applications/autopsy.desktop
		if [[ -f $HOME/.bashrc ]]
    	then
         	echo "export PATH=$PATH:$HOME/.local/bin" >> $HOME/.bashrc
         	echo "export JAVA_HOME=/usr/lib/jvm/bellsoft-java8-full-amd64" >> $HOME/.bashrc
         	source $HOME/.bashrc
     	fi
 
     	if [[ -f $HOME/.zshrc ]]
     	then
         	echo "export PATH=$PATH:$HOME/.local/bin" >> $HOME/.zshrc
         	echo "export JAVA_HOME=/usr/lib/jvm/bellsoft-java8-full-amd64" >> $HOME/.zshrc
         	source $HOME/.zshrc
    	fi
	fi
	cd $HOME/tools
	echo -e "${GREEN_BG}Installed autopsy ${RESET}"
	echo -e "$(yellowprint ' If first run is stuck please run the commandline `~/tools/autopsy-4.19.2/bin/autopsy --nosplash`')"
	sleep 1

	if [[ ! -d jadx ]]
	then
		wget "https://github.com/skylot/jadx/releases/download/v1.4.3/jadx-1.4.3.zip" -O jadx.zip
		unzip jadx.zip -d jadx
		rm jadx.zip
	fi
	echo -e "${GREEN_BG}Installed jadx ${RESET}"
	sleep 1

	if [[ ! -d ALEAPP ]]
	then
		git clone https://github.com/abrignoni/ALEAPP
		cd ALEAPP
		pip3 install -r requirements.txt
	fi
	cd $HOME/tools
	echo -e "${GREEN_BG}Installed ALEAPP ${RESET}"
	sleep 1

	if [[ ! -d iLEAPP ]]
	then
		git clone https://github.com/abrignoni/iLEAPP
		cd iLEAPP
		pip3 install -r requirements.txt
	fi
	cd $HOME/tools
	echo -e "${GREEN_BG}Installed iLEAPP ${RESET}"
	
	if [[ ! -d bulk_extractor ]]
	then
		echo -e "${GREEN_BG}Installing bulk_extractor , this might take some time ${RESET}"
		git clone https://github.com/simsong/bulk_extractor
		cd bulk_extractor; git git submodule update --init --recursive
		./bootstrap.sh
		./configure
		make -j4
		sudo make install
	fi
	cd $HOME/tools
	echo -e "${GREEN_BG}Installed bulk_extractor ${RESET}"
	sleep 1

	echo -e "${GREEN_BG}Tools installed successfully ${RESET}"
	echo -e "$(redprint ' Please Logout and Login to finish installation ')"
	cd $HOME
}

main_menu() {
	echo -ne "
$(cyanprint ' MAIN MENU')
$(blueprint ' 1)') List all tools
$(blueprint ' 2)') Install all tools
$(blueprint ' 3)') Install by category
$(redprint ' 0)') Exit
 Choose an option : "
	read -r op
	case $op in
		1)
			echo " Available Tools"
			list_tools | less
			;;
		2)
			install_pen_dependencies
			install_pen_tools
			install_dfir_dependencies
			install_dfir_tools
			;;
		3)
			echo -e "$(magentaprint '\n INSTALL BY CATEGORY')"
			echo -e "$(redprint ' 1)') PENTESTING"
			echo -e "$(blueprint ' 2)') DFIR"
			echo -e "$(yellowprint ' 0)') Back to Main Menu"
			echo -n " Choose an option : "
			read -r c
			case $c in
				1)
					install_pen_dependencies
					install_pen_tools
					;;
				2)
					install_dfir_dependencies
					install_dfir_tools
					;;
				0)
					clear
					banner
					main_menu
					;;
				*)
					echo -e "$(redprint ' Invalid Option ')"
					exit 1
					;;
				esac
			;;
		0)
			echo " Exiting"
			exit 0
			;;
		*)
			echo " Wrong option"
			exit 1
			;;
		esac
}

banner
main_menu
