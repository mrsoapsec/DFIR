## DFIR

# Microsoft Windows

# Powershell Hunting

- Versão SO -> #systeminfo | findstr /B /C:"OS Name" /C:"OS Version" 
- Patches instalados -> wmic qfe
- Variáveis do Sistema -> set Get-ChildItem Env: | ft Key,Value
- Calculo de Hash -> Get-FileHash -Algorothm md5 arquivo.exe
- 

# Processos Windows
- Poster Sans, Find Evil Process: [SANS_DFPS_FOR508_v4.10_02-23.pdf](https://github.com/mrsoapsec/CyberDefense/files/11436818/SANS_DFPS_FOR508_v4.10_02-23.pdf)
- Windows System Processes MindMap: [Windows.System.Processes.pdf](https://github.com/mrsoapsec/CyberDefense/files/11436831/Windows.System.Processes.pdf)
- Windows Services(Creation): [Windows.Services.Creation.pdf](https://github.com/mrsoapsec/CyberDefense/files/11436832/Windows.Services.Creation.pdf)



**wininit.exe**  
Responsável por startar
- ->services.exe
- ->lsass.exe
- ->lsm.exe

**services.exe**
Responsável pelo start/stop
- ->svchost.exe
- ->dllhost.exe
- ->taskhost.exe
- ->spoolsv.exe

**svchost.exe** -> 
Processo genérico que roda a partir de uma biblioteca de link dinâmico

**lsass.exe** -> 
Processo Responsável por operações de segurança CRÍTICAS. Confirma ou rejeita senhas de usuários no logon.
Este processp trabalha também durante a troca de senhas dos usuários (Obs: um atacante pode obter acesso ao sistema aproveitando deste processo)
A ferramenta mimikatz pode explorar as senhas através deste processo de lsass.exe

**winlogon.exe** ->
Processo responsável pelo login e logout do usuário

**explorer.exe** -> 
Processo PAI de quase todos os processos da interface gráfica(GUI)


Todos processos: -> 
#Get-WmiObject -Query "Select * from Win32_Process" | where {$*.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$*.GetOwner().User}} | ft -AutoSize

Processos de um usuario -> #tasklist /v /fi "username eq usuario"

Busca de um processo -> #tasklist | findstr lsass

Busca de um Srviço em um processo -> netstat -aon |findstr "numeroPorta"
                                     tasklist |findstr "numeroPid"
                  

Terminar processos -> #taskill /pid 2812

Todos serviços disponiveis no SO -> sc query type=service state=all
                                 -> sc query wuauserv (determinado serviço)




# [DRAFT] Privilegio Usuário

#whoami /priv

#whoami /groups

Requirimentos da conta -> #net accounts

Informação da conta ->  #net user usuario

Ultimo Logon -> Get-Localuser | Select Name,Lastlogon




Buscar Conteudo em arquivos: #findstr /SI /M "password" *.xml *.ini *.txt





net user z /delete

Delete local user


# Forense





# Analise Dinâmica Malware


#sudo -H pip install -U oletools
  
Sandbox de Macros Maliciosas -> #olevba documento.doc
  
Análise de documentos do office -> #oleid documento.doc
  
Informações osbre o documento -> olemeta documento.doc


# [DRAFT] Investigacao Forense

Windows

systeminfo >> notes.txt
  
netstat -nao >> notes.txt
  
route print >> notes.txt
  
echo %date% %time% >> notes.txt
  
set >> notes.txt
  
tasklist >> notes.txt
  
tasklist /m >> notes.txt
  
tasklist /svc >> notes.txt
  
net config workstation >> notes.txt
  
arp -a >> notes.txt
  
net user %username% >> notes.txt
  
ipconfig /displaydns >> notes.txt
  
net share >> notes.txt
  
ipconfig /all >> notes.txt

Linux

find /caminho/do/diretorio -ctime -2








Powershell Hunting


# Ferramentas 

[fulleventlogview-x64-new.zip](https://github.com/mrsoapsec/DFIR/files/14737079/fulleventlogview-x64-new.zip)
[browsinghistoryview-x64.zip](https://github.com/mrsoapsec/DFIR/files/14737046/browsinghistoryview-x64.zip)
[processhacker-2.39-setup.zip](https://github.com/mrsoapsec/DFIR/files/14737052/processhacker-2.39-setup.zip)

- pestudio → Malware Assesment
- Process Hacker → Atividades de processo do sistema
- Regshot → Visualizar atividades do registro
- Fiddler → Ver atividades de Rede
- Redline → ferramenta de investigação forense
- OpenhashTab → Programa que inclui calculo de hash em todos executaveis que você clica com o botão direito
- RecentFilesView → lista os ultimos arquivos abertos no sistema operacional
- BrowsingHistoyView → Ferramenta de historico de sites navegados (vários navegadores)
- Fulleventlogview → Ferramenta que contempla todos os logs do eventviewer do windows
  
**SYSINTERNALS**
- Procmon → Atividades de processo, arquivo, registro e rede
  Importante usar: "Show Process Tree”
  Filter → Operation=CreateFile (atividades de criação deatividades )
  Filter → Processname is arquivomalwareexecutado.exe
- autorun.exe → tudo que vai rodar no boot durante  o inicio do sistema. Virus total search 
- procexp.exe  lista todos os processos correntes. excelente para pegar malwares rodando
  importante→ colocar o virus total na coluna para ver o score de cada exe e dll
  colocar também command line na coluna
- Tcpview → análise em conexões de rede
---
-> Volatility

vol.py -h	options and the default values

vol.py -f imageinfo -	image identification

vol.py -f –profile=Win7SP1x64 pslist -	system processes

vol.py -f –profile=Win7SP1x64 pstree -	view the process listing in tree form

vol.py -f –-profile=Win7SP1x64 psscan	- inactive or hidden processes

vol.py -f –profile=Win7SP1x64 dlllist -	DLLs

vol.py -f –profile=Win7SP1x64 cmdscan -	commands on cmd

vol.py -f –profile=Win7SP1x64 notepad -	notepad

vol.py -f –profile=Win7SP1x64 iehistory -	IE history

vol.py -f –profile=Win7SP1x64 connscan -	active and terminated connections

vol.py -f –profile=Win7SP1x64 sockets	- TCP/UDP connections

vol.py -f –profile=Win7SP1x64 hivescan -	physical addresses of registry hives

vol.py -f –profile=Win7SP1x64 hivelist -	virtual addresses of registry hives

vol.py -f –profile=Win7SP1x64 svcscan	- running services

vol.py -f –profile=Win7SP1x64 mimikatz -	get the passwords

vol.py -f –profile=Win7SP1x64 malfind -	hidden, malicious code analysis

vol.py -f –profile=Win7SP1x64 psxview -	processes that try to hide themselves

vol.py -f –profile=Win7SP1x64 connections -	network connections

vol.py -f –profile=Win7SP1x64 filescan -	files in physical memory

vol.py -f –profile=Win7SP1x64 modules -	loaded kernel drivers

vol.py -f –profile=Win7SP1x64 driverscan -	drivers in physical memory

vol.py -f –profile=Win7SP1x64 apihooks -	hooked processes

vol.py -f –profile=Win7SP1x64 memmap -p <PID> -	shows which pages are memory resident

vol.py -f –profile=Win7SP1x64 memdump -p <PID> -D - 	dump all memory resident pages

vol.py -f –profile=Win7SP1x64 procdump -D dump/ -p <PID> -	dump the malware

vol.py -f –profile=Win7SP1x64 modscan -	hidden/unlinked drives

vol.py -f –profile=Win7SP1x64 hollowfind	- find evidence of process hollowing

vol.py -f –profile=Win7SP1x64 netscan	- scan for network artifacts

vol.py -f –profile=Win7SP1x64 hashdump	- extract and decrypt cached domain credentials

vol.py -f –profile=Win7SP1x64 hivedump	- list all subkeys in a hive recursively

vol.py -f –profile=Win7SP1x64 clipboard	- recover data from users’ clipboards

Google Dorking

Defacement
site:tce.mg.gov.br intext:"hacked by"
intext:'index of /admin' site:tce.mg.gov.br

inurl "t.me/joinchat" "APT"

Automatização
https://taksec.github.io/google-dorks-bug-bounty/
