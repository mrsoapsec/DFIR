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
wmic -> product get name,version

Linux

find /caminho/do/diretorio -ctime -2








Powershell Hunting


# Ferramentas 

[fulleventlogview-x64-new.zip](https://github.com/mrsoapsec/DFIR/files/14737079/fulleventlogview-x64-new.zip)
[browsinghistoryview-x64.zip](https://github.com/mrsoapsec/DFIR/files/14737046/browsinghistoryview-x64.zip)
[processhacker-2.39-setup.zip](https://github.com/mrsoapsec/DFIR/files/14737052/processhacker-2.39-setup.zip)

- pestudio → Malware Assesment
- Magnet DumpIt → Dump memoria ram
- volatility → analise full de dump de memoria
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


Os principais tipos de ataques explorados por atacantes no **Active Directory (AD)** geralmente têm como objetivo comprometer a infraestrutura de autenticação e controle de acesso, obtendo privilégios elevados ou controle total da rede. Aqui estão alguns dos ataques mais comuns:

### 1. **Pass-the-Hash (PtH)**
   - **Como funciona**: O atacante rouba um hash de senha (geralmente de um administrador ou outro usuário privilegiado) e usa esse hash diretamente para se autenticar em outros sistemas sem precisar da senha em texto simples.
   - **Impacto**: Pode permitir que um invasor se mova lateralmente pela rede e acesse recursos sensíveis.

### 2. **Pass-the-Ticket (PtT)**
   - **Como funciona**: O atacante obtém um ticket de autenticação (Kerberos TGT ou TGS) e o usa para acessar recursos protegidos.
   - **Impacto**: Pode fornecer acesso a serviços protegidos dentro do domínio sem a necessidade de credenciais adicionais.

### 3. **Golden Ticket**
   - **Como funciona**: Um atacante compromete a conta de um **Domain Controller (DC)** e gera um **TGT (Ticket-Granting Ticket)** com permissões de domínio ilimitadas, essencialmente assumindo o controle total do ambiente AD.
   - **Impacto**: O invasor pode obter controle administrativo sobre qualquer recurso dentro do domínio.

### 4. **Silver Ticket**
   - **Como funciona**: Um atacante cria manualmente um ticket Kerberos para um serviço específico (não o TGT), como o Serviço de Autenticação Remota ou SQL.
   - **Impacto**: Embora o escopo seja menor que o de um Golden Ticket, ainda permite comprometimento de serviços individuais.

### 5. **Kerberoasting**
   - **Como funciona**: O atacante solicita tickets de serviço Kerberos (TGS) para contas de serviço e tenta quebrar offline os hashes de senhas.
   - **Impacto**: Pode expor senhas de contas de serviço, muitas vezes configuradas com permissões elevadas, permitindo o movimento lateral na rede.

### 6. **DCSync Attack**
   - **Como funciona**: O invasor faz com que uma máquina se comporte como um controlador de domínio e solicita que outros DCs sincronizem suas senhas e hashes de senha. Isso permite que o atacante roube senhas de todas as contas de domínio.
   - **Impacto**: Exposição massiva de credenciais e controle total sobre a rede.

### 7. **DCShadow Attack**
   - **Como funciona**: O atacante registra um controlador de domínio falso no AD, permitindo que ele execute alterações maliciosas diretamente nos dados do AD, sem gerar logs tradicionais.
   - **Impacto**: Permite que o invasor manipule objetos no AD de forma invisível para sistemas de monitoramento padrão.

### 8. **LDAP Reconnaissance**
   - **Como funciona**: Atacantes fazem consultas ao protocolo LDAP do AD para mapear a estrutura de diretórios, encontrar contas privilegiadas e obter informações sobre políticas de segurança e configurações da rede.
   - **Impacto**: Auxilia em ataques mais avançados, como elevação de privilégios e movimento lateral.

### 9. **Overpass-the-Hash / Pass-the-Key**
   - **Como funciona**: O atacante usa um hash de senha para derivar chaves Kerberos e se autenticar no AD.
   - **Impacto**: Pode ser utilizado para explorar sessões e obter acesso privilegiado.

### 10. **NTLM Relay**
   - **Como funciona**: Atacantes capturam a comunicação NTLM (Challenge-Response) e a retransmitem para outro servidor para obter acesso. Usualmente é explorado em redes mal configuradas que ainda usam NTLM ao invés de Kerberos.
   - **Impacto**: Permite elevação de privilégios e movimento lateral dentro da rede.

### 11. **Skeleton Key Attack**
   - **Como funciona**: Um malware é injetado no controlador de domínio, permitindo que o invasor use uma senha mestre em qualquer conta do domínio.
   - **Impacto**: Controle total sobre qualquer conta do domínio.

### 12. **Password Spraying**
   - **Como funciona**: Em vez de tentar várias senhas em uma única conta (o que pode ser detectado rapidamente), o atacante tenta uma senha comum em várias contas.
   - **Impacto**: Reduz a probabilidade de detecção e pode levar à descoberta de contas com senhas fracas.

### 13. **Brute Force Attack**
   - **Como funciona**: O atacante tenta descobrir senhas testando várias combinações até encontrar a correta.
   - **Impacto**: Embora básico, pode ser eficaz contra contas com políticas de senha fracas.

---

**Mitigações:**
Para proteger o AD contra esses ataques, as organizações podem implementar várias medidas, como:
- **MFA (Autenticação Multifator)** para contas privilegiadas.
- **Monitoramento contínuo** de logs e atividades anômalas no AD.
- **Aplicação de políticas de senha robustas** e restrição de uso de NTLM.
- **Segmentação de rede** e **limitação de credenciais de administração** de domínio a poucos usuários essenciais.

O Active Directory é um alvo crítico, e sua segurança é essencial para a proteção da infraestrutura de TI.

