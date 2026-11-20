# AgentOS

Vlastní operační systém podle [technického zadání](ZADANI.md). Dosavadní implementaci, historické výsledky z VirtualBoxu a dosud neověřené kroky rozlišuje [plán implementace](PLAN_IMPLEMENTACE.md).

Rustové jádro po převzetí řízení od vlastního loaderu provede bootovací a procesové zkoušky, vypíše `AGENTOS KERNEL OK STAGE 1` přes UART 16550 a vykreslí stejný text přímo do framebufferu. Poté zastaví CPU. Obraz obsahuje ELF jádra a deterministický archiv newc. Minimální loader v C používá GNU-EFI pro volání firmwaru. Kernelový vstup, vlastní zásobník a textový výstup běží po `ExitBootServices`. Aktuální profil jádra potřebuje jeden segment na fyzické adrese 32 MiB.

## Sestavení a spuštění

Ve druhé etapě jádro na bootovacím procesoru vytvoří bitmapový alokátor z konvenční paměti nad prvním MiB, sestaví vlastní čtyřúrovňové tabulky stránek a přepne CR3. Kód jádra lze číst a spouštět. Konstanty lze pouze číst, zásobník a pracovní RAM lze číst a zapisovat. Nulová stránka a první stránka pod zásobníkem zůstávají bez mapování. Jádro instaluje vlastní GDT, TSS a IDT pro vektory 0–31. Pro dvojitou výjimku má samostatný zásobník.

Po přepnutí CR3 test vyvolá breakpoint a čtyři stránkové výjimky při čtení adresy nula, čtení ochranné stránky zásobníku, zápisu do konstanty a pokusu spustit instrukci ze stránky s příznakem NX. Obsluha ověří vektor, chybový kód a uložený instrukční ukazatel, u stránkových výjimek také adresu v CR2. Každý úspěšný návrat umožní pokračovat dalším testem. Neočekávaná výjimka vypíše diagnostiku na COM1 a zastaví CPU. Po testech jádro znovu prověří alokátor. Hostitel kontroluje adresu CR3, souhrn testů na COM1 a text na displeji. V obou profilech test běží na bootovacím procesoru.

Jádro přečte aktivní APIC ID z tabulky ACPI MADT. Bootovací procesor zkalibruje lokální časovač xAPIC proti časovači ACPI PM a spouští další procesory pomocí INIT a Startup IPI. Každý procesor dostane vlastní zásobník, IDT, GDT a TSS. Postupně na každém z nich běží jádrová úloha, která třikrát nastaví jednorázový časovač a čeká přes `sti; hlt`. Obsluha zkontroluje aktivní vektor v lokálním APIC, potvrdí přerušení pomocí EOI a započítá probuzení podle návratové adresy za `hlt`. Skript vyžaduje záznam úlohy se třemi probuzeními pro každé z očekávaných různých APIC ID a právě jeden záznam bootovacího procesoru (BSP).

Po ověření probuzení přepne každý CPU svůj lokální časovač do periodického režimu s kvantem přibližně 10 ms. Plánovač vybírá jádrová vlákna kruhově z fronty daného procesoru. Přerušení uloží celočíselné registry, stav x87/SSE a návratový rámec na zásobník vlákna. Po dokončení posledního vlákna se obnoví původní kontext a periodický časovač se vypne.

Zátěžová zkouška spustí dvě vlákna na každý CPU. Každé ověří vlastní hodnoty registrů přes několik kvant bez dobrovolného předání řízení a provede 4 096 přidělení a uvolnění 4KiB stránek. V 16 bodech testu všechna vlákna současně drží po osmi stránkách a před uvolněním ověří značky vlastníka na začátku a konci každé stránky. Sdílený alokátor chrání bitmapu a počitadlo zámkem, při jehož držení jsou lokální přerušení zakázaná. Hostitel vyžaduje pro každé vlákno alespoň dvě přepnutí časovačem na jiné spustitelné vlákno, dokončení všech operací a přesnou shodu celé bitmapy i počtu volných stránek před zátěží a po ní.

Při zkoušce vyčerpání jádro obsadí všechny zbývající volné 4KiB stránky alokátoru. Každý vCPU zkusí přidělit běžnou i nulovanou stránku. Po uvolnění jediné stránky se ověří vrácení částečné alokace a opětovné získání téže stránky s nulovým obsahem. Po vrácení všech stránek se porovná celá bitmapa s výchozí kopií a zopakuje se běžný dvoustránkový test.

Měření klidu začíná po obnově paměti a ukončení zátěžových vláken. Každý vCPU čeká se zapnutými přerušeními v `hlt` a nastaví jediný termín přibližně za 30 sekund. Periodické přerušení plánovače je během měření vypnuté. Jádro počítá všechny návraty z `hlt` a zvlášť eviduje jednorázová přerušení měřicího časovače. Při předčasném vypršení znovu nastaví zbývající čas a započte obě probuzení. Pro odhad aktivního času odečte od celkové doby intervaly od vstupu do čekání po vstup do obsluhy přerušení. Výsledek zahrnuje obsluhu koncového přerušení a měřicí kód. Profil VirtualBox Minimal poskytuje frekvence TSC a lokálního APIC přes CPUID. Mimo tento profil je dostupná kalibrace proti ACPI PM. Hostitel nezávisle změří dobu mezi počátečním a koncovým záznamem pomocí stopek. Surové hodnoty zůstanou na COM1 a skript zapíše délku intervalu, probuzení a aktivní podíl každého vCPU do `build/runs/<název VM>/idle.csv`. Čísla popisují čas pozorovaný hostovaným jádrem.

Příkazy se spouštějí z kořene projektu v PowerShellu. Sestavení používá WSL Ubuntu-24.04 s balíky ze `scripts/toolchain.lock`, dále sbsigntool, efitools a openssl. Vytvoření testovacího disku používá gdisk a mtools. Hostitel používá VirtualBox 7.1.12, Windows PowerShell nebo PowerShell 7 a Python 3 dostupný příkazem `python` pro kontrolu procesových logů i negativní testy podpisu.

```powershell
wsl -d Ubuntu-24.04 -- bash scripts/build.sh
.\scripts\test-vbox.ps1 -Cpus 1
.\scripts\test-vbox.ps1 -Cpus 2
```

Výsledkem sestavení je `build/agentos.efi`. Při prvním sestavení se vytvoří místní testovací podpisový klíč v linuxovém adresáři `~/.local/share/agentos/stage1-test-keys` (případně pod `XDG_DATA_HOME`). Do projektu se exportují jen veřejná data pro testovací firmware. Dvě opakovaná sestavení se porovnávají podle SHA-256 souboru `build/agentos.unsigned.efi`, před připojením podpisu.

Spouštěcí skript vytvoří vlastní VM s novým úložištěm EFI proměnných, důvěrou k testovacímu certifikátu, virtuálním GPT diskem přes AHCI, EFI64, 256 MiB RAM, VMSVGA a COM1 do souboru. Fyzický firmware a fyzické disky nejsou součástí testu. Při úspěchu skript ověří sériovou zprávu i masku znaků na snímku displeje. VM vypne a ponechá její konfiguraci a důkazy v `build/runs/<název VM>/`. Testy spouštěj jednotlivě.

```powershell
.\scripts\test-vbox.ps1 -Case loader
.\scripts\test-vbox.ps1 -Case kernel
.\scripts\test-vbox.ps1 -Case initrd
```

Každý negativní test změní jeden bajt příslušné sekce v kopii již podepsaného obrazu. Vyžaduje explicitní odmítnutí zaváděcího disku od firmwaru v logu COM1. Samotný timeout ani pád hostitelského procesu nejsou důkazem odmítnutí podpisu.

## Uživatelské procesy a nativní ABI v1

Procesor spouští statické ELF64 programy pro x86-64 v CPL3. Jádro je čte ze sekce initramfs podepsaného obrazu. Loader přijímá `ET_EXEC` s nepřekrývajícími se stránkami segmentů `PT_LOAD` v uživatelském rozsahu od `0x8000000000` do `0x10000000000` (horní hranice je otevřená). Pod čtyřstránkovým zásobníkem zůstává ochranná stránka. Každý proces má vlastní CR3, privátní stránky programu a zásobníku a samostatný zásobník pro vstup do jádra. Zapisovatelné uživatelské stránky mají NX, mapování jádra je přístupné pouze v privilegovaném režimu.

Nativní ABI používá instrukci `syscall`. Číslo volání je v RAX, první tři argumenty v RDI, RSI a RDX. RAX vrací výsledek nebo záporné číslo chyby. RCX a R11 se přepisují. Čísla řady `0x10000` označují verzi 1 a jsou dostupná v [hlavičce pro programy](user/abi.h).

| Volání | Argumenty | Výsledek |
|---|---|---|
| `getpid` | žádné | PID volajícího |
| `write` | fd, adresa, délka | Počet zapsaných bajtů. Počáteční fd 1 vede na COM1 a přijímá nejvýše 256 bajtů na volání. Zápis do roury může čekat na volné místo. |
| `exit` | stav | Ukončí proces. Rodič může převzít dolních 8 bitů stavu. |
| `spawn` | adresa jména, délka | PID potomka. Cesta k ELF má 1–64 bajtů bez koncové nuly. Potomek dostane vlastní zásobník a zdědí popisovače pod stejnými čísly. |
| `try_wait` | PID potomka | Převezme stav a uvolní prostředky potomka. Stav po výjimce je 256 + číslo vektoru. Běžící potomek vrací −11, cizí nebo již převzatý PID vrací −10. |
| `yield` | žádné | Předá CPU další spustitelné úloze. Po obnovení vrátí 0. |
| `open` | adresa cesty, délka, příznaky | Otevře běžný soubor ke čtení od začátku a vrátí nejnižší volný fd. Cesta má 1–128 bajtů bez koncové nuly. Podporované příznaky jsou 0. |
| `read` | fd, adresa cíle, délka | Vrací počet přečtených bajtů. Při nenulové požadované délce značí 0 konec souboru nebo vyprázdněnou rouru po zavření posledního zapisujícího konce. |
| `close` | fd | Uzavře popisovač a vrátí 0. Při ukončení procesu včetně pádu jádro zavře všechny zbývající popisovače. |
| `pipe` | adresa dvou 32bitových celých čísel | Vytvoří anonymní rouru a vrátí 0. Na zadanou adresu uloží čtecí a poté zapisující fd. |
| `dup2` | původní fd, cílový fd | Nahradí cílový popisovač kopií původního a vrátí cílové číslo. Duplikované i zděděné popisovače běžného souboru sdílejí pozici čtení. |
| `ipc_pair` | adresa dvou 32bitových celých čísel | Vytvoří obousměrný lokální kanál, zapíše oba fd a vrátí 0. |
| `ipc_send` | fd, adresa zprávy, délka | Odešle jednu zprávu o 1–1 024 bajtech a vrátí její délku. Čeká, pokud je schránka protistrany obsazená. |
| `ipc_recv` | fd, adresa cíle, kapacita dat | Přijme jednu zprávu včetně hlavičky s identitou odesílatele. Kapacita i návratová hodnota počítají pouze data za hlavičkou. Po vyčerpání zpráv a uzavření protistrany vrátí 0. |

Kořen VFS tvoří initramfs pouze pro čtení. Absolutní i relativní cesty se vyhodnocují od kořene po jednotlivých složkách včetně `.` a `..`. Proces má 32 míst pro popisovače. Roura zachovává pořadí bajtů a má kapacitu 1 024 bajtů. Zápisy do této velikosti jsou atomické, větší zápis může vrátit dílčí počet. Plánovač uspí čtenáře prázdné roury nebo zapisovatele čekajícího na místo a znovu jej zařadí při změně podmínek. Zápis po zavření všech čtecích konců vrátí −32. Neplatný nebo nesprávně použitý popisovač vrátí −9, nepřístupný uživatelský buffer −14 a neznámé volání −38.

### Lokální zprávové IPC

Volání `ipc_pair`, `ipc_send` a `ipc_recv` mají čísla `0x1000c`, `0x1000d` a `0x1000e`. Každý směr kanálu má jednu schránku pro nejvýše `IPC_MAX_MESSAGE` (1 024) bajtů. Hranice zpráv zůstávají zachované. Příjemce prázdné schránky i odesílatel čekající na místo se uspí; změna obsahu nebo poslední uzavření protistrany je znovu zařadí do plánování. `dup2` i `spawn` drží další referenci ke stejnému konci kanálu. EOF a chyba zápisu proto nastanou až po uzavření všech referencí protistrany.

Přijatá zpráva začíná 16bajtovou `struct ipc_peer`: PID jako 64bitové číslo, UID a GID jako dvě 32bitová čísla, vše v pořadí little-endian. Hlavičku sestavuje jádro z identity procesu při odeslání; hodnoty uvedené v datech zprávy ji neovlivní. Současný bootovací profil přiděluje procesům UID i GID 1000. Správa účtů a změny oprávnění přijdou v dalších etapách.

**Cíl příjmu musí mít místo pro hlavičku i data.** Argument kapacity a návratová hodnota hlavičku nezahrnují:

```c
struct {
    struct ipc_peer sender;
    unsigned char data[IPC_MAX_MESSAGE];
} message;
long received = os_call(SYS_IPC_RECV, fd, (long)&message, sizeof(message.data));
/* sender a data jsou platné při received > 0. */
```

Prázdná nebo příliš velká odesílaná zpráva a nedostatečná kapacita příjmu vracejí −90 (`EMSGSIZE`). Chybný buffer vrací −14 (`EFAULT`). Neúspěšný příjem zprávu neodebere; před zápisem se ověřuje celý rozsah hlavičky a dat. Zprávu zařazenou před uzavřením odesílatele lze ještě přijmout, teprve další příjem vrátí EOF. Odeslání po uzavření protistrany vrací −32 (`EPIPE`). Neplatné číslo fd vrací −9 (`EBADF`), IPC volání nad jiným typem otevřeného popisovače −88 (`ENOTSOCK`).

Současné kanály propojují procesy připnuté ke stejnému vCPU, s jedním vláknem na proces. Přenos konců mezi CPU, migrace procesů a vícevláknové sdílení popisovačů zatím nejsou podporované. Toto je transportní základ; agentní protokol a správce služeb jsou samostatné další kroky.

### Procesový akceptační scénář

Akceptační běh na každém dostupném vCPU spustí `init`. Jeho první potomek `fault` vyvolá při čtení stránky jádra výjimku. Rodič převezme stav 270 a ověří vlastní data. Pak spustí druhého potomka `receiver`, otevře `/data/transfer.bin` a jeho obsah odešle rourou. Rodič čte po 317 bajtech střídavě přes dva popisovače téhož souboru. Potomek čte z roury po nejvýše 193 bajtech, porovná všech 8 193 bajtů s očekávanými hodnotami a dvakrát ověří EOF. Hostitel kontroluje vztahy PID, odlišné CR3, počet bajtů, FNV-1a, návratové stavy i následnou kontrolu volných stránek. Rodič a jeho potomci jsou připnuti ke stejnému vCPU.

Následuje kontrola IPC v `init`: neplatné popisovače, chybný typ popisovače, nulová a nadlimitní délka, neplatný buffer a vrácení prostředků po neúspěšném vytvoření páru. Přenos 1 024 bajtů a současná zpráva opačným směrem ověřují obsah a samostatnost schránek. Příliš malý, nepřístupný, nezapisovatelný a přetékající cíl příjmu musí ponechat zprávu neporušenou. Duplikovaný konec musí přežít uzavření originálu a zařazená zpráva uzavření odesílatele; po jejím přečtení následují EOF a `EPIPE`.

Poté `init` spustí třetího potomka `service`. Klient záměrně uvede v datech nulovou identitu. Služba ověří skutečnou identitu z hlavičky a odpoví na výzvu; klient zkontroluje odpověď i identitu služby. Záznamy `AGENTOS IPC SERVICE` a `AGENTOS IPC REPLY` obsahují protilehlé PID a UID/GID 1000. Kontrola logu vyžaduje všechny čtyři různé PID a tři úspěšná ukončení na každý CPU (`receiver`, `service`, `init`), správné pořadí událostí a privátní CR3 potomků vůči rodiči. Následuje kernelová kontrola návratu bitmapy volných stránek. Dokončení IPC scénáře ve VirtualBoxu zatím čeká na ověření.

### Kontrola logů bez VirtualBoxu

`verify-processes.ps1` zachovává rozhraní pro VM skript a spouští přenositelnou kontrolu v Pythonu. Samotný kontrolní program lze otestovat bez VM:

```powershell
python scripts/test-verify-processes.py -v
```

Testy používají syntetické logy pro jeden a dva CPU a poškozené varianty. Ověřují kontrolní program, nikoli běh operačního systému. Skutečný zachycený log lze zkontrolovat například takto (APIC ID musí odpovídat danému běhu):

```powershell
python scripts/verify-processes.py --log build/runs/<nazev-VM>/com1.log --apic-ids 0000000000000000 0000000000000001
```

Kontrola záměrně odmítne starší log bez IPC, chybějící či opakované záznamy, nesprávné identity a neúspěšná ukončení. Samotný soubor logu nedokládá původ obrazu; protokol musí dál uvádět verzi zdrojů, hash EFI a konfiguraci VM.
