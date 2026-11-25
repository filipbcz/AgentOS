# AgentOS

Vlastní operační systém pro x86-64 podle [technického zadání](ZADANI.md). Aktuální stav, přesné ověřené revize a otevřená přejímka jsou v [plánu implementace](PLAN_IMPLEMENTACE.md). Starší výsledky se nevztahují automaticky na nový obraz.

Etapa 3 obsahuje izolované procesy, nativní ELF ABI, COW, VFS nad initramfs, roury, autentizované lokální IPC, původní PID 1 se správou služeb a interaktivní TTY přes COM1 i PS/2/GOP. Milník 3.1 přidává demand paging procesů a řízenou migraci mezi CPU. Vývojová větev `dev/stage3-ipc-validation` byla 23. 11. 2026 sloučena do `main` (PR #1); samotné sloučení nenahrazuje úplnou přejímku všech profilů dle plánu. Etapa 4 nyní navazuje na ověřené AHCI a rozpracovává NVMe ve větvi `dev/stage4-nvme` (PR #2).

## Sestavení

Příkazy pro Windows se spouštějí z kořene čistého Git checkoutu v PowerShellu. Potřebné prostředí:

- WSL distribuce `Ubuntu-24.04`, balíky s přesnými verzemi z `scripts/toolchain.lock`, dále Python 3, OpenSSL, sbsigntool, efitools, gdisk a mtools;
- VirtualBox **7.1.12** s HPET (harness jej zapíná), Windows PowerShell nebo PowerShell 7;
- Python 3 dostupný ve Windows příkazem `python`.

```powershell
wsl -d Ubuntu-24.04 -- bash scripts/check-build.sh
wsl -d Ubuntu-24.04 -- bash scripts/build.sh
```

`check-build.sh` provede hostitelské testy, překlad/linkování skutečného jádra a všech 12 uživatelských ELF, kontrolu oprávnění kernelových segmentů, trap návratů a nativní ABI note. Přepínače `RUSTC`, `CC`, `LD` a `PYTHON` vybírají spustitelné soubory; skript nic nestahuje. Výsledky jsou v `build/check/`.

Textové soubory repozitáře používají konce řádků **LF** podle `.gitattributes`, také při checkoutu ve Windows. Toto pravidlo má přednost před `core.autocrlf`; automaticky rozpoznané binární soubory Git ponechá beze změny.

### Oprava staršího Windows checkoutu s CRLF

Chyba Bash `set: pipefail` / `invalid option name` hned na začátku hostitelské kontroly obvykle znamená, že skript obsahuje CRLF a Bash dostal argument `pipefail\r`. Starší checkout mohl tyto konce řádků vytvořit ještě před přidáním `.gitattributes`. Samotný `git pull` nemusí přepsat všechny již existující pracovní soubory.

Po aktualizaci větve spusť z kořene projektu v PowerShellu jednorázovou opravu. Zachová aktuální obsahové změny, převede CRLF na LF a zapíše UTF-8 bez BOM. Zahrnuje také `toolchain.lock`, protože CR na konci jeho řádků by poškodilo porovnání připnutých verzí balíčků.

```powershell
git pull --ff-only
$pUtf8 = [System.Text.UTF8Encoding]::new($false)
Get-ChildItem .\scripts\*.sh, .\scripts\toolchain.lock | ForEach-Object {
    $pText = [System.IO.File]::ReadAllText($_.FullName)
    [System.IO.File]::WriteAllText($_.FullName, $pText.Replace("`r`n", "`n"), $pUtf8)
}
```

Kontrola `git ls-files --eol -- 'scripts/*.sh' scripts/toolchain.lock` má u těchto souborů ukázat `i/lf` a `w/lf`. Potom znovu spusť původní sestavení nebo `scripts/accept-stage3.ps1`.

### Podepsaný obraz

`build.sh` kontroluje připnutý toolchain, sestaví deterministický newc initramfs a vlastní GNU-EFI loader s vloženým ELF jádra, zavolá podpis a ověří jej. Výsledkem je `build/agentos.efi`. Dvě opakovaná sestavení se porovnávají podle SHA-256 **nepodepsaného** `build/agentos.unsigned.efi`.

Při prvním sestavení vznikne místní testovací podpisový klíč v `~/.local/share/agentos/stage1-test-keys`, případně pod `XDG_DATA_HOME`. Do projektu se exportují veřejná data pro firmware. `build/build-provenance.json` váže hash obrazu, initramfs, certifikátu a toolchain locku na commit a čistý pracovní strom. Jde o kontrolovatelný záznam sestavení, nikoli nezávislou kryptografickou atestaci.

## Dokončení přejímky etapy 3 ve VirtualBoxu

Pro přejímku aktuálního stabilního základu použijte výchozí build na `main` (historická větev je zachována pro reprodukci starších důkazů):

```powershell
git switch main
git pull --ff-only
.\scripts\accept-stage3.ps1
```

Skript nejprve provede hostitelské kontroly a sestaví podepsaný obraz. Potom postupně spustí **13 profilů** s EFI64, 256 MiB RAM, VMSVGA, AHCI a odděleným úložištěm EFI proměnných. Každá VM má vlastní nově vytvořený testovací disk a důvěru k testovacímu certifikátu.

| Profil | CPU | Obsah |
|---|---|---|
| Podepsaný obraz, `info both` | 1 a 2 | Boot, demand/COW, migrace, IPC, PID 1, guardy, základní klid a GOP |
| Sériová relace, `debug serial` | 1 a 2 | Příkazy, správní IPC, restarty, provozní klid, čisté ukončení |
| Smíšená COM1/PS/2 relace, `info serial` | 1 a 2 | Totéž, navíc skutečná virtuální klávesnice a nově vykreslená odpověď |
| Podepsaný obraz, `quiet none` | 1 a 2 | Potlačení strukturovaných výpisů při funkčním systému |
| Podepsaný obraz, `debug screen` | 1 a 2 | Oddělení sériového a obrazového výstupu |
| Změněný loader, kernel, initramfs | 1 | Tři samostatná explicitní odmítnutí podpisu firmwarem |

Úspěch se oznámí jako `STAGE3_VM_MATRIX_PASSED=...`. Výsledky jsou v `build/runs/`, souhrn v `build/runs/stage3-acceptance.json`. Nezávislá kontrola souhrnu:

```powershell
python scripts/verify-stage3-suite.py --root . --manifest build/runs/stage3-acceptance.json
```

U každého úspěšného startu podepsaného obrazu vyžaduje offline kontrola jednotlivého běhu i celé matice úplné záznamy stránkování a migrace pro daný počet vCPU. Starší jednotlivý běh z doby před zavedením těchto zkoušek lze prohlédnout příkazem `python scripts/verify-vm-evidence.py --root . --run-dir CESTA_K_BEHU --legacy-traces`. V tomto režimu se ověří každá přítomná stopa. U negativních profilů se ověřuje odmítnutí obrazu firmwarem.

Každý běh zachytává COM1 přes vlastní obousměrnou pojmenovanou rouru ve Windows do `serial-com1.log` (také neinteraktivní a negativní profily), uchovává konfiguraci, verzi VirtualBoxu, screenshoty a JSON záznam s hashi obrazu, důkazů a testovacího skriptu. Jméno `serial-com1.log` je záměrné: `COM1` je ve Windows rezervovaný název zařízení i s příponou (`com1.log`), který způsoboval nekonzistentní chování `Test-Path`/`Get-FileHash`. Zachycení přes rouru odděluje chybějící sériové spojení od případu, kdy jádro běží na obrazovce, ale marker v COM1 chybí. Průběžné čekání čte přímo paměťový buffer; před ověřováním uloženého logu se souborový writer uzavře a pro interaktivní pokračování se znovu otevře v režimu append, aby Windows neblokoval čtenáře. Interaktivní profil přidává skutečně odeslané UART bajty do `com1-input.bin`; klávesnicový profil zachovává snímky před příkazem a po něm. Selhání nezanechá platný souhrn z předchozího běhu. Pokud VM selže během bootu, harness ještě **před vypnutím** zkusí pořídit `failure.png` a uloží jeho hash do neúspěšného `acceptance.json`; snímek je diagnostika, nikoli doklad úspěšné přejímky. COM1 log při selhání firmware může zcela chybět. `-SkipBuild` je určen jen pro opakování nad stejným čistým commitem a odpovídajícím obrazem.

Interaktivní COM1 vstup ve VirtualBoxu používá potvrzování každého odeslaného bajtu **skutečným echem kanonického TTY**. Starší pevná prodleva 2 ms mezi bajty nezaručovala, že emulovaný UART zpracoval předchozí znak při souběžném výpisu `AGENTOS USER EXIT`. Před dalším znakem harness čeká také na dokončení celého asynchronního kernelového záznamu. Po potvrzeném echem vkládá 20ms odstup pro dokončení emulovaného vysílání a IRQ/EOI ve VirtualBoxu (echo samo tento okamžik negarantuje). Není-li echo potvrzeno do 10 sekund, běh selže s přesným číslem a hexadecimální hodnotou bajtu; nepřidává žádný syntetický výpis ani nezmírňuje kontrolu relace. Interaktivní kontrola tří restartovaných workerů používá stejný limit **30 sekund hostitelského času** jako QEMU. Pokud chybí některý ze tří reálných `AGENTOS USER EXIT`, běh selže; před vypnutím VM navíc pošle diagnostický příkaz `services` a zahrne aktuální stav služby `flaky` do chyby. Tento dodatečný příkaz se při úspěšném běhu nikdy neposílá.

Jednotlivý profil lze zopakovat samostatně:

```powershell
.\scripts\test-vbox.ps1 -Cpus 1 -Shell
.\scripts\test-vbox.ps1 -Cpus 2 -Shell -Keyboard -LogLevel info -LogOutput serial
.\scripts\test-vbox.ps1 -Cpus 2 -LogLevel debug -LogOutput screen
.\scripts\test-vbox.ps1 -Case kernel
```

Pozitivní profil čeká na skutečný prompt shellu. Kontrola obrazovky porovnává glyphy aktuálního fontu, zachovanou bootovací identitu a pravidla `BOOT.LOG`. Klávesnicová odpověď musí vzniknout až po vstupu a tvořit samostatný celý řádek; pouhé echo nebo změněný pixel nestačí. VBox klávesnicové API dostává PC/XT Set 1 kódy pro Backspace a Enter. Negativní podpisový test vyžaduje `Access Denied` nebo `Security Violation`; samotný timeout není úspěch.

## Etapa 4 — bloková zařízení

AHCI čtení/zápis/flush a studený restart jsou ověřeny na revizi `af9ceca`; podrobnosti viz [plán etapy 4](PLAN_IMPLEMENTACE.md#4-ovladače-a-bloková-zařízení-na-obou-platformách). NVMe se vyvíjí ve větvi `dev/stage4-nvme`. Volitelný `bash scripts/build.sh --nvme-block` sestavuje izolovanou zkoušku NVMe; běžný obraz NVMe řadič neaktivuje. NVMe zatím není akceptováno, nepoužívat k zápisu na fyzické disky.

Pro izolovanou zkoušku je nutný **Oracle VirtualBox Extension Pack 7.1.12** (ověřit `VBoxManage list extpacks`). VDI se vytvoří v novém adresáři běhu; nepředává se existující disk ani fyzické zařízení.

```powershell
git switch dev/stage4-nvme
git pull --ff-only
wsl -d Ubuntu-24.04 -- bash scripts/check-build.sh
wsl -d Ubuntu-24.04 -- bash scripts/build.sh --nvme-block
.\scripts\test-vbox.ps1 -NvmeBlock -Cpus 1
.\scripts\test-vbox.ps1 -NvmeBlock -Cpus 2
```

Oba běhy vyžadují vlastní platný `VM_ACCEPTANCE_JSON`. Nezávislá kontrola porovná PCI config dump obou startů, záznamy NVMe CQ dokončení zápisů a flush, UUID téže VM a VDI, dvě potvrzená vypnutí a celý export disku před a po čtecím startu. Pro etapu 3 nebo běžný boot pak znovu sestavit bez `--nvme-block`.

Pro doplňkové ověření na QEMU (bez VirtualBox Extension Packu) použijte na Ubuntu připravený podepsaný `--nvme-block` build:

```bash
python3 scripts/qemu-nvme.py --cpus 1 --ovmf-code /usr/share/OVMF/OVMF_CODE_4M.secboot.fd --ovmf-vars /usr/share/OVMF/OVMF_VARS_4M.fd
python3 scripts/qemu-nvme.py --cpus 2 --ovmf-code /usr/share/OVMF/OVMF_CODE_4M.secboot.fd --ovmf-vars /usr/share/OVMF/OVMF_VARS_4M.fd
```

NVMe i další časné ovladače mohou použít supervisor-only `paging::map_device_window` pro 64bitové BARy nad 512 GiB bez kolize se soukromým uživatelským adresním prostorem. Samostatná CI matice QEMU používá skutečný emulovaný NVMe řadič, QMP PCI identitu, počitadla čtení/zápisu jeho blokového backendu a skutečný emulátorový trace NVMe Flush a CQ completion (QEMU 8.2.2 NVMe flush neúčtuje do QMP flush_operations). Po dvou nezávislých procesech QEMU ověří všechny bajty nového RAW disku a kernelové záznamy dokončení, při druhém bootu navíc běžné jádro a procesové zkoušky. Úspěch QEMU nenahrazuje VirtualBox ani fyzickou přejímku.

## Jádro, paměť a plánování

Loader předá konečnou mapu paměti, framebuffer a initramfs a korektně opustí UEFI Boot Services. Rustové `no_std` jádro vytvoří vlastní čtyřúrovňové stránkování, alokátor fyzických rámců a GDT/IDT/TSS. Kód je RX, konstanty RO/NX, data RW/NX; nulová stránka a loaderový stack guard nejsou mapované.

Kernelová vlákna, zásobníky pro syscall/trap, AP a IST1 používají **16 KiB** nulované paměti s nezmapovanou stránkou na každé straně. Sdílené supervisor-only/NX mapování je v horní polovině adresního prostoru. Padesát tabulek vzniká před publikací kernelového CR3; samotné stack rámce se přidělují podle potřeby. Neúspěšná alokace vrací všechny rámce, reaping ruší mapování před uvolněním. Boot skutečně přečte oba guardy a ověří page fault; dokladem je `AGENTOS KERNEL STACK GUARD OK`.

ACPI MADT řídí výběr CPU a IRQ routing. AP startují přes INIT/SIPI. Preemptivní round robin má CPU-local fronty a nejvýše 10ms kvantum. LAPIC se nastavuje **jednorázově** na nejbližší termín, který může kvantum zkrátit. Když vše čeká na čas, zbývá nejvýše sekundový watchdog; bez časového čekání se časovač vypne. UART, klávesnice, IPC a ukončení potomka přímo probouzejí příslušné čekající úlohy. Nezávislé počítání uplynulých LAPIC ticků odhaluje zastavený společný procesový čas po přibližně pěti sekundách; nevytváří smyšlený čas.

Bootové zkoušky zachovávají preempci, souběžnou alokaci, vyčerpání paměti, návrat bitmapy a samostatné přibližně 30sekundové měření klidu. Příkaz `idle` navíc měří běžící systém s PID 1, stabilní službou a zablokovaným shellem. Toto druhé měření zachytí periodická probouzení, která by pouhý bootový test neodhalil.

Demand paging z **milníku 3.1 A** [implementačního plánu](PLAN_IMPLEMENTACE.md#31-demand-paging-a-vyvažování-smp) odděluje rezervované virtuální oblasti od přidělených rámců. Loader rezervuje ELF segmenty a čtyřstránkový uživatelský zásobník; fyzické stránky i potřebné podřízené tabulky vznikají až při oprávněném přístupu. Obsah pochází z neměnného initramfs nebo nulování BSS/anonymní paměti. Jedna metadata stránka drží nejvýše 64 nepřekrývajících se oblastí včetně zásobníku. `.bss` je skutečné ELF `NOBITS`, takže velká rezervace nevytváří stejně velký initramfs.

Stejná cesta obsluhuje CPL3 page fault i kernelové čtení/zápis uživatelského bufferu. Neplatný rozsah vrací `EFAULT` (−14), nedostatek rámců `ENOMEM` (−12). Před kopírováním se ověří a připraví celý rozsah. Při OOM mohou již připravené stránky zůstat rezidentní, ale nezmění se přenášené bajty, pozice souboru ani obsah front. Každé nedokončené jednotlivé mapování vrací nové tabulky; ukončení procesu vrátí i jeho metadata a všechny stránky. Konzolový výstup dostane vlastní kopii nejvýše 256 bajtů a UART/GOP obslouží až po uvolnění zámku alokátoru.

Část **3.1 B** zachovává osm slotů v každé CPU frontě a při rozdílu alespoň dvou runnable úloh přesouvá již běžící uložený uživatelský kontext na méně zatížený CPU s volným slotem. Zdroj i cíl mají samostatné zámky, získávané ve vzestupném pořadí APIC ID. Přesouvá se celý vlastněný proces, takže PID, rodič, fd, CR3, COW a zásobník zůstávají stejné. Kernelové bootové úlohy a root před dokončením bootstrap handoffu se nepřesouvají; provozní PID 1 i běžné procesy migrovat mohou.

Společný registr životního cyklu drží jeden fyzický rámec na proces a odděluje rodičovství/reaper od fronty CPU. Vzdálený `kill` zapíše požadavek, který provede vlastník; `wait` převezme status a skutečné uvolnění proběhne až po opuštění adresního prostoru a zásobníku. Assembler potvrzuje přepnutí RSP před zveřejněním odchozí úlohy. Při každém výběru kontextu se znovu načte CR3 s vypnutými PCID/PGE, včetně opakovaného root, aby se nepoužily staré překlady sdílených kernelových stack slotů. Sdílené vícevláknové adresní prostory a aktivní TLB shootdown pro ně zůstávají v etapě 9.

Události IPC, rour, uzavření fd a ukončení procesu vyvolají IPI; cílový CPU sám ověří své čekající procesy. Prázdný AP zůstává v `STI; HLT` a nemá periodický balancovací timer. Pořadí zámků je CPU fronta → společný frame/resource gate → vlastní TTY gate; vzdálený frontový zámek ani IPI se nezískává při držení frame gate. UART/GOP výstup má předem zkopírované bajty a probíhá mimo alokátor.

Procesové lhůty používají jediný **64bit HPET** se společnou boot epochou. HPET komparátory a legacy IRQ jsou vypnuté; plánování nadále používá jednorázový LAPIC. VirtualBox harness nastavuje `--x86-hpet on`, QEMU `hpet=on`. Nepřítomný nebo neplatný 64bit HPET zastaví boot s konkrétní chybou; dostupnost na fyzickém HP musí potvrdit jeho přejímka. Původní TSC měření bootového klidu zůstává oddělené.

Části **3.1 A i B** mají společné úspěšné host a QEMU důkazy pro funkční revizi [`2023723`](https://github.com/filipbcz/AgentOS/commit/2023723cc59bc0b7fd496d45f2acece21cb8e021): 167 Python testů, 218 spuštění Rust testů, čtyři C harnessy a skutečný boot i interaktivní relace na 1/2 CPU. Zahrnut je prokázaný vzdálený `kill`/`wait` a čistý shutdown s přesným návratem rámců. Revize a měřené hodnoty jsou v [plánu](PLAN_IMPLEMENTACE.md#31-demand-paging-a-vyvažování-smp). VirtualBox, fyzické HP a samostatná guest zkouška OOM při demand pagingu zůstávají otevřené; host testy již ověřují řízené OOM a rollback.

## Uživatelské procesy a nativní ABI v2

Programy jsou statické ELF64 `ET_EXEC` pro x86-64, spouštěné v CPL3 z podepsaného initramfs. Každý musí obsahovat právě jednu `PT_NOTE` s vlastníkem `AgentOS\0`, typem 1 a descriptor `{u32 version=2, u32 flags=0}`. Společná [hlavička](user/abi.h) a [linker script](user/user.ld) ji přidávají automaticky. Build i loader odmítají chybějící, duplicitní, nepodporovanou nebo poškozenou note. Staré nativní ABI v1 se záměrně odmítá s `ENOEXEC` před alokací: jeho CPU-local čas nelze tiše změnit na společnou epochu. Všechny programy v initramfs je nutné znovu sestavit proti ABI v2. Neoznačený ELF je vyhrazen budoucímu Linux ABI a nyní také vrací `ENOEXEC`.

Segmenty `PT_LOAD` musí mít nepřekrývající se stránky v rozsahu `[0x8000000000, 0x10000000000)`. Každý proces má soukromé CR3 a uživatelský zásobník s ochrannou stránkou. `fork` sdílí data přes explicitní COW; zápis uživatele i kopírování z jádra oddělí stránku, text zůstává nezapisovatelný. Chybný ukazatel vrací chybu, pád potomka se převezme bez pádu rodiče.

Instrukce `syscall` přijímá číslo v RAX a tři argumenty v RDI/RSI/RDX. RAX vrací výsledek nebo zápornou chybu; RCX a R11 se přepisují. Přesný kontrakt včetně návratů určuje `user/abi.h`.

| Číslo | Volání | Význam |
|---|---|---|
| `0x10001` | `getpid` | Identita volajícího |
| `0x10002` | `write` | COM1, TTY nebo roura; možné dílčí zápisy |
| `0x10003` | `exit` | Ukončení a uzavření všech fd |
| `0x10004` | `spawn` | Nový ELF proces se zděděnými fd |
| `0x10005` | `try_wait` | Převzetí vlastního potomka; běžící vrací −11 |
| `0x10006` | `yield` | Dobrovolné předání CPU |
| `0x10007` | `open` | Soubor initramfs pouze ke čtení |
| `0x10008` | `read` | Soubor, TTY nebo roura |
| `0x10009` | `close` | Uzavření fd |
| `0x1000a` | `pipe` | Dvojice čtecího a zapisujícího fd |
| `0x1000b` | `dup2` | Kopie fd se sdíleným objektem/pozicí |
| `0x1000c` | `ipc_pair` | Obousměrný lokální zprávový kanál |
| `0x1000d` | `ipc_send` | Atomická zpráva; plná schránka uspí odesílatele |
| `0x1000e` | `ipc_recv` | Celá zpráva a kernelová identita odesílatele |
| `0x1000f` | `kill` | Žádost o ukončení přímého potomka; dokončení potvrdí `wait` |
| `0x10010` | `monotonic_ms` | Společné bootové milisekundy HPET |
| `0x10011` | `wait_child_until` | Potomek nebo absolutní deadline |
| `0x10012` | `sleep_until` | Uspání do absolutního deadline |
| `0x10013` | `child_after` | Výčet vlastních, včetně adoptovaných potomků |
| `0x10014` | `fork` | Migrovatelný COW klon; v dítěti návrat 0 |
| `0x10015` | `ipc_try_recv` | Prázdná otevřená schránka vrací −11 |
| `0x10016` | `boot_pause` | Jednorázové předání původního BSP PID 1 |
| `0x10017` | `wait_events_until` | IPC/EOF, child exit nebo deadline bez polling smyčky |
| `0x10018` | `timer_stats` | Čtyři u64: verze 2, společný čas, součet timer IRQ a idle IRQ |
| `0x10019` | `ipc_try_send` | Plná schránka vrací −11 bez uspání a bez odeslání |
| `0x1001a` | `vm_stats` | Osm u64: verze 1, rezervované/rezidentní stránky, tabulky, metadata, demand/COW čítače |
| `0x1001b` | `sched_stats` | Osm u64: verze 1, APIC ID, počet CPU, migrace procesu/celku, vzdálené IPI notifikace, PID, PPID |

`timer_stats(buffer,32,0)` je pouze čtecí diagnostika verze 2; čítače se čtením nenulují. Čas i absolutní lhůty jsou srovnatelné mezi CPU a při migraci se nemění; nejde o UTC. IRQ/idle čítače jsou součtem konzistentních párů z každého CPU, čtených pomocí sekvenčního čítače. `sched_stats(buffer,64,0)` zachytí identitu a stav aktuálního procesu; špatná velikost/flags vrací −22, neplatný buffer −14 a OOM −12. Počet vzdálených probouzení znamená odeslané IPI notifikace, nikoli počet probuzených procesů nebo self-IPI.

`kill` v ABI v2 vrací 0 po přijetí žádosti; vlastník procesu ji může dokončit až na jiném CPU. Návrat 1 znamená již ukončeného potomka. `try_wait` tedy může po přijatém požadavku vrátit −11. Konzumenti používají `wait_child_until` s konečnou novou lhůtou a přebírají skutečný status: 137 při nuceném ukončení, případně původní přirozený exit, který žádost předběhl. Správce služeb zachová PID a fd až do úspěšného převzetí výsledku; timeout se neoznačí za dokončený úklid.

`vm_stats(buffer,64,0)` před snímkem připraví svůj výstupní buffer. Počty zahrnují vlastní PML4, uživatelské tabulky a jednu metadata stránku; společná kernelová mapování ani samostatný lifecycle rámec procesu se nepočítají. Kumulativní počítadla demand alokací, COW kopií a povýšení posledního vlastníka začínají u nového procesu i po `fork` od nuly; aktuální rezervace a rezidentní mapování se dědí. Sdílená stránka se počítá v každém adresním prostoru, takže nejde o celkovou fyzickou spotřebu systému.

### VFS, roury a lokální zprávové IPC

VFS čte kořenový initramfs a vyhodnocuje cesty včetně `.` a `..`. Proces má 32 fd; dvojice/zděděné fd sdílejí vlastnictví a pozici. Roura má kapacitu 1024 bajtů, zachovává pořadí a zápisy do této délky jsou atomické. Prázdná roura či plný buffer uspí proces; poslední uzavření probudí čekající a oznámí EOF nebo `EPIPE`.

IPC má jednu nezávislou schránku v každém směru pro 1–1024 bajtů. Před přijatými daty je 16bajtová `struct ipc_peer`: u64 PID a dvě u32 UID/GID, little-endian. Identitu doplňuje jádro; hodnoty uvnitř zprávy ji nemění. Kapacita a výsledek `ipc_recv` **nezahrnují hlavičku**:

```c
struct {
    struct ipc_peer sender;
    unsigned char data[IPC_MAX_MESSAGE];
} message;
long received = os_call(SYS_IPC_RECV, fd, (long)&message, sizeof(message.data));
```

Krátký nebo neplatný buffer zprávu nespotřebuje. Zařazenou zprávu lze přečíst i po uzavření odesílatele, potom následuje EOF. Chyby zahrnují −9 `EBADF`, −14 `EFAULT`, −32 `EPIPE`, −88 `ENOTSOCK`, −90 `EMSGSIZE` a −11 `EAGAIN` pro neblokující varianty.

## Původní PID 1 a služby

BSP `init` s numerickým **PID 1** po procesových zkouškách jednorázově zaparkuje svůj kontext. Po vytvoření TTY jej jádro obnoví ve stejném adresním prostoru; tento proces pokračuje jako správce služeb. AP bootové testy mají vlastní konečné procesové relace. Po společných bootových zkouškách zůstávají AP dostupné pro provozní plánování; před spuštěním služeb proběhne samostatný migrační scénář. PID 1 převezme i osiřelé potomky a při shutdownu uvolní všechny prostředky své relace.

Podepsaný statický registr obsahuje `core`, `flaky` a `shell`. Graf závislostí se validuje včetně cyklů. Na autentizované READY má služba pět sekund od dokončení spuštění a zápisu START. Worker před READY ověří časovač a IPC. Služba má tři pokusy s rostoucí prodlevou. Rozpočet se obnoví po pěti sekundách souvislého provozu od READY nebo na pokyn správce. Při prvním startu se shell otevře také tehdy, když volitelná služba zůstane pět sekund připravená. Pád závislosti zastaví její následníky a obnoví je až po její připravenosti. STOP volitelné služby zůstává platný i během takové obnovy.

START/RESTART potvrdí úspěch až po vytvoření dítěte, se stavem `starting` a pokusem 1. PID 1 přijímá celou omezenou zprávu a používá neblokující odpověď, takže plná schránka klienta nezastaví ostatní dohled. Stabilní `core` po READY blokuje na IPC. `flaky` je záměrný testovací worker se stavem 42 po 100 ms. Po jeho počátečních třech pádech se zpřístupní shell.

## TTY, shell, PS/2 a GOP

COM1 pracuje na 115200 baudů, 8N1; IRQ4 vede přes MADT/I/O APIC na BSP. PS/2 první port 8042 zapíná překlad Set 2 → Set 1 a používá IRQ1. Inicializace má konečné timeouty a obnovu konfigurace; při její chybě zůstává dostupný COM1. Obě vstupní cesty používají společnou kanonickou frontu. TTY vykresluje ASCII na GOP a zachovává skutečnou bootovací identitu v horním pásu 88 pixelů; zbytek obrazovky scrolluje.

| Příkaz | Chování |
|---|---|
| `help`, `pid` | Nápověda a identita shellu |
| `echo TEXT` | Výstup textu |
| `cat PATH` | Čtení z initramfs a uzavření fd i při chybě |
| `services` | Autentizovaný stav registru a počty pokusů |
| `service start\|stop\|restart core\|flaky` | Správní operace se zachováním závislostí |
| `idle` | Pětisekundový spánek a rozdíl timer/idle IRQ čítačů |
| `exit` | Řádné ukončení shellu, služeb a PID 1; kontrola bitmapy |

Řádek má nejvýše 255 znaků a fronta čtyři dokončené záznamy. CR/LF odešle řádek, CRLF je jeden Enter, Backspace/Delete opravuje, Tab vloží mezeru, Ctrl-D na prázdném řádku vrátí jednorázové EOF. Přetečení či poškozený vstup vrátí `EOVERFLOW`; zbytek řádku se zahodí, aby se nevykonal useknutý příkaz. `EFAULT` zachová platná data pro další čtení. TTY upravuje LF na CRLF bez zdvojení existujícího CR.

Současný shell nemá přihlášení, řízení úloh, uvozovky, syntaxi rour ani trvalé přesměrování. Úplný celek C se odemčením, přihlášením a trvalým zápisem podle plánu přijde v etapě 7. Profil má jedno vlákno na proces, osm slotů úloh na CPU, IPC mezi CPU a bootovací UID/GID 1000. Bloková zařízení, účty, Linux ABI a A/B aktualizace mají vlastní další etapy. PS/2 používá US ASCII rozložení; USB HID patří do etapy ovladačů.

## Logování

EFI loader čte `EFI/BOOT/BOOT.LOG` jako jeden řádek bez BOM: `<quiet|info|debug> [serial|screen|both|none]`. Chybějící nebo neplatný soubor volí `info both`. Příklad:

```text
debug serial
```

Testovací skript nastavuje soubor pomocí `-LogLevel` a `-LogOutput`. Strukturované `[ERROR]`, `[INFO]` a `[DEBUG]` události mají nezávislý filtr obou výstupů. Omezená interní historie se uchovává i při vypnutém výstupu; runtime logger má SMP/IRQ ochranu. Přímé akceptační markery zůstávají na COM1 bez ohledu na filtr a uživatelská TTY zůstává funkční. `none` proto neznamená úplně tichý sériový port.

## Ověření v CI a reprodukce důkazů

`Host checks` spouští skutečné Rust/C host testy, negativní testy ověřovačů, kernel/user linky a PowerShell parser. Syntetické logy ověřují validátory a nikdy se nevydávají za výstup hostovaného jádra.

`QEMU Secure Boot smoke (supplementary)` sestaví podepsaný obraz připnutým toolchainem a bootuje OVMF/QEMU TCG s 1 i 2 CPU. Každý job provede bootový běh a samostatnou rozšířenou relaci: UART příkazy, START/STOP/RESTART, tři skutečné ukončené workery, provozní idle, QMP vstup do emulované PS/2 klávesnice, přesné GOP glyphy a čisté ukončení PID 1. Artefakty `qemu-secureboot-1cpu` a `qemu-secureboot-2cpu` uchovávají obraz, build provenance, logy, snímky a `smoke.json`.

Nové bootové běhy na obou CPU konfiguracích povinně ověřují také `user/demand.c`: skutečnou 16MiB BSS rezervaci s malým počtem rezidentních stránek, vzdálené první přístupy, lazy syscall buffery, COW i dosud nepřítomné oblasti při `fork` a samostatné chyby guard/NX/RO. Log lze znovu prověřit příkazem `python scripts/verify-demand-paging.py --log CESTA_K_COM1_LOG --cpus 1` (nebo `2`). Stejný ověřovač používá aktuální `test-vbox.ps1`; stávající `accept-stage3.ps1` zároveň opakuje celou regresní matici základního profilu.

Přesné dokončené běhy a jejich rozsah jsou evidovány v [etapě 3 plánu](PLAN_IMPLEMENTACE.md#3-izolované-procesy-vfs-ipc-a-terminál). Po jakékoli změně kódu či testovacího scénáře je nutný nový výsledek odpovídající revize. QEMU nepřepisuje stav povinné matice VirtualBoxu.

Migrační zkouška `user/migration.c` vytváří čtyři skutečné potomky a řízenými probuzeními vytváří nerovnoměrnou runnable zátěž. Vyžaduje pokračování již běžícího PID na jiném CPU, zachování práce/času, COW a lazy stránek, fd offsetu, pipe/IPC identity, absolutní lhůty a převzetí potomků. Na 1 CPU provede stejné funkční operace bez přesunu. Nové sériové QEMU/VBox běhy vyžadují `python scripts/verify-migration.py --log CESTA_K_COM1_LOG --cpus 1` (nebo `2`); historické důkazy bez migračního intervalu část B nepotvrzují.
