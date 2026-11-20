# AgentOS — plán implementace prvního stabilního vydání

Rozsah a závazné podmínky převzetí určuje [technické zadání AgentOS](ZADANI.md). Čísla etap udávají doporučené pořadí. U každé etapy je uvedena její skutečná závislost, aby se například vývoj sítě mohl rozběhnout souběžně s úložištěm. Průběžný stav implementace a dostupné důkazy jsou uvedeny u jednotlivých etap. Historické výsledky platí pro uvedené obrazy; automaticky nepotvrzují pozdější změny.

## Závazná pravidla implementace a předávání

Tato pravidla platí pro všechny etapy, změny zdrojového kódu, testy a předání práce. Jsou závazná vedle `ZADANI.md`; technické zadání a akceptační kritéria nelze obejít zjednodušením implementace.

1. **Jediný řídicí dokument.** `PLAN_IMPLEMENTACE.md` je autoritativní plán implementace. Postupovat podle jeho etap, skutečných závislostí a kritérií převzetí. Doplňkové dokumenty mohou obsahovat technické podrobnosti, ale nenahrazují stav a rozhodnutí zde.
2. **Průběžný zápis přímo do plánu.** Každá podstatná změna se zaznamená u příslušné etapy: dotčené soubory a rozhraní, rozsah funkce, důvody rozhodnutí, provedené testy, konkrétní výsledky a odkazy na důkazy, známá omezení, rizika a další krok. Starší neplatné informace opravit nebo výslovně označit jako historické; nevytvářet rozporné paralelní přehledy.
3. **Žádné polovičaté funkce vydávané za hotové.** Návrh musí zahrnovat běžný provoz, selhání, hraniční stavy, obnovu a uvolňování prostředků. Částečný přírůstek je přípustný pouze jako výslovně rozpracovaná součást větší funkce, s vymezením toho, co chybí; nesmí se označit za dokončenou nebo akceptovanou.
4. **Dlouhodobě udržitelná architektura.** Před změnou zhodnotit modularitu, jasná a stabilní rozhraní, budoucí rozšiřování, kompatibilitu ABI a formátů, izolaci, bezpečnost, vlastnictví paměti a prostředků, synchronizaci, více CPU a chování v přerušeních. Nepřidávat skryté globální závislosti ani provizorní řešení bez zaznamenaného migračního plánu.
5. **Testy jsou součástí dodávky.** Připravit automatické jednotkové, integrační a regresní testy odpovídající riziku změny, včetně chybných vstupů, limitů a souběhu. Ověřit, že se nezhoršily dříve funkční subsystémy. Pouhé napsání testu, úspěšný překlad nebo zelené CI samy neprokazují běh ve VM či na fyzickém zařízení.
6. **Důkaz před označením „hotovo“.** Rozlišovat `navrženo`, `implementováno`, `host-test ověřeno`, `CI ověřeno`, `VM ověřeno`, `fyzicky ověřeno` a `akceptováno`. Uvést commit SHA, verzi nástrojů, konfiguraci, hash obrazu a odkazy na logy/protokoly tam, kde je to relevantní. Neprovedené kontroly uvést jako neověřené, nikoliv jako úspěšné.
7. **Bezpečné změny a stabilní větev.** Vyvíjet na určené pracovní větvi, zachovat stabilitu `main`, neporušovat existující API a akceptované funkce. Změny ABI nebo chování vyžadují zdůvodnění, aktualizaci konzumentů, testy a explicitní evidenci v plánu.
8. **Předatelnost.** Po každé pracovní dávce musí další vývojář pouze ze zdrojů a tohoto plánu zjistit, co je hotové, co se změnilo, jak to reprodukovat, co zůstává neověřené a jaký je následující krok. Nepředpokládat znalost předchozí konverzace.
9. **Dokončovat ucelené funkce.** Upřednostnit dokončení a ověření jedné funkční oblasti před paralelním otevíráním dalších nedokončených částí. Pokud dostupné prostředí neumožňuje přejímku, připravit úplné testy a přesný postup ověření, ale ponechat stav otevřený.

## Jak budeme ověřovat postup

Vývoj může pokračovat i v prostředí bez VirtualBoxu. U změn se zvlášť evidují provedené kontroly zdrojů, sestavení a hostitelské testy; běh jádra a integrační akceptace zůstávají neověřené do skutečného spuštění ve VM. Fyzické zkoušky HP v následujících etapách jsou odložené do budoucí fyzické přejímky a neblokují pokračování vývoje.

- Automatické integrační běhy používají VirtualBox 7.1.12, EFI64, 2 vCPU a 256 MiB RAM. Funkční běhy jádra se opakují také s 1 vCPU. Hostitel ovládá konzoli přes COM1, kontroluje časový limit, výstupy programu a výsledný stav po restartu.
- Fyzické zkoušky se provádějí na HP ProBook 460 G11. Podepsané USB umožní časný boot a ověření ovladačů. Pro instalaci a zápisy na interní NVMe se pracovní disk s Windows vyjme a eviduje se identita vyhrazeného disku. Výsledek z VM a výsledek z HP se zaznamenávají zvlášť.
- Každý protokol obsahuje verzi zdrojů, hash obrazu a testovacích vstupů, konfiguraci, očekávaný a naměřený výsledek. Unit testy pokryjí algoritmy, integrace skutečnou cestu od uživatelské operace až k pozorovatelnému výsledku. Po změně se zopakují také zkoušky již dokončených částí, které změna ovlivňuje.

## Etapy

### 1. Sestavení, zkušební prostředí a první podepsaný start

**Výsledek.** Připnout verze nástrojů pro Rust `no_std`, sestavit ELF jádra a initramfs, vložit je do obrazu EFI a podepsat odděleným testovacím klíčem. Připravit po jednom příkazu pro sestavení a spuštění VM. Implementovat předání bootovacích údajů, korektní `ExitBootServices`, GOP a diagnostiku přes COM1. Na HP časně prověřit možnosti přidání certifikátu při zachování důvěry a startu Windows, dostupnost zdroje entropie a dokumentaci konkrétní revize síťového čipu.

**Převzetí.** Dvě čistá sestavení dají shodný nepodepsaný EFI. Na VM firmware přijme podepsaný obraz a jádro po ukončení Boot Services vypíše identifikaci sestavení na displej i COM1. Změna bajtu zvlášť v loaderu, jádře a initramfs znemožní start daného obrazu. Totéž ověřit v rozsahu fyzické zkoušky na HP z USB. Výstupem je první protokol celku A.

**Ověření ve VirtualBoxu 7.1.12.** Jádro v Rustu po ukončení Boot Services vypsalo `AGENTOS KERNEL OK STAGE 1` na framebuffer i COM1 při 256 MiB a samostatných bězích s 1 i 2 vCPU. Firmware odmítl všechny tři modifikace sekcí hlášením `Access Denied`. Čistá sestavení před podpisem dala SHA-256 `e1321987fa7a15111024f6e32f89afe4837e8e97e8205e466f168cca3b30f7d2`. [Snímek z VM](build/runs/AgentOS-signed-2cf3a34216/kernel-display.png) a [sériový log](build/runs/AgentOS-signed-2cf3a34216/com1.log). Postup opakování je v [README](README.md). Přijetí celku A na fyzickém HP dosud čeká na zkoušku.

### 2. Paměť, výjimky, časovače a více procesorů

**První ověřená část ve VM.** Po převzetí konečné UEFI mapy funguje na bootovacím procesoru přidělení dvou různých fyzických stránek, kontrola zápisu a čtení, uvolnění a opětovné přidělení. Podepsaný EFI měl SHA-256 `73967783072438c957f3e8ece690fc3a4dd527d454c9bc6492926e23ab5d83d7`. COM1 i framebuffer prošly na 256 MiB v konfiguracích [1 vCPU](build/runs/AgentOS-signed-e71f2ed0e4/com1.log) a [2 vCPU](build/runs/AgentOS-signed-97f389c7f9/com1.log). První pokus s 2 vCPU vypršel před startem jádra, opakovaný start stejného obrazu uspěl.

**Vlastní stránkování a výjimky ověřeny ve VM.** Stejný podepsaný EFI (SHA-256 `a181e8b7f9bb6b73903077c39fd0db9e8c0180546cb19ee63bd2c448795c99c1`) nabootoval s 256 MiB v konfiguracích [1 vCPU](build/runs/AgentOS-signed-db4dc65dd8/com1.log) a [2 vCPU](build/runs/AgentOS-signed-dd58f05c08/com1.log). V obou případech bootovací procesor přečetl po přepnutí vlastní CR3 `0x105000`. Vlastní IDT zachytila breakpoint a stránkové výjimky při přístupu k nulové adrese, ochranné stránce zásobníku, zápisu do konstanty a pokusu o spuštění dat. Po návratu ze všech výjimek prošel test alokátoru i kontrola textu na displeji.

**Spuštění dalších procesorů a lokální časovač ověřeny ve VM.** Podepsaný obraz se SHA-256 `5febdbab7b90f2b3ee38709e3a10db9576201afe29c6dad4c93e928db4e0bd5b` prošel ve VirtualBoxu 7.1.12 s EFI Secure Boot a 256 MiB RAM. V profilu [1 vCPU](build/runs/AgentOS-signed-8a87775904/com1.log) běžela úloha na APIC ID 0. V profilu [2 vCPU](build/runs/AgentOS-signed-d51a1a3ec3/com1.log) ji vykonaly procesory s APIC ID 0 a 1. Každá instance potvrdila tři návraty z HLT po vlastním jednorázovém přerušení lokálního časovače. Oba běhy prošly také kontrolou výjimek, alokátoru a textu na displeji.

**Preempce a souběžná alokace ověřeny ve VM.** Podepsaný EFI se SHA-256 `a40a212447039d768ec64fbb2133c0abfd8115015ef6df307b7fc6d923f266c4` prošel ve VirtualBoxu 7.1.12 s EFI Secure Boot a 256 MiB RAM. Na [1 vCPU](build/runs/AgentOS-signed-11b15dca74/com1.log) vystřídal časovač dvě běžící vlákna celkem 40krát, na [2 vCPU](build/runs/AgentOS-signed-81c2a0f69a/com1.log) čtyři vlákna celkem 88krát. Každé dokončilo 4 096 dvojic přidělení a uvolnění. V 16 synchronizovaných dávkách držela vlákna současně 16, respektive 32 různě označených stránek. Po zátěži se v obou bězích přesně shodovala bitmapa i počet volných stránek s výchozím stavem. Při prvním startu finálního obrazu se 2 vCPU vypršel časový limit ve firmwaru, ještě před výstupem jádra. Opakovaný start prošel včetně kontroly displeje.

**Vyčerpání fyzických stránek a režie v klidu ověřeny ve VM.** Stejný podepsaný obraz se SHA-256 `6f1a97b4850c7e0bec5b9e71a3ef059c74e02b7d1bb01f5ea4c2b6f52d368897` prošel ve VirtualBoxu 7.1.12 s EFI Secure Boot a 256 MiB RAM. Alokátor vydal všech 53 369 volných stránek při [1 vCPU](build/runs/AgentOS-signed-98dbbd7a39/com1.log) a 53 346 při [2 vCPU](build/runs/AgentOS-signed-15b3cb4e39/com1.log). Při nulové rezervě každý dostupný procesor ověřil odmítnutí běžné i nulované alokace. Po uvolnění jediné stránky prošlo vrácení částečné alokace a kontrola celé znovu přidělené nulované stránky. Po návratu všech stránek se shodovala původní bitmapa i počty a prošel dvoustránkový test.

| VM | APIC ID | Interval hostovaného jádra | Probuzení z HLT | Aktivní čas včetně měření | Podíl intervalu |
|---|---:|---:|---:|---:|---:|
| [1 vCPU](build/runs/AgentOS-signed-98dbbd7a39/idle.csv) | 0 | 29,905 s | 1 | 213 µs | 0,00071 % |
| [2 vCPU](build/runs/AgentOS-signed-15b3cb4e39/idle.csv) | 0 | 30,000 s | 2 | 433 µs | 0,00144 % |
| 2 vCPU | 1 | 30,000 s | 2 | 422 µs | 0,00141 % |

Každý řádek odpovídá jednomu měřicímu oknu. Stopky hostitele zaznamenaly 29,980 s a 29,948 s. Všechna probuzení vyvolal jednorázový měřicí časovač. V profilu se dvěma vCPU na obou procesorech poprvé doběhl před termínem a jádro jej nastavilo na zbývající dobu. Měření používá frekvence zveřejněné profilem VirtualBox Minimal. Předchozí kalibrace podle ACPI PM ve dvouprocesorovém běhu nedodržela délku okna a do výsledků se nezapočítala. Fyzická přejímka zůstává odložená.

**Navazuje na 1.** Zavést alokaci stránek, stránkování, ochrany paměti, ACPI/APIC, obsluhu výjimek a přerušení. Nad nimi spustit preemptivní plánovač, synchronizaci, monotónní čas a čekání bez trvalého pollingu.

**Převzetí.** Test na 1 a 2 vCPU a následně na HP spustí identifikovatelnou úlohu na každém dostupném CPU. Zátěž ověří souběžnou alokaci a uvolňování stránek, preempci a probuzení časovačem. Ověří se ochranné stránky, NX a chování při vyčerpání paměti. V klidu se změří probuzení procesorů a režie jádra. Tím se uzavře celek B.

### 3. Izolované procesy, VFS, IPC a terminál

**Izolace procesů a první nativní ABI ověřeny ve VM.** Podepsaný obraz se SHA-256 `237fd7d17e608b40dd1616af57455d14e0ebc41b07f1c9648bb8843130ee6e5a` načetl ze svého initramfs statický ELF `init`, který přes `spawn` spustil ELF `fault`. Oba běžely v CPL3 s vlastními tabulkami stránek. Na [1 vCPU](build/runs/AgentOS-signed-e481021595/com1.log) spadl PID 2, rodič PID 1 převzal stav 270 a skončil s kódem 0. Na [2 vCPU](build/runs/AgentOS-signed-ace69882ea/com1.log) proběhl scénář postupně na APIC ID 0 (PID 1 a 2) a APIC ID 1 (PID 3 a 4). V každé dvojici měly procesy odlišné CR3. Čtení chráněné stránky jádra vyvolalo v potomkovi výjimku 14 s chybovým kódem 5. Rodič po pádu ověřil svůj původní obsah zásobníku na stejné virtuální adrese, vypsal zprávu na COM1 a úspěšně skončil. Jádro ověřilo shodu bitmapy volných stránek a pokračovalo v běhu. Rodič také ověřil chybové návraty pro nepřístupné buffery a neznámé číslo systémového volání. Rozhraní a omezení prvního profilu popisuje [nativní ABI v1](README.md#uživatelské-procesy-a-nativní-abi-v1).

**VFS, souborové popisovače a roury ověřeny ve VM.** Podepsaný EFI se SHA-256 `c1dd9800cac87ecf26d0ab0ec884c4eccf35a99d60f0cc1d1ef5b7258a49f2b7` spustil dva izolované procesy. Rodič otevřel přes VFS soubor `/data/transfer.bin` v initramfs a odeslal jej rourou. Příjemce porovnal všech 8 193 bajtů s očekávaným obsahem, ověřil EOF a ohlásil FNV-1a `1490a95f`. Na [1 vCPU](build/runs/AgentOS-signed-26567f4312/com1.log) proběhl přenos z PID 1 do PID 3. Na [2 vCPU](build/runs/AgentOS-signed-1b13556e1d/com1.log) proběhl postupně na CPU 0 z PID 1 do PID 3 a na CPU 1 z PID 4 do PID 6. Po každé dvojici jádro ověřilo návrat volných stránek do výchozího stavu.

**Lokální IPC implementováno; ověření ve VM čeká.** Nativní ABI obsahuje vytvoření páru, odeslání a příjem zprávy s kernelovou identitou PID/UID/GID. Kanál zachovává zprávy o 1–1 024 bajtech, po jedné v každém směru, s čekáním na data či místo a referencemi přes `dup2` a `spawn`. Uživatelský scénář zahrnuje hraniční délky a chybné buffery, obousměrný přenos, zachování zprávy při neúspěšném příjmu, duplikaci, uzavření a výměnu výzvy a odpovědi s oddělenou službou. Hostitelská kontrola nyní ověřuje oba IPC záznamy, vzájemné identity a tři úspěšná ukončení na CPU; původní kontrola očekávala jen dvě a nový scénář by odmítla. Rozhraní a současná omezení popisuje [README](README.md#lokální-zprávové-ipc).

**Kontroly při přípravě IPC změny bez VM.** Prošlo 16 regresních testů kontrolního programu nad syntetickými logy. Programy `init`, `fault`, `receiver` a `service` se přeložily a slinkovaly s GCC 14.2 a hostitelským linkerem při zachování freestanding přepínačů a chyb při varováních. Tento kontrolní překlad nenahrazuje sestavení s verzemi ze `scripts/toolchain.lock`. Úplný EFI obraz, spuštění PowerShell obálky a běhy VirtualBoxu s 1 a 2 vCPU zatím nebyly pro tuto změnu provedeny. Etapa 3 tím není převzatá; navazují TTY, vstup, shell a správa služeb, stejně jako zbývající požadavky izolace procesů.

**První sériový TTY a shell připraveny; ověření ve VM čeká.** Vstup COM1 je směrovaný přes I/O APIC podle MADT na BSP. Řádková vrstva má omezenou frontu, opravu Backspace/Delete, ochranu proti provedení zkráceného příkazu po přetečení a kopírování do uživatelského prostoru před spotřebováním dat. Čtenář se uspí; plánovací časovač se při absenci spustitelné práce vypne a UART ho může probudit. Po původních bootovacích a klidových zkouškách se v CPL3 spustí ELF `shell` s příkazy `help`, `pid`, `echo`, `cat` a `exit`. Po ukončení se kontroluje návrat bitmapy volných stránek. Přepínač `test-vbox.ps1 -Shell` připravuje skutečnou výměnu příkazů přes obousměrný COM1 a ověřuje celý zachycený výstup. Profil je zatím sériový, bez přihlášení, klávesnice a vykreslování TTY na displej; správa služeb PID 1 ani celá etapa 3 nejsou hotové. Podrobná omezení a postup jsou v [README](README.md#první-sériový-tty-a-shell).

**Kontroly TTY mimo VM.** Hostitelské testy spouštějí skutečný C shell s náhradním syscall rozhraním, skutečnou Rustovou řádkovou vrstvu a TTY s náhradními porty a kontrolní programy nad syntetickými logy. `scripts/check-build.sh` k nim přidává překlad a linkování skutečného jádra i uživatelských ELF. GitHub workflow `Host checks` zpřístupňuje tuto kontrolu také mimo lokální vývojové prostředí. Žádný takový výsledek sám neprokazuje správné doručení přerušení nebo běh ve VirtualBoxu; oba integrační běhy s 1 a 2 vCPU zůstávají povinným dalším ověřením.

**PS/2 klávesnice – implementace ve vývojové větvi, VM neověřeno (2026-11-20).** `kernel/keyboard.rs` obsahuje dekodér Set 1, `kernel/ps2.rs` experimentální ovladač prvního portu 8042 s omezeným čekáním, nastavením překladu Set 2 → Set 1 a obnovou konfigurace. `kernel/acpi.rs`, `kernel/ioapic.rs`, `kernel/exceptions.rs`, `kernel/traps.S`, `kernel/smp.rs` a `kernel/tty.rs` zavádějí směrování IRQ1 přes MADT/I/O APIC, vektor 0xe2 a vstup do společné kanonické TTY. Při selhání inicializace zůstává COM1. Přidány hostitelské testy dekodéru a kombinovaného vstupu. **Důkaz funkčního IRQ1, připojené klávesnice ani zadávání příkazů ve VirtualBoxu zatím neexistuje.** Starší odstavec o chybějícím hardwarovém zapojení tímto záznamem nahrazen.

**Bootovací logování – implementace, VM neověřeno (2026-11-20).** EFI loader čte `EFI/BOOT/BOOT.LOG`: `quiet|info|debug` a volitelný cíl `serial|screen|both|none`; výchozí `info both`. `kernel/log_policy.rs` odděluje testovatelnou filtraci a prefixy, `kernel/main.rs` směruje bootovací události na COM1 a/nebo framebuffer. `scripts/disk.sh` a `scripts/test-vbox.ps1` podporují příslušné volby. Přímé kritické a akceptační sériové výpisy zůstávají mimo filtr; `none` proto není úplné vypnutí COM1. Pět jednotkových testů pravidel je zahrnuto do `scripts/check-build.sh`. **Nejde o hotový centrální logger ani framebufferový shell.**

**Historie logů – datová struktura implementována, runtime nezapojen (2026-11-20).** `kernel/log_ring.rs` má pevnou kapacitu 32 záznamů, nejvýše 96 bajtů zprávy, sekvenci, volajícím dodaný monotónní čas, CPU ID, úroveň a indikaci zkrácení; čtení hlásí přepsané položky. `scripts/tests/log-ring-host.rs` a `scripts/check-build.sh` obsahují šest testů. Struktura je **single-owner, není bezpečná pro sdílení mezi CPU ani reentrantní IRQ**, není vytvořena globální instance a žádný běžící subsystém do ní dosud nezapisuje. Následuje návrh per-CPU vlastnictví a neblokujícího výstupu.

**Průběžné ověření a stav převzetí (2026-11-20).** Změny jsou na větvi `dev/stage3-ipc-validation` v PR #1. Úspěch posledního CI je nutné ověřit proti konkrétnímu SHA; nový kód nebyl lokálně spuštěn ve VirtualBoxu. Pro hostitelské ověření spustit `bash scripts/check-build.sh`, pro integrační testy `.\\scripts\\test-vbox.ps1 -Cpus 1 -Shell -LogLevel debug -LogOutput serial` a stejný test s `-Cpus 2`. Uložit SHA podepsaného obrazu, COM1 log, obrazovku a výsledky příkazů. **Etapa 3 není hotová ani převzatá.**

**Pořadí dalších prací podle etapy 3:** (1) poslední CI a integrační COM1 shell s 1/2 vCPU; (2) ověření PS/2 IRQ1 a filtrů BOOT.LOG; (3) bezpečné runtime logování s per-CPU buffery a časovými značkami; (4) interaktivní TTY na framebufferu; (5) správce služeb PID 1 včetně restartovacího limitu; (6) zbývající přejímací scénáře. Nezavádět nové etapy mimo tento plán bez dokončení požadovaných závislostí.

**Audit souladu s pravidly implementace (2026-11-20; PR #1, revize `aeb7cd684af2382426765b50b5665cbf369d1fb3`).** Kontrola zdrojů a diffu, nikoli potvrzení funkčnosti ve VM. **Výsledek: částečný soulad; etapa 3 není připravena k převzetí.** Zjištění a nápravná kritéria:

- **Nedokončená integrace logování (pravidla 3, 4, 9):** `kernel/log_ring.rs` je testovatelný single-owner buffer, ale `kernel/main.rs` jej pouze deklaruje jako modul; žádný runtime zápis ani čtení. Náprava: definovat vlastnictví pro více CPU, IRQ-safe zápis, ztráty a pořadí událostí, časový zdroj a oddělený neblokující transport; prokázat testy souběhu, přetečení a výpadku výstupu. Do té doby neoznačovat za hotový logger.
- **PS/2 rollback (pravidla 3, 4, 5):** `kernel/ps2.rs::enable` vypíná první port příkazem `0xad`, ale při selhání následujícího `0x20` nebo `recv()` vrací `None` bez obnovení předchozího stavu. Náprava: navrhnout explicitní stavy inicializace a rollback pro všechny dosažitelné chyby, otestovat timeouty, NACK, chybné status bity a následné obnovení COM1; teprve poté VM test IRQ1.
- **Nedostatečné integrační důkazy (pravidla 5, 6):** testy PS/2 dekodéru a UART harnessu nenahrazují test skutečného řadiče a IRQ1. Poslední CI a VM 1/2 vCPU nejsou doloženy k této revizi. Náprava: uložit SHA commitu, podepsaného obrazu, parametry a COM1 logy; ověřit klávesnici, sériový vstup, souběh a chybové scénáře.
- **Nekonzistentní směrování logů (pravidla 3, 4):** `BootLog::event` respektuje `BOOT.LOG`, ale přímé `serial(...)` v `kernel/main.rs` jej obcházejí. Jde o historické akceptační/diagnostické markery, které nelze bez návrhu odstranit. Náprava: rozdělit povinné boot/fatal markery od konfigurovatelných událostí, dokumentovat smlouvu pro `none`, přidat testy obou režimů.
- **Neúplný framebufferový TTY (pravidla 3, 9):** `glyph` v `kernel/main.rs` pokrývá jen část znaků a `draw` neimplementuje kurzor, posun, přetečení ani shellový výstup. Náprava: samostatný terminálový renderer, úplná definovaná znaková sada, wrapping, scrolling, hranice framebufferu, chybové testy a integrace s TTY.
- **Evidence a předání (pravidla 1, 2, 8):** tato revize zapisuje nálezy přímo do autoritativního plánu; doplňkové `docs/*` jsou pouze technické podklady. Při následující implementaci aktualizovat tento oddíl a odstranit zastaralé výroky. Nezaměňovat připravený test za úspěšný běh.

**Náprava zahájena – PS/2 rollback (2026-11-20).** V `kernel/ps2.rs` jsou nyní chybové větve při neúspěšném příkazu pro čtení konfigurace a při chybějící odpovědi doplněny o pokus znovu zapnout první port (`0xae`). Přidán hostitelský simulátor skutečného `kernel/ps2.rs` (`scripts/tests/ps2-host.rs`) se třemi scénáři: úspěšné zapnutí/obnova, chybějící odpověď a NACK zařízení. Test je zařazen do `scripts/check-build.sh`. **Omezení:** při selhání samotného I/O příkazu `0xae` nelze garantovat obnovu; před přečtením konfigurace není znám původní stav prvního portu, proto tento fallback může změnit stav původně vypnutého portu. Simulátor neověřuje časování, IRQ1 ani fyzické chování 8042. **Host test a CI nejsou tímto zápisem prohlášeny za úspěšné; PS/2 auditní nález zůstává otevřený do úplného návrhu stavů a testů.** Tento dílčí krok se nesmí vydávat za dokončenou funkci.

**Oprava PS/2 zachování stavu (2026-11-20, navazuje na audit).** `kernel/ps2.rs::enable` nyní čte původní konfigurační bajt 8042 **před** vypnutím prvního portu, aby nedošlo ke ztrátě informace o jeho původním stavu (bit 4). Pokud toto čtení selže, žádná změna portu se neprovede. Po pozdějším selhání se obnovuje uložený konfigurační bajt; `restore` nově vrací `bool` pro rozlišení úspěchu a selhání. Simulátor v `scripts/tests/ps2-host.rs` modeluje změny bitu 4 a zahrnuje pět testů včetně původně vypnutého portu a NACK při původně zapnutém portu. **Neověřeno:** skutečný běh hostitelských testů a VM, příkazy 8042 s trvalým I/O selháním, obnovení režimu scan-code klávesnice (předchozí set není uložen), neúspěšný rollback je volajícím zatím ignorován. Proto zůstává PS/2 nález otevřený. Následuje kontrola CI, doplnění obnovy stavu zařízení a testy poruch příkazů; potom VM IRQ1.

**Pokračování kontroly PS/2 (2026-11-20).** `kernel/tty.rs::disable` nově kontroluje návratovou hodnotu `ps2::restore` a při selhání zapisuje explicitní diagnostiku `AGENTOS PS2 RESTORE FAILED` na COM1; chyba tedy nezůstane zcela skrytá. Nejde o automatickou obnovu nefunkčního řadiče a nezaručuje to návrat původního scan-code setu. **Stav:** změna implementována; build, host testy, VM a skutečná obnova hardwaru nejsou ověřeny. Nález je stále otevřený. Kompletní odstranění auditních nálezů dále vyžaduje samostatně otestovanou obnovu PS/2 zařízení, SMP/IRQ-safe runtime logger, plnohodnotný framebufferový TTY a integrační přejímku.

**Pořadí nápravy:** nejdříve opravit PS/2 rollback a doplnit simulované chybové testy, poté ověřit host build/CI; následně integrovat runtime logger bezpečný pro SMP a IRQ, dokončit framebuffer TTY a provést VM integrační testy. Bez jejich výsledků ponechat etapu 3 otevřenou.

**Navazuje na 2.** Implementovat uživatelský režim, nativní syscall ABI, loader ELF, adresní prostory včetně copy-on-write, popisovače a identitu procesů. Z initramfs spustit PID 1. Přidat VFS, roury, lokální IPC s identitou volajícího, TTY, shell, PS/2 vstup a správu služeb. Textový shell pracuje přes TTY, správní operace přes služby podle § 3.

**Převzetí.** Uživatelský program přečte soubor z initramfs a pošle výsledek rourou. Chybný uživatelský ukazatel a pád samostatného procesu neukončí jádro ani druhý proces. PID 1 převezme ukončeného potomka a při opakovaném pádu služby omezí restartování. Interaktivní vstup a výstup se prověří přes COM1 a klávesnici s displejem. Úplná zkouška celku C včetně odemčení, přihlášení a trvalého přesměrování proběhne v etapě 7.

### 4. Ovladače a bloková zařízení na obou platformách

**Potřebuje 2; uživatelské zkoušky využijí 3.** Zprovoznit PCI/PCIe, přerušení MSI/MSI-X, DMA mapování a blokové rozhraní s dokončením a vyprázdněním zápisů. Podle pořadí v § 5.1 připojit AHCI a NVMe, transport VirtIO-net, xHCI, USB HID, USB Mass Storage a kabelový Realtek. Síťové ovladače zde stačí dovést k odeslání a příjmu rámce.

**Převzetí.** Na VDI, vyhrazeném USB a vyhrazeném NVMe zapsat vzorek do předem určené testovací oblasti, vynutit dokončení zápisu a po restartu porovnat obsah. Timeout či odpojení USB musí ukončit čekání, DMA buffery se smějí uvolnit až po zastavení přenosu. Na HP ověřit vestavěnou i USB klávesnici a přenos známého ethernetového rámce.

### 5. Generátor náhodnosti a šifrovaná bloková vrstva

**Navazuje na 1, 3 a blokovou část 4.** Ověřit skutečný zdroj entropie v obou konfiguracích a inicializovat systémový generátor. Implementovat podporovaný profil LUKS2, Argon2id, dva klíčové sloty, výzvu z initramfs, rotaci údajů a zálohu hlavičky. Použít prověřená kryptografická primitiva a zveřejněné testovací vektory.

**Převzetí.** AgentOS a referenční Linux odemknou stejný testovací svazek a na stejné blokové adrese přečtou shodná data. Ověřit normální frázi, diskový obnovovací kód, zamítnutí nesprávného údaje, přerušení rotace a obnovu poškozené hlavičky na kopii VDI. Při nedostupnosti všech zdrojů entropie zůstane cílový obraz bajtově shodný. Změřit špičku paměti a dobu odvození klíče v referenční VM.

### 6. Trvalá data, ext4 a zotavení po pádu

**Navazuje na 3–5.** Stanovit přesný podporovaný profil ext4/JBD2, napojit jej na VFS a připojit odemčený oddíl v `/data`. Dokončit adresáře, odkazy, vlastnictví, práva, cache, přejmenování, `fsync` a přehrání žurnálu. Dodat také potřebný zápis FAT32 na vyhrazený systémový oddíl pro instalátor a následné aktualizace.

**Převzetí.** Stejné soubory přečte a upraví AgentOS i Linux na VDI, USB a NVMe. Protokol porovná obsah i metadata. Na kopii VDI přerušit zápis před přejmenováním, během potvrzování a po synchronizaci adresáře. Obnovu provede AgentOS; na odpojeném ext4 ji nezávisle ověří `e2fsck -fn`. Po potvrzené synchronizaci musí zůstat celá nová verze.

### 7. Účty, přihlášení, instalace na NVMe a úplná obnova

**Navazuje na 3, 5 a 6.** Zavést účty, skupiny, audit, obnovu správce a autorizaci jednotlivých správcovských operací. Dokončit instalátor, který rozpozná cílový disk a stav jednotlivých instalačních kroků. Doplnit šifrovanou zálohu a obnovu na nové médium, zastavení služeb a čisté odpojení svazků.

**Převzetí.** Ve VM přerušit instalaci po GPT, LUKS2, ext4 a při založení správce. Ověřit bezpečné pokračování a hash necílového VDI. Na HP vyjmout pracovní disk, nainstalovat z USB na vyhrazený interní NVMe, odebrat USB a provést studený start, odemčení, přihlášení a čtení synchronizovaného souboru. Ověřit běžný i chybný login, zákaz přístupu mezi účty, povolené skupinové čtení, zvýšení oprávnění a rozdíl mezi obnovou disku a účtu. Na prázdný cíl obnovit zálohu bez přítomnosti původního disku a přihlásit oba původní uživatele. Tím se uzavře úložiště a instalace celku D; práva přes Linux ABI se zopakují v etapě 9.

### 8. Síť, systémový čas a TLS

**Potřebuje 3 a síťové ovladače ze 4; důvěra a správa využijí 5–7.** Implementovat Ethernet až TCP/UDP, loopback, DHCP, DNS a výchozí firewall podle § 7. Zavést monotónní lhůty, kontrolu věrohodnosti UTC a ověřování TLS včetně správy lokální CA a připnutí jejího rozsahu ke konkrétnímu serveru.

**Převzetí.** Na obou platformách získat adresu, přeložit jméno, přenést soubor přes TCP a ověřit obsah u příjemce. Ověřit, že nevyžádané příchozí spojení výchozí politika zablokuje. Na řízeném serveru vyzkoušet platný certifikát i všechny negativní případy celku E. Při chybě TLS server nesmí obdržet testovací aplikační údaj. Odpojení sítě zachová funkční lokální přihlášení.

### 9. Linux ABI pro skutečné binárky

**Základ může začít po 3; převzetí potřebuje 6–8.** Od zaváděcího zásobníku ELF postupovat k souborům, procesům, signálům, vláknům, TLS vláken, futexům, socketům a epoll. Vést tabulku podporovaných syscallů, příznaků a chyb. Stejné kontroly VFS a identity použít pro obě ABI.

**Převzetí.** Na Linuxu i AgentOS spustit totožné statické binárky s evidovaným SHA-256. Porovnat výstup a návratové kódy skriptu BusyBoxu, chybného otevření, vícevláknového programu s musl a loopback testu s timeoutem a probuzením `epoll_wait`. Zopakovat zkoušky soukromého a sdíleného souboru z etapy 7 nativní i linuxovou cestou. Výsledky uzavírají celek F.

### 10. Podepsané aktualizace A/B a servisní médium

**Navazuje na 1, 6 a 7.** Implementovat manifest vydání, kontrolu identity, architektury a verze uvnitř podepsaného EFI, zápis a zpětné ověření neaktivního slotu, jednorázový start a potvrzení až při připravených kritických službách. Připravit podepsané servisní médium a postup rotace a odvolání klíčů.

**Převzetí.** Aktualizovat A → B na VDI a na interním NVMe bez USB. Na kopiích VDI přerušit jednotlivé fáze, ukončit přihlašovací službu před potvrzením a ověřit identitu skutečně zavedeného vydání i data. Podvržený manifest a starší EFI se správným hashem v novějším manifestu musejí být odmítnuty před změnou slotu. Na izolované VM ověřit revokaci v `dbx`, odmítnutí při vypnutém Secure Bootu a funkční servisní start.

### 11. Agentní protokol, skutečný model a účinné odvolání práv

**Protokol využívá 3 a 7; úplné převzetí potřebuje také 8 a 9.** Nejprve implementovat lokální správu úloh, IPC identitu a kernelové vynucení pověření. Nad tím postavit katalog nástrojů, delegování, žádosti o práva, operace odolné vůči opakování a důvěryhodné potvrzení přes terminál. Nakonec připojit modelovou službu, omezení zdrojů, audit a zrušení celé větve úloh.

**Převzetí.** Pomocí dvou nezávislých klientů ověřit scénáře § 4.6 a celku G včetně ztracené odpovědi, souběžného jednorázového zápisu a odvolání. Samostatný linuxový potomek nesmí právům uniknout přes přímý syscall ani zděděný či duplikovaný popisovač. Na VM i HP skutečný agent přečte novou událost povolené služby a uloží zprávu se správným identifikátorem. Ověřit obsah na disku, odmítnutí nepovoleného síťového cíle a funkční konzoli po výpadku modelu.

### 12. Společná přejímka vydání

**Potřebuje všechny předchozí etapy.** S jediným kandidátem vydání zopakovat celky A–G podle § 11, včetně instalace, obnovy a přihlášení na fyzickém HP. Doložit shodný hash před podpisem ze dvou čistých sestavení a reprodukovatelné médium ze stejného podepsaného artefaktu. Přiložit postup sestavení, instalace, správy klíčů a obnovy, vývojářskou dokumentaci a protokol výsledků dle § 9–11.

| Měření | Podmínka převzetí |
|---|---|
| Studený start VM | Ve ≥ 19 z 20 běhů nejvýše 1 s od značky bootloaderu po výzvu, která přijme jméno. Odečíst pouze zadávání fráze. Secure Boot je aktivní. Odvození klíče s produkčními parametry Argon2id a připojení ext4 se započítají. Dobu firmwaru včetně ověření podpisu uvést zvlášť. |
| Paměť v klidu | Ve VM po získání adresy a 30 s klidu nejvýše 128 MiB obsazených stránek systému, z toho nejvýše 32 MiB jádro a jeho struktury podle § 9. |
| Výkon při práci | Na VM a HP změřit start procesu, zápis 1 MiB s `fsync` a lokální volání nástroje. Po 10 zahřátích provést 100 měření, uvést medián, 95. percentil, špičku RAM a chyby. První vydání vytvoří srovnávací základ. |

Ke každému povinnému kritériu se přiřadí platforma, konkrétní test a protokol z daného kandidáta. Chybějící fyzická zkouška, neověřený bezpečnostní požadavek nebo nesplněný limit ponechá vydání otevřené.
