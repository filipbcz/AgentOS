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

**Převzetí.** Test na 1 a 2 vCPU a následně na HP spustí identifikovatelnou úlohu na každém dostupném CPU. Zátěž ověří souběžnou alokaci a uvolňování stránek, preempci a probuzení časovačem. Ověří se ochranné stránky, NX a chování při vyčerpání paměti. V klidu se změří probuzení procesorů a režie jádra. Tím se ověří základ celku B; obecný demand paging a řízené vyvažování SMP podle § 4.3–4.4 mají vlastní implementaci a přejímku v milníku 3.1, který potřebuje také skutečné procesy z etapy 3.

### 3. Izolované procesy, VFS, IPC a terminál

**Aktuální stav základního profilu k 2026-11-21: implementováno, jádro a uživatelské programy ověřeny host testy a skutečným QEMU; povinná přejímka ve VirtualBoxu zůstává otevřená.** Pracovní větev je `dev/stage3-ipc-validation`, [draft PR #1](https://github.com/filipbcz/AgentOS/pull/1). `main` se nemění. Starší průběžné zápisy byly přesunuty beze změny věcného obsahu do [historie etapy 3](docs/HISTORY_STAGE3_BEFORE_COMPLETION.md); aktuální stav určuje pouze tato část. Nově přiřazené požadavky na demand paging a vyvažování SMP jsou samostatně sledované v navazujícím milníku 3.1 a tento stav ani dosavadní důkazy je nepotvrzují.

**Navazuje na 2.** Implementovat uživatelský režim, nativní syscall ABI, loader ELF, adresní prostory včetně copy-on-write, popisovače a identitu procesů. Z initramfs spustit PID 1. Přidat VFS, roury, lokální IPC s identitou volajícího, TTY, shell, PS/2 vstup a správu služeb. Textový shell pracuje přes TTY, správní operace přes služby podle § 3.

**Převzetí.** Uživatelský program přečte soubor z initramfs a pošle výsledek rourou. Chybný uživatelský ukazatel a pád samostatného procesu neukončí jádro ani druhý proces. PID 1 převezme ukončeného potomka a při opakovaném pádu služby omezí restartování. Interaktivní vstup a výstup se prověří přes COM1 a klávesnici s displejem. Úplná zkouška celku C včetně odemčení, přihlášení a trvalého přesměrování proběhne v etapě 7.

#### Implementovaný rozsah

| Oblast | Chování a zdroj | Kontrola |
|---|---|---|
| Izolované procesy | CPL3, soukromé CR3, kontrola uživatelských ukazatelů, W^X/NX, omezený ELF loader; `kernel/{process,paging,scheduler,smp}.rs` | Skutečný pád potomka bez pádu rodiče/jádra, odlišná CR3, chybové ABI, návrat rámců |
| Nativní ABI | Explicitní `AgentOS` ELF PT_NOTE, verze 1, flags 0; `kernel/native_abi.rs`, `user/{abi.h,user.ld}` | Rust parser, negativní metadata, skutečně slinkované ELF; každý z 12 programů prochází build gate |
| COW a životní cyklus | `fork`, lazy oddělení uživatelských stránek i při kernelovém copy-out, reaping/adopce sirotků, uzavření fd | Host test skutečného paging/scheduleru, guest COW/orphan scénáře a kontrola bitmapy |
| Kernelové zásobníky | 16 KiB + guard na obou stranách pro kernelové úlohy, syscall/trap, AP a IST; `kernel/stack.rs` | OOM rollback, nulování/reuse, supervisor/NX, sdílení mezi CR3; skutečný PF na obou guardech |
| VFS a roury | Initramfs pouze ke čtení, 32 fd/proces, sdílená pozice, omezené buffery a blokující čekání | Přenos 8193 bajtů, FNV-1a, EOF, chybné cesty/fd/buffery a uvolnění prostředků |
| Lokální IPC | Zprávy do 1024 B, kernelová PID/UID/GID identita, EOF/EPIPE, blokující i neblokující operace | Protilehlé identity, hraniční délky, zachování zprávy po chybě, full-mailbox EAGAIN bez změny dat |
| Původní PID 1 | Stejný BSP `init`/CR3 po jednorázovém `boot_pause`, statický DAG služeb, READY, reaping, restart limit/backoff, transitive stop a ordered shutdown | Guest identita PARK→SESSION, tři skutečné pády workeru, host selhání závislosti/orphan/timeout/IPC a čistý konec relace |
| Tickless běh | Jednorázový LAPIC podle nejbližšího deadline/kvanta, I/O wakeup; `kernel/timer.rs` | Host politika i scheduler, samostatný boot idle a provozní pětisekundový příkaz `idle` |
| TTY a shell | Kanonický COM1/PS2 vstup, ASCII GOP se scrollingem, chybová obnova, `services`, `service`, `idle`; `kernel/{line,tty,ps2,keyboard,fb_console}.rs`, `user/shell.c` | Skutečné UART/klávesnicové příkazy a obrazový glyph test; host chyby vstupu, overflow, EOF, čtení a partial write |
| Logování a důkazy | SMP/IRQ-safe omezená historie, BOOT.LOG filtr; zachovaný skutečný boot header | Pozitivní i potlačené výstupy, provenance a hash svázaný se zdroji, skutečné COM1/screenshot artefakty |

#### Náprava po review a zdůvodnění změn

1. **START/RESTART a obnova shellu.** Manager nyní provede spawn ještě před úspěšným ACK (`starting`, pokus 1); první příkaz nečeká na jinou událost či 60s deadline. Stav DOWN s dostupnou závislostí je okamžitá práce. Zastavená volitelná služba neblokuje obnovení již provozovaného shellu po pádu `core`. Testy pracují se skutečným C managerem a ověřují i jeho hlavní smyčku.
2. **Omezený dohled i při chybě klienta.** Celý až 1024bajtový paket se nejprve převezme a až potom validuje; chybná délka tak nezůstane ve frontě. Odpověď používá nové `SYS_IPC_TRY_SEND=0x10019`. Plná či uzavřená schránka izoluje porouchanou relaci přes stejný bounded restart, místo zablokování PID 1. OOM při zakládání služby také spotřebuje restartovací budget.
3. **Provozní nečinnost.** `core` po READY blokuje na celoživotním IPC, neprovádí 100ms periodickou práci. Timer používá minimum nejbližšího deadline a 10ms kvanta; při všech uspaných úlohách zůstává nejvýše 1s watchdog, bez timed waiterů je vypnutý. Nezávislý rozpočet počítá spotřebované LAPIC tick-y i při jiných IRQ. `SYS_TIMER_STATS=0x10018` kopíruje 32 B: verzi, lokální monotónní ms, runtime timer IRQ a idle timer IRQ. Čtení nenuluje počítadla; guest test ověřuje i neplatné pointery/velikost/flags.
4. **Skutečné guardy kernelových zásobníků.** Horní supervisor/NX podstrom vzniká před kopírováním privátních user roots. Padesát tabulek je trvalých; datové rámce zásobníků se transakčně přidělují/uvolňují. CPU-local vlastnictví a invalidace při reuse odpovídají stávající architektuře bez migrace. Marker `AGENTOS KERNEL STACK GUARD OK` vzniká po skutečném page faultu dolního i horního guardu. Host testy prověřují všech 50 přípravných OOM bodů a selhání jednotlivých datových alokací.
5. **Rozlišení ELF ABI.** Note má owner `AgentOS\0`, typ 1 a descriptor `{version=1,flags=0}`; loader ji ověří před privátními page-table alokacemi. Neoznačený ELF vrací ENOEXEC, protože je podle zadání vyhrazen budoucímu Linux ABI. Již vytvořené nativní programy je nutné znovu slinkovat přes aktualizovanou hlavičku/script. Dynamický linker ani Linux ABI se tím nepředstírají.
6. **Testovací skripty odpovídají aktuálním producentům.** Záznam ukončení je `AGENTOS MANAGER SESSION STOP`, VBox Backspace/Enter používá vstupní PC/XT Set 1 a ověření GOP hledá přesnou novou odpověď na celém řádku. Horních 88 px uchovává skutečné bootové pixely, takže pozitivní test nezávisí na závodu s vymazáním obrazovky. TCP capture čeká i na kompletní závěrečný strukturovaný řádek. Kontrola souhrnu vyžaduje odpovídající čistý checkout, aby starší úspěch nepotvrzoval pozdější změny.

Rozhraní a limity jsou popsány také v aktuálním [README](README.md). Přidané syscally nemění čísla starších operací. Nová ABI note je záměrně povinná a všechny dodávané programy jsou aktualizované současně.

#### Ověření této pracovní dávky

Finální ověřená implementační revize včetně přejímacích skriptů je [`64f87f8899e3d7e0cb3fff7bf55ff147bef2354c`](https://github.com/filipbcz/AgentOS/commit/64f87f8899e3d7e0cb3fff7bf55ff147bef2354c). [Host checks 44938920075](https://github.com/filipbcz/AgentOS/actions/runs/44938920075) a [QEMU Secure Boot 44938920070](https://github.com/filipbcz/AgentOS/actions/runs/44938920070) oba skončily **success**. CI checkout používá PR merge `e25f4323c979a6a803c9a756c6a0b8b423eaf802`; jeho strom `80894fb984d5dca7065134ea640a791349d27ee4` je přesně shodný se stromem uvedeného headu. Následný zápis těchto výsledků mění pouze dokumentaci, nikoli implementaci, build ani testovací scénáře.

| Ověření | Skutečný výsledek |
|---|---|
| Host Python | 131 úspěšných testů |
| Rust | 159 úspěšných spuštění ve 12 sadách; sdílené moduly se mohou testovat opakovaně |
| Rizikové nové části | 30 scheduler/timer, 6 ABI parser, 4 stack allocator a 6 paging/COW testů prošlo |
| C | Manager, worker, supervisor a orphans harness prošly |
| Sestavení | Rust 1.75.0, GCC 13.3.0; kernel a všech 12 user ELF slinkováno; W^X, trap návraty a note ověřeny |
| PowerShell | Parser všech skriptů prošel |
| QEMU 1 CPU | Podepsaný boot 33,570 s; úplná UART/PS2/GOP relace 40,450 s, výsledek pass |
| QEMU 2 CPU | Podepsaný boot 35,584 s; úplná UART/PS2/GOP relace 41,715 s, výsledek pass |
| Provozní klid | 1 CPU: 5000 ms, 2 CPU: 5001 ms; v obou celkem 6 timer IRQ, všech 6 při všech úlohách blocked |
| Reálné restarty a úklid | 1 CPU ukončil nová PID 19/20/21, 2 CPU PID 31/32/33 se stavem 42; původní kořen zůstal PID 1; konec obou relací stav 0 a FRAMES=OK |

Podepsané obrazy mají SHA-256 `4d95f709d19e1ab15bde8d0a8b97d97ee367d9a925b7f24aaee41af2446655ce` (1 CPU) a `c2660a509ffddf533b1e43b59af5b81bc09b0f39eba940d0665203c17edbca8c` (2 CPU). Rozdíl odpovídá odděleným dočasným podpisovým klíčům jobů. **Obě nezávislá sestavení mají shodný nepodepsaný EFI hash** `aecaff94a3fae061a1a61e74a20a31b0865b1d006c7b04d1e6c8e00af03b10b1` a initramfs hash `11245c2e08a32abdaf317e09c0faac2bc9d347f8054a3fb6d708794333393fc6`.

GitHub artefakty [qemu-secureboot-1cpu](https://github.com/filipbcz/AgentOS/actions/runs/44938920070/artifacts/14720892772) (ID 14720892772) a [qemu-secureboot-2cpu](https://github.com/filipbcz/AgentOS/actions/runs/44938920070/artifacts/14721225362) (ID 14721225362) obsahují skutečné COM1 logy, odeslané bajty, GOP snímky, signed EFI, build provenance a `smoke.json`; byly staženy a kontrolní součty porovnány s GitHub metadaty. Bootoval OVMF Secure Boot/QEMU TCG, 256 MiB, 1/2 CPU. Screenshot reálné PS/2 odpovědi byl také vizuálně zkontrolován. QEMU je samostatná platforma, ne potvrzení VirtualBoxu.

Lokálně dále prošly čtyři C harnessy, freestanding link všech user programů s GCC 14.2 a Python kontroly. Místní prostředí nemá rustc, QEMU, PowerShell ani VirtualBox; příslušné provedené kontroly výše skutečně běžely v GitHub CI.

Finální CI zahrnuje i čekání na kompletní poslední TCP řádek, kontrolu aktuálního čistého Git checkoutu, zákaz bytecode cache samotného ověřovače/QEMU harness a odstranění starého souhrnu před novým sestavením. Všech 12 regresních testů souhrnu včetně pěti testů se skutečnými dočasnými Git repozitáři prošlo. Předchozí implementační commit `6905d203f86e73feb86b29343acd139671c15ab6` měl také zelené host i QEMU běhy; pro aktuální předání jsou rozhodující finální výsledky výše.

#### Jediný zbývající přejímací krok základního profilu etapy 3

Na Windows s VirtualBoxem **7.1.12**, WSL `Ubuntu-24.04` a potřebným toolchainem, z čisté aktuální vývojové větve:

```powershell
.\scripts\accept-stage3.ps1
python scripts/verify-stage3-suite.py --root . --manifest build/runs/stage3-acceptance.json
```

Matice automaticky sestaví a podepíše obraz a provede 13 profilů: na 1/2 CPU základní boot `info both`, plnou COM1 relaci `debug serial`, COM1+PS/2/GOP relaci `info serial`, `quiet none`, `debug screen`; dále tři negativní podpisové modifikace loader/kernel/initramfs na 1 CPU. Interaktivní relace zahrnuje opravu Backspace, VFS/chybové příkazy, okamžitý START, STOP, pětisekundový idle, trvání STOP, RESTART se třemi skutečnými pády bez status-pollingu, PS/2 podle profilu a konec PID 1 s `FRAMES=OK`. Idle validátor odmítá původní stovky periodických IRQ.

Souhrnný úspěch je `STAGE3_VM_MATRIX_PASSED`, důkazy zůstávají v `build/runs/` včetně `stage3-acceptance.json`. `-SkipBuild` smí opakovat pouze totožný čistý commit a obraz. Selhání vyžaduje vyhodnotit konkrétní log, opravit příčinu a znovu provést dotčené testy; není dovoleno snížit kritéria nebo přijmout timeout jako úspěch. **Dokud tato matice reálně neprojde, etapa není akceptovaná a draft PR se neslučuje.**

#### Hranice etapy a navazující práce

Registr je konečný profil tří služeb z podepsaného initramfs: timer/IPC `core`, záměrně padající `flaky`, shell. Přihlášení, účty, LUKS2/ext4, bezpečný unmount/flush a A/B potvrzování závisí na etapách 4–10; jejich absence se nevydává za ověřenou kritickou službu. Shell `exit` dnes ukončí systémovou testovací relaci; přihlašovací služba v etapě 7 přinese opakované uživatelské relace. Úplný shell celek C včetně trvalého přesměrování zůstává v etapě 7 podle původního kritéria.

Současné procesy mají jedno vlákno, CPU-local fd/IPC a monotónní epochu, osm task slotů na CPU, 32 fd, bootovací UID/GID 1000. Základní profil před milníkem 3.1 mapoval ELF segmenty a uživatelský zásobník před spuštěním; samotné COW nebylo obecným demand pagingem. Novou implementaci demand pagingu sleduje část 3.1 A níže. Migrace a nutné mezi-CPU probouzení/IPC patří do části 3.1 B. Vícevláknové POSIX ABI, dynamické service manifests a perzistentní audit nejsou v tomto základním profilu implementované. Změna těchto hranic musí rozšířit vlastnictví/TLB/protokolové testy. Fyzické HP, dlouhodobá provozní zátěž a širší platformní podpora zůstávají vlastními navazujícími zkouškami; QEMU výsledky je nenahrazují.

### 3.1. Demand paging a vyvažování SMP

**Stav k 2026-11-21: část A implementována a připravena k ověření v CI; část B zůstává navržená a neimplementovaná.** Tento milník přiřazuje dva požadavky zadání, které původní plán nepojmenoval v žádné etapě. Přejímka zůstává otevřená; historické host/QEMU výsledky etapy 3 nové chování nepotvrzují. Aktuální bootové scénáře doplňují ověření demand pagingu a opakují původní regrese.

| Požadavek zadání | Odpovědná část milníku | Návaznost |
|---|---|---|
| § 4.3 — demand paging pro procesy | 3.1 A: procesová paměť a obsluha page faultu | Adresní prostory, ELF a COW z etapy 3 |
| § 4.4 — řízený přesun úloh mezi CPU a vyvažování zátěže | 3.1 B: plánovač SMP a vlastnictví prostředků | SMP/časovače z etapy 2 a procesy, IPC a čekání z etapy 3 |

**Navazuje na 2 a 3.** Doporučené pořadí je dokončit základní profil etapy 3, poté část A a následně část B včetně jejich společných regresí. Obě části patří do společných kernelových rozhraní, která později použije také Linux ABI. Nízké ovladače etapy 4 mohou vznikat souběžně; převzetí etapy 9 a stabilního vydání v etapě 12 vyžaduje dokončený milník 3.1. Dosavadní číslování etap 4–12 zůstává zachováno.

#### A. Demand paging procesové paměti

Oddělit evidenci rezervovaných virtuálních oblastí, jejich práv a zdroje obsahu od přidělených fyzických rámců. Platný první přístup má přidělit a vynulovat anonymní stránku nebo načíst příslušnou část ELF z initramfs, včetně správného nulování BSS. Obsluha nesmí zpřístupnit nulovou adresu, guard zásobníku ani stránky mimo povolené oblasti; zachová NX a W^X. Podporované oblasti a jejich limity musí být dokumentované.

Sjednotit tuto cestu s COW a kernelovým čtením/zápisem uživatelských bufferů: platná dosud nepřítomná stránka musí fungovat i při syscallu, neplatný přístup musí skončit odpovídající chybou. `fork` musí zachovat rezervace i obsah před prvním načtením stránky i po něm. OOM, selhání částečné alokace a ukončení procesu musí mít definovaný výsledek, vrátit všechny rozpracované prostředky a zachovat ostatní procesy. První přejímka používá anonymní paměť a neměnný initramfs, takže není závislá na hotovém ext4.

**Dotčená rozhraní.** Správa oblastí a PTE v `kernel/paging.rs`, životní cyklus/loader v `kernel/process.rs`, page fault a syscall copy-in/copy-out, evidence rámců a jejich referencí. Přesná veřejná rozhraní, chybové návraty a potřebné změny ABI se doplní při implementaci spolu s konzumenty a testy.

##### Implementace části A a její hranice

- `kernel/paging.rs` vlastní jednu metadata stránku s nejvýše 64 oblastmi včetně čtyřstránkového zásobníku. `UserSpace` zůstává malý kvůli osmi procesním slotům uloženým ve struktuře CPU. Rezervace nepřiděluje datové rámce ani podřízené tabulky. `kernel/process.rs` ověřuje celé ELF a uchovává pouze statický backing z initramfs; zásobníkový guard zůstává mimo rezervace. `user/user.ld` ukládá `.bss` jako `NOBITS`.
- Page fault přijímá pouze oprávněné uživatelské první čtení/zápis/spuštění a skutečný COW zápis; jiné protection, reserved-bit, guard, NX a RO případy ukončí příslušný proces. Obsah části stránky před segmentem, BSS i padding se nuluje. Neúspěšné vytvoření jednotlivého mapování vrací celý nepublikovaný podstrom tabulek.
- `read`/`readable`/`writable`/`write` nejprve ověří celý buffer podle oblastí, poté materializují potřebné stránky a až nakonec kopírují. `kernel/files.rs`, `kernel/ipc.rs` a syscall cesty v `kernel/smp.rs` propagují `EFAULT` (−14) a `ENOMEM` (−12) odlišně. Selhání přípravy zachová offset souboru, zprávu IPC i obsah roury. Již úspěšně připravené stránky či oddělené COW mapování mohou po více-stránkovém OOM zůstat rezidentní; nejde o potvrzený přenos dat a jejich vlastnictví zůstává procesu. UART/GOP výstup se dokončuje mimo zámek fyzického alokátoru z vlastní omezené kopie dat.
- `fork` kopíruje i nepřítomné rezervace, sdílí pouze rezidentní stránky a ochrany rodiče mění až po úspěšném klonování. Ukončení vrací data, soukromé tabulky, metadata a všechny reference. Kontrola přetrvávajícího PID 1 normalizuje původní rezidentní snapshot pouze přes přesné PT/datové rámce dosažitelné z jeho aktuálního adresního prostoru; kontrola ostatních bitů i závěrečná bitmapa po ukončení celé relace zůstávají zachované.
- Přibývá aditivní nativní syscall `vm_stats` (`0x1001a`, buffer 64 bajtů, flags 0). Osm little-endian u64 obsahuje verzi 1, rezervované stránky, rezidentní uživatelské stránky, soukromé tabulky včetně root, metadata stránky, počet demand alokací, COW kopií a povýšení posledního vlastníka. Cíl se připraví před snímkem. Kumulativní počty jsou od vzniku daného prostoru, v potomkovi začínají od nuly; počty mapování dědí aktuální stav. Nejde o unikátní fyzickou spotřebu celého systému. Kontrakt a nové návraty `ENOMEM` jsou v `user/abi.h` a README.

##### Ověření a předání části A

Lokálně prošlo 139 Python testů ověřovačů a C harness entrypointů, kontrola syntaxe Python/Bash a link všech 12 nativních uživatelských ELF s kontrolou ABI note. Nová Rust sada testuje skutečný pager, loader, VFS, fd a IPC s vlastněnou zarovnanou host pamětí, OOM body, rollback a zachování dat; další testy ověřují přesné započítání živých rámců do snapshotu. Lokální prostředí nemá Rust ani hypervizor, proto **Rust/kernel link a skutečný QEMU běh této implementace zatím čekají na CI**; tento odstavec se po jejich dokončení doplní konkrétní revizí a důkazy.

`user/demand.c` běží v původním initu na 1/2 CPU. Rezervuje 16 MiB skutečného BSS, měří málo rezidentních stránek a jejich přírůstek po čtyřech vzdálených přístupech, ověřuje lazy file/pipe/IPC buffery, fork nad rezidentními i nepřítomnými oblastmi a ukončení samostatných potomků při guard/NX/RO přístupu. `verify-demand-paging.py` kontroluje čítače, přesnou posloupnost, identitu, adresy a chybové kódy skutečných faultů. `qemu-smoke.py` a `test-vbox.ps1` jej v nových pozitivních sériových bězích vyžadují. Host OOM testy neznamenají provedenou guest zkoušku vyčerpání paměti demand procesem.

Přejímka ve VirtualBoxu zůstává neprovedená. Aktuální `scripts/accept-stage3.ps1` sestaví nový obraz a provede 13 profilů s rozšířeným bootovým scénářem. Výsledné COM1 logy pro 1/2 CPU lze samostatně ověřit přes `python scripts/verify-demand-paging.py --log CESTA_K_COM1_LOG --cpus 1` nebo `2`; celý souhrn dál vyžaduje čistý odpovídající Git checkout. Následující implementační práce je část B; úspěch testů části A ji neuzavírá.

#### B. Řízená migrace a vyvažování SMP

Zachovat samostatné fronty CPU a zavést měřitelné vyvažování skutečné zátěže přesunem spustitelných úloh. Popsat pravidla výběru zdrojového/cílového CPU, bezpečný okamžik přesunu a synchronizaci front bez jednoho globálního zámku plánovače. Úloha smí mít právě jednoho vlastníka a nesmí současně běžet na dvou CPU. Připnutí zůstane jen pro zdůvodněné CPU/zařízení vázané úlohy; obecné procesy se musejí skutečně přesouvat. Vyvažování musí zachovat tickless klid bez trvalého pollingu.

Odstranit vazbu identity procesu, rodičovství, fd, rour, IPC a čekacích front na původní CPU. Přesun musí zachovat PID, oprávnění a otevřené prostředky, umožnit probuzení z jiného CPU a bezpečné dokončení/ukončení potomka. Zajistit přenos kontextu, správné CR3 a kernelový zásobník, synchronizaci referencí COW a invalidaci TLB před opětovným použitím mapování či rámců. Změna nesmí uvolnit prostředek, který ještě používá jiné CPU nebo zařízení.

Monotónní čas a platné lhůty nesmějí při migraci změnit význam. Nahradit dnešní CPU-local předpoklady v `kernel/scheduler.rs`, `kernel/smp.rs`, `kernel/stack.rs`, `kernel/paging.rs` a fd/IPC vrstvách a určit společnou časovou doménu nebo ekvivalentní mechanismus zachovávající lhůty. Rozhraní v `user/abi.h`, zejména `monotonic_ms`, časovaná čekání a `timer_stats`, musí dostat výslovné rozhodnutí o kompatibilitě/verzování; současné v1 nelze tiše předefinovat. Souběžná vlákna jednoho adresního prostoru, TLS a futexy se doplní a samostatně prověří v etapě 9 nad těmito kernelovými mechanismy.

#### Převzetí milníku 3.1

Připravit host testy algoritmů a selhání, integrační testy z uživatelského prostoru a skutečné běhy ve VirtualBoxu 7.1.12 s 256 MiB na 1 a 2 vCPU. Protokol uvede commit, hash obrazu, konfiguraci, logy a měřené hodnoty. QEMU může poskytovat průběžné regresní důkazy; fyzické ověření na HP se eviduje odděleně a zopakuje v etapě 12.

1. **Skutečně odložená alokace.** Po rezervaci oblasti doložit počet rezidentních datových rámců; nevyužité stránky se nesmějí přidělit předem. První oprávněné přístupy v uživatelském režimu i přes syscall musí vytvořit jen potřebné stránky se správným obsahem ELF/BSS/anonymní paměti. Režii metadat a tabulek vykázat odděleně.
2. **Izolace, COW a návrat prostředků.** Ověřit `fork` před prvním přístupem i po něm, soukromé zápisy rodiče/potomka, chybné adresy, ochrany a řízené OOM. Po ukončení a rollbacku se musí evidence rámců, tabulek a metadat vrátit do výchozího stavu; druhý proces a jádro pokračují.
3. **Skutečné vyvažování.** Na 2 vCPU vytvořit nevyváženou frontu a doložit, že plánovač přesunul existující úlohu na druhé CPU a ta tam pokračovala. Počáteční rozmístění úloh na obě CPU tento požadavek nesplňuje. Ověřit zachování identity, právě jedno vykonávání každé úlohy a dokončení práce bez hladovění.
4. **Migrace za provozu.** Při opakovaných přesunech ověřit lazy page fault/COW, syscally, roury, IPC a mezi-CPU probuzení, ukončení/reaping, monotónní čas a neztracené lhůty. Zahrnout závody přesunu s probuzením a ukončením, plnou cílovou frontu a znovupoužití zásobníků bez zastaralého TLB; nesmí vzniknout ztracená úloha, dvojí běh ani deadlock.
5. **Regrese původního základu.** Na 1 vCPU musí systém fungovat bez potřeby druhého CPU. Na 1/2 vCPU znovu projdou dotčené testy etap 2 a 3, včetně PID 1/služeb, TTY, ochranných stránek a měření probuzení v klidu. Teprve tento protokol uzavírá oba doplněné požadavky § 4.3–4.4; původní výsledky etapy 3 je nenahrazují.

### 4. Ovladače a bloková zařízení na obou platformách

**Potřebuje 2; uživatelské zkoušky využijí 3.** Zprovoznit PCI/PCIe, přerušení MSI/MSI-X, DMA mapování a blokové rozhraní s dokončením a vyprázdněním zápisů. Podle pořadí v § 5.1 připojit AHCI a NVMe, transport VirtIO-net, xHCI, USB HID, USB Mass Storage a kabelový Realtek. Síťové ovladače zde stačí dovést k odeslání a příjmu rámce.

Vývoj může běžet souběžně s 3.1. Rozhraní pro dokončení I/O a probouzení musí respektovat možné přesunutí čekajícího procesu na jiné CPU. Aktivní DMA buffery mají stabilní fyzické rámce po celou dobu přístupu zařízení; demand paging ani migrace úlohy nesmějí tuto evidenci obejít. Po propojení s 3.1 se zopakují dotčené I/O a timeout testy.

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

**Základ může začít po 3; převzetí potřebuje 3.1 a 6–8.** Od zaváděcího zásobníku ELF postupovat k souborům, procesům, paměťovým operacím, signálům, vláknům, TLS vláken, futexům, socketům a epoll. Paměťové syscally a plánování použijí společné kernelové mechanismy z 3.1. Vést tabulku podporovaných syscallů, příznaků a chyb. Stejné kontroly VFS a identity použít pro obě ABI.

**Převzetí.** Na Linuxu i AgentOS spustit totožné statické binárky s evidovaným SHA-256. Porovnat výstup a návratové kódy skriptu BusyBoxu, chybného otevření, vícevláknového programu s musl a loopback testu s timeoutem a probuzením `epoll_wait`. Zopakovat zkoušky soukromého a sdíleného souboru z etapy 7 nativní i linuxovou cestou. Rozšířit regrese 3.1 o skutečně souběžná vlákna sdílející adresní prostor na 2 vCPU: lazy page faulty, změny mapování/TLB, TLS, futex probuzení a migraci při zachování lhůt. Výsledky uzavírají celek F.

### 10. Podepsané aktualizace A/B a servisní médium

**Navazuje na 1, 6 a 7.** Implementovat manifest vydání, kontrolu identity, architektury a verze uvnitř podepsaného EFI, zápis a zpětné ověření neaktivního slotu, jednorázový start a potvrzení až při připravených kritických službách. Připravit podepsané servisní médium a postup rotace a odvolání klíčů.

**Převzetí.** Aktualizovat A → B na VDI a na interním NVMe bez USB. Na kopiích VDI přerušit jednotlivé fáze, ukončit přihlašovací službu před potvrzením a ověřit identitu skutečně zavedeného vydání i data. Podvržený manifest a starší EFI se správným hashem v novějším manifestu musejí být odmítnuty před změnou slotu. Na izolované VM ověřit revokaci v `dbx`, odmítnutí při vypnutém Secure Bootu a funkční servisní start.

### 11. Agentní protokol, skutečný model a účinné odvolání práv

**Protokol využívá 3 a 7; úplné převzetí potřebuje také 8 a 9.** Nejprve implementovat lokální správu úloh, IPC identitu a kernelové vynucení pověření. Nad tím postavit katalog nástrojů, delegování, žádosti o práva, operace odolné vůči opakování a důvěryhodné potvrzení přes terminál. Nakonec připojit modelovou službu, omezení zdrojů, audit a zrušení celé větve úloh.

**Převzetí.** Pomocí dvou nezávislých klientů ověřit scénáře § 4.6 a celku G včetně ztracené odpovědi, souběžného jednorázového zápisu a odvolání. Samostatný linuxový potomek nesmí právům uniknout přes přímý syscall ani zděděný či duplikovaný popisovač. Na VM i HP skutečný agent přečte novou událost povolené služby a uloží zprávu se správným identifikátorem. Ověřit obsah na disku, odmítnutí nepovoleného síťového cíle a funkční konzoli po výpadku modelu.

### 12. Společná přejímka vydání

**Potřebuje všechny předchozí etapy včetně 3.1.** S jediným kandidátem vydání zopakovat celky A–G podle § 11, včetně demand pagingu a vyvažování SMP z 3.1, instalace, obnovy a přihlášení na fyzickém HP. Doložit shodný hash před podpisem ze dvou čistých sestavení a reprodukovatelné médium ze stejného podepsaného artefaktu. Přiložit postup sestavení, instalace, správy klíčů a obnovy, vývojářskou dokumentaci a protokol výsledků dle § 9–11.

| Měření | Podmínka převzetí |
|---|---|
| Studený start VM | Ve ≥ 19 z 20 běhů nejvýše 1 s od značky bootloaderu po výzvu, která přijme jméno. Odečíst pouze zadávání fráze. Secure Boot je aktivní. Odvození klíče s produkčními parametry Argon2id a připojení ext4 se započítají. Dobu firmwaru včetně ověření podpisu uvést zvlášť. |
| Paměť v klidu | Ve VM po získání adresy a 30 s klidu nejvýše 128 MiB obsazených stránek systému, z toho nejvýše 32 MiB jádro a jeho struktury podle § 9. |
| Výkon při práci | Na VM a HP změřit start procesu, zápis 1 MiB s `fsync` a lokální volání nástroje. Po 10 zahřátích provést 100 měření, uvést medián, 95. percentil, špičku RAM a chyby. První vydání vytvoří srovnávací základ. |

Ke každému povinnému kritériu se přiřadí platforma, konkrétní test a protokol z daného kandidáta. Chybějící fyzická zkouška, neověřený bezpečnostní požadavek nebo nesplněný limit ponechá vydání otevřené.
