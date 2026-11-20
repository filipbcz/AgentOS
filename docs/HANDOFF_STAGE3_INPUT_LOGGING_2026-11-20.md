# Předání AgentOS – etapa 3: PS/2 + boot logging, 2026-11-20

## Kontext a hranice změn

Repo `filipbcz/AgentOS`, větev `dev/stage3-ipc-validation`, PR #1. Výchozí commit `deafa829185503e145ee5527c778acf6d9c70683`. Závazný plán `PLAN_IMPLEMENTACE.md`, etapa 3. Není měněn `main`, syscall ABI ani formát BootInfo (verze 3).

## Implementace

- `kernel/ps2.rs`: první port 8042, omezené čekání na připravenost, čtení konfigurace, zapnutí překladu Set 2->Set 1, výběr Set 2 na zařízení, spuštění skenování a obnova konfigurace po ukončení shellu. Při chybě inicializace se PS/2 nepovolí a COM1 zůstane funkční. Obsluha IRQ čte nejvýše 64 bajtů.
- `kernel/keyboard.rs`: předchozí dekodér Set 1 pro US-QWERTY.
- `kernel/acpi.rs`: IRQ1 GSI a případný override v MADT; výchozí ISA IRQ1 edge/high.
- `kernel/ioapic.rs`: samostatná maskovaná cesta pro IRQ1 do BSP a vektor 0xe2.
- `kernel/traps.S`, `kernel/exceptions.rs`, `kernel/smp.rs`: nový IRQ gate, validace in-service bitu lokálního APIC, EOI, probuzení čtenáře.
- `kernel/tty.rs`: volitelná PS/2 cesta sdílející existující `LineInput` se sériovým portem, reset dekodéru a invalidace poškozeného řádku při chybě.
- `boot/loader.c`, `kernel/main.rs`: konfigurovatelná úroveň bootovacích událostí a volba COM1/framebuffer přes `EFI/BOOT/BOOT.LOG`.
- `scripts/tests/tty-host.rs`: hostitelský UART harness odděluje neexistující PS/2 port; regresní testy stávajícího UART nejsou nahrazené testy PS/2.

## Konfigurace

`EFI/BOOT/BOOT.LOG` je jediný ASCII řádek bez BOM: `quiet|info|debug` a volitelně `serial|screen|both|none`. Příklad `debug serial`. Výchozí `info both`. Hodnota v `BootInfo.log_level`: bity 0–1 úroveň (0/1/2), bit 8 COM1, bit 9 framebuffer. UEFI `Print` používá firmware konzoli (screen). Původní přímé diagnostické výpisy subsystémů a akceptační markery jsou nezávislé na filtraci; `none` není úplné umlčení COM1. Nejde ještě o centrální runtime logger, per-CPU ring buffer ani persistentní žurnál.

## Testy a důkazy

```bash
bash scripts/check-build.sh
rustc --edition 2021 --test kernel/keyboard.rs -o /tmp/agentos-keyboard-tests
/tmp/agentos-keyboard-tests
```

Před akceptací je nutné ověřit úspěšný CI **posledního SHA**, sestavit podepsané EFI dle `scripts/build.sh` a spustit oba integrační testy:

```powershell
.\scripts\test-vbox.ps1 -Cpus 1 -Shell
.\scripts\test-vbox.ps1 -Cpus 2 -Shell
```

Samostatný PS/2 VM test zatím neexistuje: je nutné poslat skutečné scan kódy přes emulovanou klávesnici, ověřit reakce shellu a přechod při nepřítomnosti klávesnice. Zajistit konfiguraci VM, hash EFI, sériový log, screenshot a záznam výsledků. Nespouštělo se lokální EFI/VirtualBox ověření v prostředí asistenta.

## Známá rizika a navazující kroky

1. 8042 může být nepřítomný, mít jinou konfiguraci nebo vracet chyby ACK; ovladač je minimální a zatím není hardwarově ověřen. Nepředpokládat, že USB klávesnice poskytne 8042.
2. IRQ1 a COM1 zapisují do společné řádkové fronty; prověřit souběh, doručení a ochranu před zkráceným příkazem při přetečení.
3. Při nepodporovaném GSI nebo selhání PS/2 se používá jen COM1. Otestovat chybové stavy a návrat původní konfigurace 8042.
4. Doplnit hostitelský fake 8042 a testy timeoutů, ACK, parity, resetu a omezeného odčerpání FIFO.
5. Doplnit textový terminál na framebuffer (současné kreslení zobrazuje jen bootovací události), případně mapování české klávesnice.
6. Navrhnout centrální runtime logger s per-CPU omezenými buffery, časovými razítky, kategoriemi, bezpečným chováním v IRQ/panice a oddělenými sinky. Nepoužívat blokující UART zápisy uvnitř globálního zámku.
7. Dokončit správce služeb PID 1 a ostatní akceptační podmínky etapy 3. Neslučovat PR do `main` jen na základě hostitelských testů.

## Stav

Implementace zapsaná do vývojové větve; akceptace VM a funkčnost PS/2 zatím nepotvrzeny. Poslední CI je třeba vyhodnotit zvlášť. Další vývojář má pokračovat podle pořadí v `PLAN_IMPLEMENTACE.md`.


## Dodatečné změny testovacího prostředí

- `scripts/disk.sh`: přijímá validovanou kombinaci úrovně a cíle, zapisuje přesný obsah do `EFI/BOOT/BOOT.LOG`.
- `scripts/test-vbox.ps1`: přepínače `-LogLevel quiet|info|debug` a `-LogOutput serial|screen|both|none`; výchozí `info both`.
- `scripts/tests/tty-host.rs`: doplněny dva integrační hostitelské testy pro sdílený sériový/PS2 vstup a odmítnutí poškozeného příkazu. PS/2 port je v hostitelském testu simulovaný; nejde o důkaz IRQ1 ve VM.
- Poznámka k CI: během postupného zápisu souborů mohly průběžné commity dočasně selhat, protože nový `tty.rs` předběhl úpravu testovacího harnessu. Rozhodující je výsledek posledního commitu celé změny.


## Pokračování bez čekání na CI: izolace pravidel boot logování

- Přidán `kernel/log_policy.rs`: čistý `no_std` modul bez I/O a alokací. Typované úrovně `Error/Info/Debug`, cíle `Serial/Screen`, masky kompatibilní s `BootInfo.log_level` verze 3 a stabilní prefixy pro parser logů.
- `kernel/main.rs`: `BootLog::event` nově používá jednu společnou politiku pro rozhodnutí o obou cílech. Formát stávajících výpisů a přímé povinné diagnostiky se nemění.
- `scripts/check-build.sh`: spouští pět hostitelských regresních testů logování. Testy pokrývají výchozí nastavení, `quiet`, `debug serial`, `none` a stabilitu prefixů.
- Kompatibilita: EFI parser `BOOT.LOG` a předávání bitů přes `BootInfo` zůstaly beze změny; `none` nadále vypíná pouze běžné události, nikoliv všechny přímé COM1 diagnostiky.
- Pro reprodukci: `rustc --edition 2021 --test kernel/log_policy.rs -o /tmp/agentos-log-policy-tests && /tmp/agentos-log-policy-tests`; nebo celý `bash scripts/check-build.sh`.
- Tato změna byla zapsána do vývojové větve bez čekání na CI. Její vlastní výsledek CI a VM ověření je nutné zkontrolovat na posledním SHA před akceptací. Zatím nejde o runtime logovací subsystém s časem, bufferem či bezpečným souběhem CPU.
