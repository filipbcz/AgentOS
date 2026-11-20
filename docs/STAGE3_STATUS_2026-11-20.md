# AgentOS – stav implementace etapy 3 (2026-11-20)

## Jak číst stav

- **Implementováno:** zdrojový kód je ve vývojové větvi; samo o sobě to neznamená úspěšné sestavení.
- **Host-test:** automatický test existuje; jeho úspěch se posuzuje pouze vůči konkrétnímu SHA.
- **VM ověřeno:** skutečný podepsaný obraz prošel integračním během; bez logu a hashe obrazu se nesmí uvádět.
- **Hotovo:** akceptační kritéria podle `PLAN_IMPLEMENTACE.md` jsou doložená.
- **Rozpracováno:** chybí některá implementace nebo důkazy.

## Aktuální změny v této sérii

| Oblast | Kód | Testy | Integrace / stav |
|---|---|---|---|
| PS/2 dekódování | `kernel/keyboard.rs` | host unit | IRQ1 ve VM neověřeno |
| PS/2 řadič 8042 | `kernel/ps2.rs` | UART host harness se simulací, nikoli fyzický 8042 | timeouty/ACK v emulátoru neověřeny |
| IRQ1 a TTY | `kernel/acpi.rs`, `ioapic.rs`, `smp.rs`, `tty.rs` | smíšený vstup a chybový řádek v host testech | VM neověřeno |
| Bootovací filtry | `kernel/log_policy.rs`, `kernel/main.rs`, `boot/loader.c` | 5 host unit | BOOT.LOG přes EFI ve VM neověřen |
| Výběr výstupu | `scripts/disk.sh`, `scripts/test-vbox.ps1` | validace parametrů skriptu | COM1/framebuffer v posledním VM neověřeny |
| Historie logů | `kernel/log_ring.rs` | 6 host unit v `scripts/tests/log-ring-host.rs` | **pouze připravená datová struktura**, žádné runtime napojení |
| Centrální logger | zatím neexistuje | ne | rozpracováno |
| Framebufferový interaktivní terminál | zatím neexistuje | ne | rozpracováno |
| Správce služeb PID 1 | nedokončen | ne | rozpracováno |

## Poslední implementační krok: log ring

- `Ring` je pevně omezený na 32 záznamů po maximálně 96 bajtech zprávy, bez heap alokací.
- Každý záznam obsahuje sekvenční číslo, časovou značku v tazatelem dodaných monotónních ticích, CPU ID, úroveň a příznak zkrácení.
- `read(cursor)` rozlišuje prázdný výsledek a přepsaný záznam, u něhož vrací první dostupné sekvenční číslo. Při vyčerpání u64 sekvence `push` odmítá zápis namísto přetečení.
- Buffer je **single-owner**. Není bezpečný pro sdílení mezi CPU ani pro reentrantní IRQ. Modul je zahrnut do překladu jádra, ale není vytvořena globální instance, nezapisuje se do něj a nic jej nečte. Toto omezení je záměrné.
- Není měněn `BootInfo`, syscall ABI, EFI podpis, stávající COM1 výpis ani `main` větev.

## Ověření pro dalšího vývojáře

```bash
rustc --edition 2021 --test scripts/tests/log-ring-host.rs -o /tmp/agentos-log-ring-tests
/tmp/agentos-log-ring-tests
bash scripts/check-build.sh
```

Zkontrolovat GitHub Actions **na posledním commitu větve**. V tomto prostředí nebylo lokálně dostupné `rustc` ani VirtualBox; netvrdit, že testy proběhly lokálně. Výsledek CI je oddělený od VM akceptace.

## Další kroky dle etapy 3

1. Ověřit build/CI, vyhodnotit regresní testy; opravit případné selhání.
2. Podepsaný VM boot a COM1 shell s 1/2 vCPU, PS/2 IRQ1, chyby vstupu, volbu BOOT.LOG a zachování markerů. Uložit SHA obrazu, konfiguraci a logy.
3. Navrhnout per-CPU vlastnictví log bufferů, IRQ-safe zápis bez blokujícího UART, bezpečné slévání sekvencí a časových značek, testy přetečení. Až pak integrovat `log_ring` do běhu jádra.
4. Interaktivní framebufferový terminál a směrování výstupu shellu, včetně izolace od diagnostického logování.
5. Správce služeb PID 1 a zbývající akceptační podmínky etapy 3. Teprve po důkazech označit etapu jako hotovou.

## Předávací pravidlo

Při každé další změně doplnit tento dokument: konkrétní soubory, rozsah implementace, testy, výsledky a neověřené body. Nepovažovat zdrojový kód ani samotný zelený CI za důkaz funkčnosti na hardwaru.
