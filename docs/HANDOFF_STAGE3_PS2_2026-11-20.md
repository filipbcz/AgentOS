# AgentOS – předání práce: etapa 3, PS/2 dekodér (2026-11-20)

## Výchozí stav

- Repozitář: `filipbcz/AgentOS`; vývojová větev `dev/stage3-ipc-validation`, PR #1.
- Výchozí commit před touto prací: `4ed11ee9d310ec9560cf9123a023181d1df2bc01`.
- Závazné podklady: `ZADANI.md` a `PLAN_IMPLEMENTACE.md`, etapa 3.
- Předchozí PR obsahuje IPC, COM1 TTY, shell a hostitelské testy. Předchozí úspěšný CI běh se vztahuje k výchozímu commitu, nikoliv automaticky k novým změnám.
- Úspěšný integrační běh shellu v podepsaném EFI ve VirtualBoxu zatím není doložen.

## Provedené změny

1. `kernel/keyboard.rs`: samostatný `no_std` dekodér PS/2 scan-code Set 1 s pevnou tabulkou US-QWERTY. Stavové zpracování levého/pravého Shift, Ctrl, Alt, Caps Lock, E0 a šestibajtového E1/Pause. MAKE události emitují pouze povolené ASCII; BREAK, neznámé klávesy a nepodporované sekvence se ignorují. Ctrl-D mapuje na bajt 4 a Delete na 127, aby mohly využít existující `LineInput`. Metoda `reset()` obnoví stav po ztrátě bajtu.
2. `kernel/main.rs`: registrace modulu pro překlad skutečného jádra. **Není zatím volán z IRQ ani ze shellu.**
3. `scripts/check-build.sh`: přidáno spuštění skutečných Rust unit testů dekodéru před linkováním jádra.
4. `README.md`: popsána hranice implementace a navazující hardwarová integrace.
5. `PLAN_IMPLEMENTACE.md`: stav dílčí práce a neuzavřené akceptační podmínky.

## Testování a reprodukce

```bash
rustc --edition 2021 --test kernel/keyboard.rs -o /tmp/agentos-keyboard-tests
/tmp/agentos-keyboard-tests
bash scripts/check-build.sh
```

Sedm nových jednotkových testů kontroluje běžné klávesy a BREAK, Shift/Caps, editační a Ctrl-D klávesy, pravé modifikátory, E0/E1, reset stavu a omezenou množinu výstupních bajtů. Testy jsou zahrnuté do workflow `Host checks`. Při předání je nutné zkontrolovat CI výsledek **na posledním commitu větve**, ne na starším SHA. V tomto běhu asistenta nebyl dostupný `rustc` ani VirtualBox, proto lokální kompilaci či VM běh **neoznačujeme za provedený**.

## Nehotové a rizika

- **PS/2 zatím není funkční vstup.** Neexistuje inicializace řadiče 8042, detekce zařízení, přepnutí/ověření scan-code Set 1, IRQ1 ani předání bajtů do `LineInput`.
- Při integraci nepředpokládat automaticky, že každý řadič překládá Set 2 na Set 1; nejprve ověřit konfiguraci a ACK. Omezit polling timeoutem a počet bajtů zpracovaných v IRQ.
- Ztráta scan kódu může znamenat ztracené uvolnění Shift/Ctrl. Při paritní chybě nebo přetečení resetovat dekodér a zneplatnit aktuální příkaz v TTY. Nikdy nevykonat zkrácený vstup.
- Stávající sériový shell je nutné nejdřív ověřit přes `test-vbox.ps1 -Cpus 1 -Shell` a `-Cpus 2 -Shell` v podepsaném EFI. Zachovat důkazy: SHA-256 obrazu, konfiguraci VM, `com1.log`, `com1-input.bin`, `display.png` a výsledek validátorů.
- TTY na framebufferu, služba PID 1, restartování služeb a další akceptační body etapy 3 zůstávají otevřené.

## Navazující implementační pořadí

1. Ověřit poslední CI a opravit případné chyby testů či překladu.
2. Prokázat integrační běh dosavadního COM1 shellu na 1 a 2 vCPU; PR #1 neslučovat jen na základě hostitelských testů.
3. Přidat oddělený 8042 ovladač a testovat jeho časové limity, ACK a chybové stavy bez VM.
4. Přidat IRQ1 přes ACPI MADT / I/O APIC, směrovat do BSP, zavést bezpečné odpojení při ukončení relace.
5. Propojit dekodér a TTY; regresně ověřit přerušení, opakování, chyby a přepnutí vstupu.
6. Přidat textový výstup na framebuffer a správu služeb PID 1 dle etapy 3, následně provést akceptaci.

## Omezení rozsahu

Žádná změna nativního ABI, formátu EFI, bezpečnostní politiky ani stabilní větve `main`. Není deklarována funkční PS/2 klávesnice, VM integrace ani dokončení etapy 3.
