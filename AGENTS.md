# AgentOS — závazná pravidla pro všechny vývojáře a AI agenty

Platí pro všechny etapy, adresáře a změny repozitáře, včetně existujícího kódu. Před zahájením práce načti [ZADANI.md](ZADANI.md) (technické požadavky) a [PLAN_IMPLEMENTACE.md](PLAN_IMPLEMENTACE.md) (autoritativní plán, stav, závislosti a důkazy). Historické handoff dokumenty ani dřívější zelené CI nemají přednost před těmito pravidly.

## 1. Nativní operační systém a standardní hardware

- AgentOS je plnohodnotný nativní OS pro x86-64, UEFI, ACPI a PCI/PCIe. Musí fungovat na fyzickém hardwaru i ve VirtualBoxu. QEMU je pouze doplňková vývojová a regresní platforma, nikoliv cílová architektura.
- V rámci schváleného rozsahu implementuj všechny relevantní standardní varianty hardware a provozních stavů podle normativních specifikací. Návrh nesmí vycházet jen ze schopností právě dostupného emulátoru nebo jednoho konkrétního zařízení. Zjišťuj topologii, adresy, parametry a capabilities dynamicky. Počítej s více řadiči a zařízeními, různými počty CPU, velikostmi RAM, šířkami adres, geometriemi disků, revizemi, přerušeními, DMA, souběhem, stavem převzatým od firmwaru, hotplugem a poruchami.
- Správně vyjednávej volitelné schopnosti a používej standardní alternativy, pokud daná schopnost není dostupná. Nepoužívej pevné hodnoty emulátoru, testovací BDF, port, MAC, počet CPU, NSID, identitu či obsah média jako podmínku obecné funkce. Vendor-specific ovladače a hardwarové quirks musí být podložené dokumentací a izolované.
- Hardware mimo schválený rozsah bezpečně identifikuj a odmítni. Standardní variantu uvnitř požadovaného rozsahu nesmíš svévolně vyloučit jen proto, že ji neumí testovací prostředí. Rozsah podpory lze zúžit pouze s výslovným souhlasem zadavatele.

## 2. Absolutní oddělení přejímky od produkčního kódu

**V samotném produkčním kódu nesmí být nic, co existuje pouze kvůli přejímce.**

- V bootloaderu, jádře, ovladačích, systémových službách, PID 1 a běžných uživatelských programech jsou zakázány přejímací scénáře, testovací fixture, očekávané testovací hodnoty, umělé markery a počitadla určené výhradně ověřovači, testovací rendezvous přes COM1/QMP, rozpoznávání testu a speciální chování pro testovací prostředí.
- Nevytvářej `*_acceptance` build flags, zvláštní přejímací kernel, přepínač test mode v produkční implementaci ani alternativní funkční cestu aktivní pouze během testu. Běžný boot inicializuje dostupný hardware a spustí skutečné systémové služby, nikoliv zátěžové či přejímací scénáře.
- Veškerá testovací logika patří do oddělených testů, samostatných testovacích klientů, hostitelských nástrojů a CI. Testy přímo používají stejné produkční moduly nebo běžná dokumentovaná rozhraní. Přejímka ověřuje tentýž funkční kód bootloaderu, jádra, ovladačů a služeb bez zvláštní kompilace těchto částí. Testovací program lze dodat odděleně a spustit běžnou cestou; nesmí být součástí distribučního initramfs ani povinného startu systému. Jednotkové testy smějí používat izolované testovací náhrady, ne produkční implementace.
- Obecná provozní diagnostika, standardní správa, logování skutečných událostí, metriky, bezpečnostní kontroly a validace jsou žádoucí. Musí však mít vlastní provozní účel nezávislý na testu a fungovat stejně mimo přejímku. Ověřovač smí sledovat skutečné provozní výstupy, nikoliv určovat chování OS.
- Test nesmí předstírat výsledek operace, generovat náhradní důkaz, oslabovat podmínky úspěchu nebo vyžadovat obcházení bezpečnosti. Skutečné výsledky ověřuj nezávisle: například obsah rámce u příjemce, trvalost zápisu po restartu nebo skutečný stav zařízení.

## 3. Vždy plnohodnotná funkčnost

- Každou funkci navrhni jako běžnou součást OS od prvního přírůstku. Implementuj celý požadovaný životní cyklus: detekci, inicializaci, normální provoz přes dokumentované rozhraní, souběh, hraniční a chybové stavy, omezené čekání, nedostatek prostředků, zotavení, ukončení a bezpečné uvolnění prostředků.
- Zákaz stubů vydávaných za hotové funkce, předstíraného úspěchu, jednorázové bootovací demonstrace místo runtime ovladače, hardwarových zjednodušení kvůli emulátoru a minima k dosažení zeleného CI. Nepřidávej provizorní funkční architekturu, kterou bude nutné později nahradit. Polling je přípustný tam, kde má skutečný provozní důvod podle návrhu; nesmí nahrazovat požadované runtime IRQ, souběh nebo obnovu.
- Respektuj bezpečnost, izolaci, ABI, vlastnictví prostředků, správnou synchronizaci a paměťové bariéry. Úspěch vrať pouze po skutečném dokončení příslušné operace.
- Pracovní commity mohou zachycovat skutečné dílčí kroky úplné implementace. Nedokončená funkce zůstává otevřená, se seznamem chybějících částí. Před navázáním závislou funkcí dokonči její základ. Povinné funkce neodkládej do jiné etapy bez schválení. Odložená fyzická přejímka není povolením odložit implementaci.

## 4. Pracovní postup a předávání

1. Načti aktuální větev, zadání, plán, dotčený kód, testy a relevantní specifikace. Prověř i standardní varianty hardware, které nejsou právě dostupné v CI.
2. Vyvíjej na určené pracovní větvi. `main` neměň bez výslovného pokynu. Změny ABI, bezpečnosti nebo rozsahu zdůvodni a ověř podle zadání.
3. Implementuj obecné funkční rozhraní bez přejímací logiky. Přidej oddělené pozitivní, negativní, hraniční, souběžné a regresní testy; ověř běžný start nezávislý na harnessu.
4. Eviduj host testy, QEMU, VirtualBox a fyzický HP zvlášť s revizí, konfigurací a artefakty. Úspěch v QEMU ani překlad nejsou důkazem fyzické funkčnosti. Chybějící prostředí, důkaz nebo specifikaci označ jako blokující problém nebo neověřený stav; nic nepředstírej.
5. Aktualizuj příslušnou etapu v plánu: skutečný stav, rozsah změn, rozhodnutí, zbývající požadavky, výsledky a odkazy na důkazy, další krok. Před předáním zkontroluj soulad s tímto dokumentem.

## 5. Povinná náprava dosavadní implementace

Pravidla platí i zpětně. Dosavadní testovací bootovací scénáře a profily `--ahci-dma`, `--ahci-block`, `--nvme-block`, `--virtio-net`, `--xhci` jsou historické vývojové přírůstky a technický dluh, nikoliv povolený vzor. Dřívější důkazy platí pouze pro tehdejší revize a scénáře; neprokazují plnou funkčnost běžného OS.

Odstraň jejich přejímací logiku z produkčního kódu, převeď testy na běžná rozhraní a dokonči obecnou provozní implementaci. Nápravu základů sleduje milník 3.2 a nápravu ovladačů etapa 4 v plánu. Před rozšiřováním závislých funkcí oprav jejich základy. Zachovej sílu dřívějších testů, nikoliv jejich testovací mechanismus uvnitř OS. Samotný zápis těchto pravidel není důkazem opravy kódu.
