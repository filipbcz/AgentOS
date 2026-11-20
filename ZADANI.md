# AgentOS — technické zadání operačního systému

Finální název operačního systému je **AgentOS**. Odkazuje na propojení AI agentů se službami a oprávněními operačního systému.

## 1. Záměr projektu

Cílem je vytvořit vlastní moderní 64bitový operační systém s vlastním jádrem, který bude:

- rychlý a předvídatelný,
- jednoduchý na pochopení, sestavení a údržbu,
- nenáročný na operační paměť, úložiště a výkon procesoru,
- bezpečný díky izolaci procesů a použití paměťově bezpečného jazyka,
- založený na otevřených hardwarových standardech,
- postupně schopný spouštět existující linuxové programy bez rekompilace.

Systém nemá být kopií Linuxu ani univerzální náhradou všech současných desktopových systémů. Má mít vlastní vnitřní architekturu a pouze samostatnou kompatibilní vrstvu pro linuxové uživatelské ABI.

## 2. Základní rozhodnutí

| Oblast | Rozhodnutí |
|---|---|
| První platforma | `x86_64`, UEFI, ACPI, PCI/PCIe |
| Typ jádra | Modulární monolitické jádro |
| Hlavní jazyk | Rust `no_std` |
| Nízkoúrovňový kód | Minimální množství assembleru pouze tam, kde je nezbytný |
| Spouštění | Jeden podepsaný obraz EFI obsahující vlastní bootloader, jádro ve formátu ELF a initramfs |
| Uživatelský prostor | Vlastní stabilní ABI a oddělená kompatibilní vrstva Linux ABI |
| Cílové platformy | Oracle VirtualBox na tomto notebooku a přímý start na HP ProBook 460 G11 |
| Licence | Bude stanovena před zveřejněním první verze |

Modulární monolitické jádro je zvoleno kvůli nízké režii a jednoduchému běhu. Subsystémy a ovladače musí být přesto oddělené jednoznačnými interními rozhraními, aby je bylo možné testovat, nahrazovat a případně později přesouvat do uživatelského prostoru.

## 3. Rozsah první stabilní verze

První stabilní verze musí poskytovat:

- systémové rozhraní pro AI agenty a možnost z konzole zadat, sledovat a zastavit skutečnou agentní úlohu podle § 4.6,
- start přes UEFI bez závislosti na BIOSu,
- samostatnou instalaci na interní NVMe a start z tohoto disku po odebrání instalačního média,
- běh na vícejádrových procesorech `x86_64`,
- virtuální paměť a izolaci uživatelských procesů,
- preemptivní plánování vláken,
- souborový systém, konzoli, časovače a základní IPC,
- šifrovaný datový oddíl s lokálním odemčením při startu a ověřenou obnovou přístupu podle § 6.1,
- detekci zařízení přes ACPI a PCI/PCIe,
- standardní úložiště, vstupní zařízení, obrazový výstup a síť,
- načítání 64bitových ELF programů,
- textový terminál s interaktivním shellem jako hlavní uživatelské prostředí,
- spuštění vybraných staticky sestavených linuxových programů pro `x86_64` bez jejich změny.

Grafické desktopové prostředí, Wi-Fi, Bluetooth, zvuk, kontejnery, virtualizace a úplná kompatibilita s distribucemi Linuxu nejsou součástí první stabilní verze.

### Terminál a návaznost budoucího GUI

První vydání se sestaví a spustí bez grafického serveru. Na notebooku vykresluje znaky konzole do GOP framebufferu. Ve VirtualBoxu je terminál dostupný také přes COM1. Z textového prostředí musí uživatel zvládnout celý běžný provoz včetně odemčení a přihlášení, práce se soubory, správy služeb, aktualizací a schvalování požadavků agentů. Příkazové nástroje musí fungovat i ve skriptech přes standardní vstup, výstup, chybový výstup a návratové kódy. Citlivé interaktivní potvrzení zůstává v důvěryhodné relaci podle § 8.

Pro budoucí GUI se už nyní oddělí tři odpovědnosti. Shell a aplikace pracují s terminálovým rozhraním (TTY). Obsluha klávesnice předává vstupní události odděleně od jejich převodu na znaky. Zobrazení textu do framebufferu zajišťuje samostatná část konzole. Systémové služby nabízejí operace a výsledky přes dokumentované rozhraní nezávislé na podobě obrazovky. Budoucí grafický klient tak může například zobrazit žádost agenta a předat rozhodnutí téže službě se stejným ověřením identity a oprávnění. Údaje zobrazené terminálem nemusí zpětně načítat z textu.

Budoucí správce obrazovky a vstupu poběží jako služba v uživatelském prostoru. Návrh rozhraní zařízení musí umožnit výslovné předání a vrácení výhradního přístupu k displeji a vstupu oprávněné relaci. Textová konzole zůstane dostupná jako samostatné prostředí pro správu a obnovu. Volba grafického protokolu a vykreslování patří až do zadání grafické verze.

### Referenční konfigurace

| Součást | Oracle VirtualBox 7.1.12 na Windows | HP ProBook 460 16 inch G11 Notebook PC |
|---|---|---|
| CPU a paměť | x86-64, I/O APIC, 2 vCPU, 256 MiB RAM; funkční test také s 1 vCPU | Intel Core Ultra 7 155H |
| Start a obraz | EFI64, VMSVGA, výstup do GOP framebufferu | UEFI, interní displej přes GOP, Intel Arc Graphics (8086:7D55) |
| Disk | Soubor VDI přes SATA/AHCI | Pracovní Samsung MZVL21T0HCLR-00BH1 (144D:A80A) pouze pro čtení. Pro instalační a zápisové zkoušky samostatný vyhrazený interní NVMe, jehož model a řadič se uvedou v protokolu. |
| Konzole | PS/2 klávesnice, COM1 přes hostitelskou pojmenovanou rouru | Vestavěná klávesnice hlášená jako PS/2 (ACPI HPQ8002), externí USB HID přes xHCI (8086:7E7D a 8086:7EC0) |
| Síť | VirtIO-net přes PCI v režimu NAT | Kabelový Realtek PCIe GbE (10EC:8168, revize 15) |

Konfigurace notebooku vychází z inventáře Windows. Funkčnost GOP, vstupu a síťového čipu ověří až fyzický boot. Wi-Fi Intel AX211 a akcelerace grafiky jsou mimo rozsah první verze. Pro nainstalovaný VirtualBox 7.1.12 bez Extension Packu je referenčním diskovým řadičem AHCI. [Řadiče disků ve VirtualBoxu 7.1](https://docs.oracle.com/en/virtualization/virtualbox/7.1/user/storage.html)

## 4. Architektura systému

### 4.1 Bootloader

Bootloader tvoří vstupní bod aplikace EFI pro x86-64. Sestavení vloží samostatně sestavené jádro ELF, initramfs a bezpečnostně významné parametry startu do pojmenovaných datových sekcí PE/COFF. Podpis vzniká až po jejich vložení. Při každém startu proběhnou následující kroky.

1. firmware podle § 8.3 ověří obraz EFI a předá řízení jeho vstupnímu bodu. Bootloader zkontroluje aktivní Secure Boot, rozsahy a jednoznačnost vložených sekcí a meze segmentů ELF. Do cílové paměti načte jádro a initramfs výhradně z právě ověřeného obrazu v paměti. Externí initramfs, parametry z editovatelné konfigurace či EFI LoadOptions nesmějí změnit spouštěný kód ani režim zabezpečení,
2. získat adresu, rozměry, formát pixelů a délku řádku framebufferu a ukazatel na ACPI tabulky,
3. vyhradit paměť pro předávací strukturu a mapu včetně rezervy,
4. získat konečnou mapu paměti s klíčem a předat klíč do `ExitBootServices`; při neplatném klíči načíst mapu znovu a volání opakovat,
5. po úspěchu předat jádru mapu, rozsahy stále používané bootloaderem a ostatní bootovací údaje. Jádro po převzetí zapisuje přímo do framebufferu.

Pořadí posledních dvou operací vychází ze [specifikace UEFI, kapitola Boot Services](https://uefi.org/specs/UEFI/2.11/07_Services_Boot_Services.html).

Běžný provoz jádra je nezávislý na UEFI runtime službách. Aktualizační služba má úzce omezené kernelové rozhraní pro správu vlastních zaváděcích položek podle § 8.4. Formát předávaných bootovacích informací musí být stabilní a nezávislý na konkrétním bootloaderu.

### 4.2 Jádro

Jádro bude rozděleno nejméně na tyto subsystémy:

- architektura procesoru a přerušení,
- správa fyzické a virtuální paměti,
- plánovač procesů a vláken,
- systémová volání,
- IPC a synchronizace,
- VFS a souborové systémy,
- správce zařízení a ovladače,
- síťová vrstva,
- bezpečnost a oprávnění,
- diagnostika a strukturované logování,
- linuxová kompatibilní vrstva.

Závislosti mezi subsystémy musí být jednosměrné a výslovné. Ovladače nesmějí přímo používat interní stav plánovače, VFS ani správce paměti mimo jejich veřejná kernelová rozhraní.

#### Životní cyklus služeb

Správu uživatelských služeb zajišťuje první proces (PID 1) z ověřeného initramfs. Spouští služby podle závislostí, přebírá ukončené potomky a po pádu služby zaznamená příčinu. Připravenost služba hlásí přes IPC po úspěšném funkčním ověření. Pro potvrzení aktualizace jsou kritické správce služeb, přístup k odemčenému zapisovatelnému datovému svazku, služba účtů a přihlášení přijímající vstup. Pád kterékoli z nich během zkušebního startu před potvrzením tento pokus zamítne. Při běžném provozu PID 1 omezeně opakuje start selhané služby s prodlevou a po vyčerpání pokusů nabídne diagnostiku. Výpadek sítě nebo modelu neblokuje lokální správu. Při vypnutí i restartu PID 1 zastaví příjem nové práce, ukončí služby v opačném pořadí závislostí, vyčká na dokončení zápisů, synchronizuje a odpojí ext4 a uzavře LUKS2. Chybu zápisu ohlásí před vypnutím.

### 4.3 Paměť

Správa paměti musí zahrnovat:

- detekci a evidenci fyzické paměti,
- efektivní alokátor fyzických stránek,
- čtyřúrovňové stránkování `x86_64`,
- oddělený adresní prostor každého procesu,
- nepřístupnou nulovou stránku,
- NX a W^X ochranu,
- uživatelský a kernelový zásobník s ochrannou stránkou,
- demand paging a copy-on-write pro procesy,
- evidenci paměti přidělené pro DMA po celou dobu, kdy s ní zařízení může pracovat.

Kernelový heap nesmí být vyžadován během nejranější fáze startu. Alokace v kritických cestách musí být omezené a měřitelné.

### 4.4 Procesy a plánování

Plánovač bude preemptivní, SMP a tickless. Každé CPU bude mít vlastní frontu spustitelných vláken; vyvažování zátěže proběhne řízeným přesunem úloh mezi CPU. Návrh nesmí vyžadovat jeden globální zámek plánovače.

Proces musí mít vlastní:

- virtuální adresní prostor,
- tabulku popisovačů prostředků,
- identitu a oprávnění,
- jedno nebo více vláken,
- stav signálů a návratový kód.

Základní synchronizační prostředky budou mutex, spinlock, semaphore, event/wait queue a futex pro uživatelský prostor.

### 4.5 Uživatelské ABI

Vlastní systémová volání musí mít verzované a dokumentované ABI. Aplikace nesmějí být závislé na interních strukturách jádra.

Linuxová kompatibilita bude překládat linuxová systémová volání na vlastní kernelové operace. Nebude tvořit základ vnitřní architektury jádra. První kompatibilní profil bude:

- Linux `x86_64` syscall ABI,
- staticky linkované ELF programy,
- programy sestavené proti `musl`,
- základní souborové, procesní, paměťové, časové a terminálové operace,
- vlákna a synchronizace přes `clone` a `futex`,
- sockety a `epoll` po dokončení síťového subsystému.

Další profil může přidat dynamický linker, sdílené knihovny a širší kompatibilitu s glibc. Kompatibilita se bude určovat automatickými testy konkrétních syscallů, nikoliv pouze tím, že se aplikace spustí.

Pro první testovací sadu je vstupním formátem statický ELF64 `ET_EXEC` pro x86-64 bez segmentu `PT_INTERP`. Běžný neoznačený ELF v tomto profilu používá Linux ABI. Vlastní programy používající nativní ABI ponesou explicitní identifikátor v ELF note. Loader ověří rozsahy segmentů, vynuluje oblast BSS a připraví vstupní zásobník Linux ABI včetně zarovnání, argumentů, prostředí a pomocného vektoru `auxv`. Pro vícevláknový test zajistí také lokální úložiště vláken a správnou bázi registru FS při přepnutí vlákna. Neznámé číslo linuxového systémového volání vrátí `-ENOSYS`.

### 4.6 Spolupráce OS s AI agenty

Přihlášený uživatel může agentovi zadat úkol v přirozeném jazyce a vybrat prostředky, se kterými smí pracovat. Například při hledání příčiny výpadku služby může zpřístupnit stav služby, posledních 100 záznamů jejího provozního logu a cílový soubor pro zprávu. Agent si stav a záznamy vyžádá přes systémové rozhraní, spojí závěr s konkrétními záznamy a uloží zprávu. Uživatel může ve stejné konzoli sledovat provedené operace, přečíst výsledek nebo úkol zastavit.

**Rozhraní pro více agentů.** Služba v uživatelském prostoru poskytne dokumentovaný, verzovaný protokol přes lokální IPC. Vestavěný klient i samostatně vytvořený agent používají stejné operace pro převzetí úkolu, zjištění dostupných nástrojů, jejich volání, průběžné hlášení, dokončení a zrušení. Každý nástroj má popsané vstupy, výstupy, chyby a požadovaná práva. První sada poskytne čtení stavu služby, odběr jejích událostí, přístup k vybraným souborům a zápis výsledku. Událost může probudit čekající úlohu v mezích jejího původního zadání. Při předání práce druhému agentovi OS zaznamená oba účastníky a omezí příjemce na stejná nebo užší oprávnění.

**Oprávnění úlohy.** Konzole před spuštěním ukáže identitu agenta, vybrané objekty, povolené operace a případný cíl pro přenos dat. OS spouští agenta pod izolovanou identitou a předává mu časově omezené popisovače svázané s úlohou. Rozsah práv je průnikem práv uživatele a uděleného pověření. Omezení platí také pro přímá systémová volání, potomky procesu a síťová spojení. Obsah souboru, zpráva druhého agenta ani výstup modelu nemohou měnit pověření. Rozšíření rozsahu potvrzuje uživatel v důvěryhodné konzoli. Správcovský zásah dále vyžaduje ověření podle § 8.2. Po zrušení úkolu systém odebere oprávnění i delegovaným agentům, ukončí odběry a zobrazí, které změny již proběhly. Audit uchová identitu uživatele a agenta, cíl operace a její výsledek. Výchozí audit vynechá obsah souborů a konverzací.

**Provoz modelu.** Správce může nastavit poskytovatele modelu na vlastním serveru nebo u externí služby. Stejné rozhraní umožní připojit místní modelový proces, pokud pro něj zařízení má dostatek paměti. Odeslání dat mimo zařízení vyžaduje pověření pro konkrétní zdroje a cílového poskytovatele. Spojení zajišťuje samostatná služba s TLS a ověřením identity serveru. Přístupové údaje spravuje mimo dosah agentů a předávaného kontextu. Služby pro AI se aktivují na vyžádání po přihlášení. Boot, přihlášení i běžná správa fungují offline. Ve VM s 256 MiB se skutečná agentní úloha ověří s modelem na druhém stroji. Pro aktivní úlohu se změří zvlášť paměť a čas na straně OS a čas čekání na model. Úloha má nastavitelnou mez paměti, času a počtu požadavků, po jejímž dosažení vrátí konkrétní stav.

#### 4.6.1 Spojení a zjišťování nástrojů

Verze 1 používá systémový IPC kanál se zachovanými hranicemi zpráv. Jedna zpráva obsahuje jeden objekt JSON v UTF-8. Požadavek má pole `id`, `method` a `params`. Odpověď zopakuje `id` a obsahuje buď `result`, nebo `error` se stabilním strojovým kódem a popisem. První volání `session.open({versions:[1]})` vrátí dohodnutou verzi, maximální velikost zprávy a identitu klienta odvozenou jádrem z IPC spojení. Pokud společná verze chybí, služba vrátí `unsupported_version`. Identifikátory úloh a objektů vydává OS. Znalost identifikátoru sama o sobě nezakládá právo.

| Volání | Odpověď a význam pro klienta |
|---|---|
| `tools.list(task_id, cursor?)` | Stránka nástrojů viditelných pro tuto úlohu, revize katalogu a případný další kurzor. Položka uvádí stabilní ID, verzi, účel, vedlejší účinky a stav `granted` nebo `requestable`. Politika může nástroj zcela skrýt. |
| `tools.describe(task_id, tool_id, version)` | Schéma argumentů a výsledku, požadované operace nad objekty, omezení rozsahu a možné chyby. První verze používá JSON Schema 2020-12. |
| `tools.call(task_id, tool_id, version, arguments)` | Služba ověří schéma, identitu řešitele, konkrétní objekty a aktuální práva. Oprávnění k nástroji může platit jen pro jediný soubor či službu. Chybějící pověření vrátí `permission_required`, odvolané `revoked`, neplatné argumenty `invalid_arguments`. |

Například katalog může pro daný úkol nabídnout nástroj `service.events.read` s přístupem k posledním 100 záznamům jedné služby a `file.write` s právem zápisu pouze do cílové zprávy. Po změně katalogu služba zneplatní starý kurzor, vrátí `catalog_changed` a klient obnoví seznam. Změna oprávnění se vynucuje okamžitě i při použití staršího popisu nástroje.

V zápisu metod výše i níže odpovídají názvy parametrů klíčům objektu `params`. Klient například načte popis nástroje touto zprávou:

```json
{"id":"req-17","method":"tools.describe","params":{"task_id":"task-42","tool_id":"service.events.read","version":1}}
```

#### 4.6.2 Předávání práce

1. `agents.list(task_id)` vrátí identifikátory dostupných a povolených příjemců s popisem jejich schopností. Řešitel zavolá `tasks.delegate(task_id, recipient_id, goal, input_refs, scope, deadline)`. Služba ověří každou předávanou referenci, právo ji delegovat, rozsah operací, dobu platnosti a zbývající rozpočet. Požadavek přesahující některou mez odmítne jako `scope_exceeded`.
2. Služba vytvoří podúlohu se stavem `offered` a vrátí její ID. Určený příjemce získá nabídku přes `tasks.inbox()` a zavolá `tasks.accept(child_id)` nebo `tasks.decline(child_id)`. Přijetí atomicky nastaví jediného řešitele a stav `running`. Teprve nyní obdrží povolený vstup a vlastní odvolatelné popisovače. Nepřijatá nabídka po termínu přejde do `expired`. Tento postup platí i pro první úkol zadaný z konzole.
3. Řešitel hlásí postup přes `tasks.progress` a odevzdá výsledek přes `tasks.complete(child_id, result_refs)`, případně chybu přes `tasks.fail`. Zadavatel čte stav a výsledek přes `tasks.get(child_id)`. Výstupní reference smějí označovat pouze výsledky povolené ke sdílení se zadavatelem. Terminální stav uzavře pověření řešitele. Při `tasks.cancel(task_id)` se uzavřou také všechny odvozené nabídky a pověření. Rozpracovaná operace znovu ověří jejich platnost před nevratným účinkem. Již dokončené účinky zůstanou v přehledu úlohy.

U operací s vedlejšími účinky klient předává také `operation_id`. Služba pro tutéž identitu a úlohu rozpozná opakování po ztrátě odpovědi a vrátí původní ID nabídky, žádosti nebo známý výsledek. Použití téhož klíče pro odlišný obsah odmítne jako `conflict`. Při neurčitém výsledku externí operace vrátí `outcome_unknown` a operaci automaticky neopakuje.

#### 4.6.3 Žádost o oprávnění

Agent zavolá `permissions.request(task_id, tool_id, scope, reason, expires_at)`. Rozsah určuje operaci, identitu cílového objektu a případně povolený počet záznamů, zdroj dat a síťového příjemce. OS ihned vrátí ID žádosti a stav `pending`, nebo ji zamítne podle politiky. Agent může přes `permissions.get(request_id)` zjistit výsledek i po obnovení spojení.

Důvěryhodná konzole zobrazí uživatele, agenta, řetězec delegování, požadovanou změnu proti současným právům a dobu platnosti. Text zdůvodnění je označen jako sdělení agenta. Rozhodnout může pouze oprávněný uživatel prostřednictvím konzole. Může žádost zamítnout nebo udělit konkrétní operaci jednou či do určeného času. Schválený rozsah vždy zůstane v mezích práv uživatele, politiky OS a u podúlohy také rozsahu povoleného rodičem. Širší delegování vyžaduje změnu rodičovského pověření a nové předání rozsahu potomkovi. Správcovská akce dále podléhá § 8.2.

Schválení vrátí stav `granted` s přesným rozsahem. Vlastní akci agent provede až samostatným voláním nástroje. Jednorázové právo služba při přijetí operace atomicky rezervuje pro její `operation_id`, aby dva souběžné požadavky nemohly provést dva zápisy. Zamítnutí, vypršení nebo zrušení se projeví jako `denied`, `expired` nebo `revoked`. Čekající žádost zrušené úlohy už konzole nemůže schválit. Audit spojuje úlohu, žádost, rozhodnutí a provedenou operaci jejich identifikátory.

## 5. Model ovladačů

Ovladače budou implementovat veřejné specifikace zařízení. Nebudou přebírány binární linuxové ovladače ani napodobováno nestabilní interní API linuxového jádra.

Každý ovladač musí být oddělen na:

1. hardwarově nezávislou logiku,
2. přístup k registrům zařízení,
3. napojení na kernelový subsystém,
4. správu přerušení a DMA,
5. testovatelný stavový automat.

`unsafe` kód musí být uzavřen v nejmenší možné vrstvě pro MMIO, portové I/O, přerušení a DMA. Vyšší logika ovladače má zůstat v bezpečném Rustu.

### 5.1 Pořadí standardních rozhraní

Ovladače a hardwarové vrstvy budou vznikat v tomto pořadí:

1. UEFI GOP framebuffer a textová konzole,
2. sériová konzole 16550 pro diagnostiku,
3. ACPI, Local APIC, I/O APIC a časovače,
4. PCI a PCI Express včetně MSI/MSI-X,
5. SATA/AHCI pro virtuální disk a NVMe pro interní disk notebooku,
6. vstup z klávesnice PS/2 na obou platformách,
7. VirtIO-net přes PCI pro kabelovou síť ve VM,
8. xHCI a USB HID pro klávesnici a myš,
9. USB Mass Storage,
10. ovladač pro zjištěnou revizi kabelového adaptéru Realtek na notebooku.

Pro adaptér Realtek se před implementací ověří dokumentace konkrétní varianty čipu. Samotná podpora Ethernetu v síťové vrstvě pro obsluhu PCI řadiče nestačí.

### 5.2 DMA a bezpečnost zařízení

Ovladač získává adresu pro zařízení z DMA rozhraní, které rozlišuje virtuální adresu CPU, fyzickou adresu a adresu viditelnou zařízením. Mapování zohledňuje adresní omezení zařízení a koherenci cache. Před uvolněním bufferu musí ovladač ověřit dokončení přenosu nebo zastavit DMA, a to i po timeoutu. Základní profil důvěřuje připojeným DMA zařízením. Hardwarovou izolaci lze deklarovat pouze na konfiguraci s aktivním a ověřeným překladem přes IOMMU. [Adresy a mapování DMA](https://docs.kernel.org/core-api/dma-api-howto.html)

Chyba jednoho zařízení nesmí způsobit nekonečné čekání jádra. Každá operace vůči hardwaru musí mít konečný timeout a diagnostikovatelný výsledek.

## 6. Úložiště a souborové systémy

Disky budou používat GPT. EFI systémový oddíl bude FAT32. Běžný systém nesmí ukládat provozní data přímo do EFI oddílu.

Pro trvalá data se použije **ext4 s interním žurnálem JBD2**. Stejný formát bude na datovém oddílu testovacího VDI ve VirtualBoxu a na vyhrazeném USB i interním NVMe notebooku. Kořen při startu poskytne read-only initramfs. VFS zpřístupní datový oddíl v `/data` a zachová jednotný model souborů, adresářů, zařízení, rour a socketů.

Ext4 poskytuje vlastnictví, přístupová práva a odkazy potřebné pro linuxové aplikace. Formát lze vytvořit pomocí `mke2fs`, připojit v Linuxu a nezávisle zkontrolovat nebo opravit pomocí `e2fsck`. To umožní porovnat chování vlastního ovladače s další implementací. [Dokumentace formátu ext4](https://docs.kernel.org/filesystems/ext4/)

**Profil první verze.** Obraz používá bloky 4 KiB, extenty a interní žurnál v režimu `data=ordered`. Recept pro vytvoření obrazu výslovně určí verzi nástrojů, velikost inode a úplný seznam zapnutých příznaků ext4 a JBD2. Ovladač plně obslouží všechny vlastnosti tohoto profilu včetně obnovy po pádu. Před prvním zápisem nebo přehráním žurnálu ověří, že formátu rozumí. Svazek mimo podporovaný profil odmítne s popisem důvodu a ponechá jej beze změny. Bloková cache se započítá do paměťového limitu dle § 9 a musí umět vrátit čisté stránky při nedostatku paměti.

**Zápis a obnova.** Přes VFS musí fungovat čtení, zápis, zkrácení, vytváření a mazání souborů i adresářů, atomické přejmenování na témže svazku, pevné a symbolické odkazy, vlastnictví a oprávnění. Žurnál zajišťuje konzistenci metadat. Při `fsync` souboru musí ovladač zajistit trvalé uložení jeho změn až na blokové zařízení a předat případnou chybu aplikaci. Pro trvalost nového jména aplikace synchronizuje také nadřazený adresář. Po nečistém odpojení ovladač dokončí obnovu žurnálu před zpřístupněním svazku pro zápis. [Žurnál ext4 a pořadí zápisů](https://docs.kernel.org/filesystems/ext4/journal.html)

### 6.1 Šifrování datového oddílu a obnova přístupu

Na obou platformách bude datový oddíl GPT obsahovat **LUKS2**. Po odemčení poskytne šifrovací vrstva blokové zařízení pro ext4. Šifrují se tím obsah souborů, názvy, metadata, žurnál i databáze účtů. Zaváděcí oddíl FAT32, jádro a initramfs zůstávají čitelné a obsahují pouze veřejné součásti systému. Cílem je důvěrnost vypnutého média. Režim XTS sám neověřuje pravost sektorů ani zaváděcího kódu. Běžící či uložená odemčená VM obsahuje citlivý stav také v paměti hostitele.

**Příprava svazku.** Každá instalace vygeneruje kryptograficky bezpečným generátorem vlastní náhodný 512bitový klíč pro `aes-xts-plain64` (dva klíče AES-256). Reprodukovatelný distribuční obraz končí před touto inicializací. Dva nezávislé sloty LUKS2 chrání tentýž klíč svazku. První odemyká uživatelem zvolená dlouhá fráze, druhý náhodný obnovovací kód s alespoň 128 bity entropie ve formátu vhodném k ručnímu zadání. Vlastník uloží kód odděleně od zařízení a při inicializaci potvrdí jeho správný přepis. Recept svazku stanoví podporovanou velikost šifrovaného sektoru a parametry Argon2id pro sloty. Parametry se ověří včetně špičkové spotřeby RAM ve VM s 256 MiB. Před odvozením klíče se zkontrolují meze z hlavičky. Pro kryptografické operace se použije prověřená knihovna. [Formát a správa klíčů LUKS](https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/FAQ.md)

**Start.** Po předání řízení jádru spustí initramfs lokální výzvu k odemčení svazku. Zadávání má skrytou odezvu a zobrazuje aktivní rozložení klávesnice. Fráze i kód musí fungovat na podporované klávesnici notebooku i ve VM. Po ověření údaje systém otevře šifrovací vrstvu, případně obnoví žurnál ext4, připojí `/data`, načte databázi účtů a zobrazí přihlášení podle § 8.1. Chybný údaj ponechá svazek zamčený a umožní opakovat zadání. Chyba hlavičky nebo neznámý profil ukončí běžný start s diagnostikou, bez formátování či zápisu na oddíl. Odemčení samo neotevírá uživatelskou relaci. Po odhlášení zůstává svazek dostupný službám. Při řádném vypnutí se nejdříve synchronizuje a odpojí ext4, poté uzavře mapování a vymažou klíče z pracovní paměti. Fráze a pomocné klíče se vymažou ihned po použití. Tajné údaje se neukládají do logů, výpisů při pádu ani bootovacího obrazu.

**Zapomenutá fráze.** Na stejné výzvě vlastník zvolí odemčení obnovovacím kódem. Pro nastavení nové fráze ji nástroj zapíše do volného slotu a ověří samostatné odemčení novým údajem. Teprve pak odstraní původní slot. Stejné pořadí platí pro výměnu obnovovacího kódu. Přerušení změny musí zachovat alespoň jednu ověřenou cestu k datům. Klíč pro obnovu správcovského účtu podle § 8.1 je jiný údaj a jeho ověřovací hodnota leží uvnitř odemčeného svazku. Při ztrátě všech platných údajů ke svazku zbývá obnova dat z nezávislé zálohy.

**Poškozená hlavička.** Při inicializaci a po změně slotů se vytvoří aktuální záloha hlavičky včetně oblasti klíčových slotů a označí se UUID svazku. Uloží se chráněně mimo zařízení. Postup obnovy z důvěryhodného média ověří přiřazení zálohy ke konkrétnímu svazku a nejprve vyzkouší odemčení a čtení na jeho kopii. K odemčení je třeba i údaj platný v okamžiku zálohy. Starší hlavička proto může zpřístupnit stejná data i dříve odebranou frází. Po rotaci správce vyřadí staré kopie hlavičky. Při možném úniku staré hlavičky spolu s platným údajem se data převedou na svazek s novým náhodným klíčem. Samotná záloha hlavičky neobnoví poškozený obsah souborů. [Záloha a vlastnosti hlavičky LUKS](https://man7.org/linux/man-pages/man8/cryptsetup-luksheaderbackup.8.html)

### 6.2 První instalace a pokračování po výpadku

Podepsané instalační médium zobrazuje dostupná zařízení, jejich model, kapacitu, stabilní identifikátor a existující oddíly. Instalační profil používá celý výslovně vybraný prázdný disk. Před prvním zápisem vlastník na lokální konzoli potvrdí jeho identitu a instalátor ji znovu ověří na otevřeném zařízení. Zdrojové médium, cizí instalace a disky s uživatelskými daty nejsou cílem automatické inicializace. Při fyzické přejímce se pracovní NVMe s Windows vyjme a nahradí vyhrazeným diskem. Souběžná přítomnost jiného disku se ověří ve VM pomocí druhého VDI s kontrolním obsahem.

Po ověření náhodnosti podle § 8.5 instalátor založí GPT, oddíl EFI s místem pro obě vydání a datový oddíl LUKS2. Uvnitř vytvoří ext4, založí prvního správce a dokončí předání obou různých obnovovacích údajů. Instalátor vede na cíli trvalý záznam dokončených fází svázaný s identitou disku a instalace. Po přerušení porovná záznam se skutečným stavem GPT, LUKS2, ext4 a účtů. Pokračovat smí jen po ověření cíle a zachování již vytvořených dat. Nejednoznačný stav předá lokální obnově. Existující svazek vyžaduje odemčení vlastníkem. Běžný start nesmí přepnout do inicializace účtů. Zavádění označí instalátor jako dokončené až po ověření podepsaného obrazu, čitelnosti dat a dokončení účtů.

### 6.3 Záloha a obnova celého média

Správce může ze servisního média připojit čistě odpojené zdrojové ext4 pouze pro čtení a vytvořit úplnou zálohu na jiném šifrovaném médiu s nezávislým odemykacím údajem. Záloha zahrnuje uživatelská data, účty a skupiny s původními UID/GID, konfiguraci služeb a důvěry, oprávnění, časy, pevné i symbolické odkazy a stav nutný pro obnovu účtů. Manifest zaznamená verzi systému a umožní autentizovaně ověřit obsah i metadata zálohy před jejich použitím. Dokončená záloha musí jít obnovit s přístupem k záloze a důvěryhodnému servisnímu médiu i při úplné ztrátě původního disku.

Na prázdném náhradním médiu se vytvoří nový LUKS2 svazek s novým klíčem a vlastním obnovovacím údajem. Servisní prostředí obnoví data včetně metadat a nainstaluje kompatibilní, stále povolené podepsané vydání. Před aktivací ověří manifest i dokončení obnovy. Přerušená či porušená záloha nesmí být označena za úspěšně obnovený systém.

## 7. Síť

Síťová vrstva musí být nezávislá na ovladači síťové karty. První verze bude podporovat:

- Ethernet,
- ARP,
- IPv4,
- ICMP,
- UDP a TCP,
- DHCP klienta,
- DNS klienta,
- loopback rozhraní,
- základní firewall s výchozím zákazem nevyžádaného příchozího provozu.

IPv6 bude součástí návrhu rozhraní, ale jeho úplná implementace nemusí blokovat první použitelnou verzi.

## 8. Bezpečnost

Pro spojení se serverem modelu používá klient správně nastavený čas UTC, ověření doby platnosti řetězce a shody DNS jména (při použití IP odpovídající IP SAN). Systémové kořeny pocházejí z podepsaného vydání. Správce může po opětovném ověření identity přidat či odebrat vlastní důvěryhodnou CA pro konkrétní koncový bod. Její otisk nejprve ověří nezávislým kanálem. Po startu systém ověří věrohodnost času z RTC vůči uložené poslední důvěryhodné hodnotě. Při zjevně nesprávném nebo neurčeném čase vyžádá opravu správcem či synchronizaci z důvěryhodného zdroje. Do úspěšného ověření TLS neodešle aplikační kontext ani přístupové údaje. Pro časové limity a životnost běžících úloh používá monotónní hodiny.

Povinné vlastnosti:

- oddělení kernelového a uživatelského režimu,
- žádné spouštění zapisovatelných stránek,
- validace všech ukazatelů a délek předaných uživatelem,
- capability-like popisovače prostředků bez globálně přístupných kernelových objektů,
- princip nejnižších oprávnění,
- bezpečné výchozí nastavení sítě,
- deterministický pád konkrétního procesu místo poškození jádra,
- audit všech bloků `unsafe`,
- ochrany procesoru dostupné na cílovém hardwaru, zejména NX, SMEP a SMAP.

Pro první stabilní vydání jsou povinné Secure Boot i ověřování aktualizací podle § 8.3 a § 8.4.

### 8.1 Lokální účty a přihlášení

Při přípravě nové instalace vlastník z lokální konzole jednorázově založí pojmenovaný správcovský účet a zvolí heslo. Při běžném startu systém otevře přihlašovací výzvu. Služba v uživatelském prostoru ověří heslo a až po úspěchu spustí shell s identitou účtu. Odhlášení uzavře interaktivní relaci a vrátí konzoli k přihlášení. Síťové přihlášení je ve výchozím stavu vypnuté.

Databáze účtů je na trvalém úložišti. Ověřovací hodnoty může číst pouze pověřená služba a změny provádí autorizovaná správa účtů. Pro každé heslo se uloží výsledek Argon2id, jedinečná kryptograficky náhodná sůl a parametry výpočtu. Použije se prověřená implementace s testovacími vektory. Parametry a limit souběžných ověření se ověří měřením času a špičkové paměti na referenční VM s 256 MiB. Konzole heslo při zadávání nezobrazuje. Opakované neúspěšné pokusy služba časově omezuje i při opětovném otevření výzvy. [Argon2id a testovací vektory, RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html)

Poškozená nebo chybějící databáze při běžném startu zablokuje přihlášení. Její absence nesmí zpřístupnit založení nového správce. Pro obnovu vlastník při inicializaci dostane náhodný obnovovací klíč k uložení mimo notebook. Režim obnovy na lokální konzoli ověří klíč vůči ověřovací hodnotě uložené odděleně od databáze účtů. Teprve potom povolí obnovit přístup správce.

### 8.2 Vynucování práv a správa

Jádro přiřadí procesu UID, primární GID a doplňkové skupiny a kontroluje změny identity. Nativní rozhraní i Linux ABI používají stejné kontroly VFS podle vlastníka, skupiny a bitů čtení, zápisu a spuštění na ext4. Při průchodu cestou se kontroluje právo průchodu každým adresářem. Při vytvoření, odstranění či přejmenování položky se ověří práva k dotčeným nadřazeným adresářům. Domovský adresář nového účtu má režim `0700`. Jádro kontroluje také přístup k zařízením a operace nad procesy jiných uživatelů.

Správce po přihlášení pracuje s běžnými právy. Pro změnu účtů, konfiguraci firewallu či přímý zápis na blokové zařízení pověřená služba ověří správcovskou roli a opětovně ověří identitu správce. Oprávnění platí pro vyžádanou operaci a její cíl. Systémové služby mají oddělené identity a jen prostředky potřebné k jejich práci. Chráněný auditní log zaznamená přihlášení, zvýšení oprávnění a změny účtů včetně času, výsledku a dotčené identity. Hesla, jejich ověřovací hodnoty a obnovovací klíče se do logů nezapisují.

Přístup procesů po odemčení dat řídí jádro podle výše uvedených pravidel. Před odemčením chrání data na médiu povinné šifrování podle § 6.1.

### 8.3 Secure Boot a obnova důvěry

Na obou referenčních platformách se vyžaduje UEFI v režimu vynucování podpisů (`SecureBoot=1`, `SetupMode=0`). Firmware před spuštěním ověří podpis PE/COFF Authenticode (SHA-256, RSA) vůči povoleným položkám `db` a zákazům `dbx`. Podpis pokrývá kód bootloaderu i sekce s jádrem, initramfs a parametry. Každá z těchto součástí tak získá stejný původ a patří ke stejnému vydání. Privilegovaný kód raného startu a výzva LUKS2 mohou pocházet pouze z tohoto ověřeného obsahu. Při odmítnutí obrazu z něj nesmí proběhnout žádný vstup ani výzva k zadání tajného údaje. Obnovovací médium podléhá stejnému ověření. [UEFI Secure Boot a databáze podpisů](https://uefi.org/specs/UEFI/2.10_A/32_Secure_Boot_and_Driver_Signing.html)

Ve VirtualBoxu se použije samostatné úložiště EFI proměnných testovací VM. Na HP se před nasazením ověří, zda jeho firmware dovoluje přidat veřejný podpisový certifikát projektu do `db` při zachování továrních klíčů, aktuálního `dbx` a startu Windows. Před plánovanou změnou důvěry musí vlastník mít k dispozici obnovovací údaje Windows, pokud je disk chráněn BitLockerem. Schopnost konkrétního firmwaru se potvrdí fyzickou zkouškou. Testovací podpisy zůstanou omezené na vyhrazený testovací profil. [Správa Secure Bootu ve VirtualBoxu 7.1](https://docs.oracle.com/en/virtualization/virtualbox/7.1/user/vboxmanage.html)

Soukromý klíč pro podpis EFI zůstává v odděleném podpisovém prostředí. Při rotaci správce nejprve přidá nový veřejný certifikát a ověří start nově podepsaného provozního i obnovovacího obrazu. Teprve potom odvolá původní důvěru. Bezpečnostně zakázaný obraz se zablokuje jeho UEFI hashem v `dbx`, při kompromitaci podepisujícího klíče se zablokuje odpovídající certifikát. Provede se autorizovaná aktualizace databáze firmwaru. Samotný podpis prokazuje původ obrazu; starší platně podepsaný obraz lze spustit přímo z jiného média, dokud jej politika firmwaru přijímá.

### 8.4 Podepisování a instalace aktualizací

Vydání obsahuje hotový podepsaný obraz EFI a manifest s jednoznačným identifikátorem systému, architekturou, rostoucím pořadovým číslem vydání, délkou a SHA-256 distribuovaného souboru. Vydavatel podepíše přesné bajty manifestu samostatným klíčem Ed25519. Veřejný klíč je součástí ověřeného systémového obrazu a mění se prostřednictvím nového důvěryhodného vydání. Při kompromitaci klíče se důvěra obnoví z ověřeného servisního média s novým klíčem. Soukromé klíče nejsou součástí zdrojů, distribučního obrazu ani cílového stroje. Stejná trojice (identita systému, architektura, pořadové číslo vydání) je jednoznačně zakódována v povinné datové sekci EFI kryté podpisem Authenticode. Před zápisem do neaktivního umístění aktualizátor ověří i podpis samotného EFI vůči přípustné důvěře projektu, platnou revokační politiku a přesnou shodu této trojice s podepsaným manifestem. Verzi kandidáta i potvrzeného vydání odvozuje z ověřeného obrazu.

Po autorizaci správce aktualizační služba ověří podpis manifestu, cílový systém, architekturu, pořadí verze a přesnou shodu celého obrazu. Pro příjem z USB i ze sítě platí stejná pravidla. Běžná instalace přijme pouze novější vydání oproti poslednímu potvrzenému. Na systémovém médiu se udržují dvě oddělená zaváděcí umístění A/B. Služba zapíše kandidáta do neaktivního umístění, dokončí zápis na zařízení a zpětným čtením ověří délku a hash. Pak nastaví jednorázový start kandidáta pomocí `BootNext`. Dosud potvrzený obraz zůstává výchozí až do dokončení zkušebního startu.

Kandidát se potvrdí až po úspěšném ověření firmwaru, odemčení a připojení dat, spuštění přihlášení a kontrole základních služeb. Potvrzení musí být opakovatelné po výpadku a svázané s konkrétním manifestem a právě spuštěným obrazem. Správa položek zachová ostatní systémy a jejich vzájemné pořadí. Při přerušení zápisu nebo neúspěšném zkušebním startu zůstane při dalším startu dostupné poslední potvrzené vydání, pokud je politika firmwaru stále povoluje. Zkušební vydání smí do potvrzení provádět jen změny dat slučitelné s návratem. Pokud firmware odmítá oba obrazy, použije se aktuální podepsané obnovovací médium.

### 8.5 Zdroj náhodnosti při první instalaci

Jádro poskytuje jednotnou službu kryptografické náhody. Bootloader před ukončením Boot Services může získat seed z ověřeného zdroje přes EFI RNG. Na HP i ve VirtualBoxu je alternativou instrukce RDSEED, pouze pokud ji daná platforma hlásí a skutečně vrací úspěšné vzorky. Pro obě konfigurace musí protokol uvést dostupný zdroj a jeho původ, u VM včetně zajištění čerstvé entropie hostitelem. Startovací čas, identifikátor disku ani samotná přítomnost rozhraní se za zdroj entropie nepovažují.

Klíče svazků, obnovovací kódy, soli a náhodnost pro TLS se vydávají až po inicializaci prověřeného generátoru seedem s alespoň 256 bity entropie. Citlivý seed se po převzetí vymaže. Instalační běh načerpá nový seed i při opakovaném použití distribučního obrazu. Jestliže dostupnost zdroje na konkrétní platformě není prokázána nebo inicializace selže, instalace skončí před prvním zápisem na disk s konkrétní diagnostikou.

## 9. Výkonové a provozní cíle


Na referenčním virtuálním stroji se 2 CPU a 256 MiB RAM jsou cíle první stabilní verze:

- přechod od vstupu do vlastního UEFI bootloaderu k přihlašovací výzvě připravené přijmout uživatelské jméno do 1 sekundy v alespoň 19 z 20 studených startů VM, po odečtení pouze doby ručního zadávání fráze,
- běžný základní systém včetně sítě do 128 MiB RAM,
- samotné jádro a povinné struktury při nečinnosti do 32 MiB RAM,
- nulový trvalý polling zařízení, pokud zařízení podporuje přerušení,
- nečinný systém bez periodického scheduler ticku,
- žádné dynamické alokace v obsluze přerušení,
- reprodukovatelné výsledné obrazy sestavení.

Čas měří hostitel přes COM1 od první značky bootloaderu po poslední znak první přihlašovací výzvy. Služba smí výzvu vypsat až po načtení databáze účtů a aktivaci vstupu. Hostitel ihned odešle jméno testovacího účtu a ověří přechod k zadání hesla. Výzva, která vstup nezpracuje, znamená neúspěšný start. Měří se již inicializovaná instalace. Každý běh začíná s vypnutým VM, stejným výchozím obrazem disku a stavem EFI NVRAM. DHCP běží souběžně.

Každý běh začíná se zamčeným svazkem. Hostitel do připravené odemykací výzvy odešle frázi určenou výhradně pro testovací svazek. Z celkového času odečte pouze interval od připravené výzvy po odeslání fráze. Odvození klíče, otevření svazku i připojení ext4 se do sekundového cíle započítají. Zvlášť se vykáže čas do odemykací výzvy, čas od odeslání fráze po přihlášení připravené přijmout jméno a použitý profil Argon2id. Akceptační běh použije produkční bezpečnostní parametry.

Protokol samostatně vykáže dobu firmwaru před první značkou, dobu ověření hesla účtu od jeho odeslání a dobu od úspěšného ověření po připravenost shellu potvrzenou odpovědí na příkaz. U výsledků se uvede model hostitelského CPU, režim virtualizace, verze VirtualBoxu a konfigurace zařízení. Ověření podpisu firmwarovým Secure Bootem probíhá před první značkou bootloaderu a započítá se do vykazované doby firmwaru. Všech 20 měření proběhne se zapnutým ověřováním.

RAM se odečte z evidence fyzických stránek hostovaného OS po získání adresy a 30 sekundách klidu. Do 128 MiB se započtou všechny obsazené stránky OS včetně jádra, procesů, initramfs, cache a DMA bufferů, každá právě jednou. Limit 32 MiB tvoří podmnožinu pro obraz jádra, zásobníky jádra, tabulky stránek, alokátory a struktury ovladačů. Paměť vyhrazenou firmwarem a MMIO vykáže protokol odděleně. Pro každé vydání se změří také velikost jádra, initramfs a obsazené místo na systémových oddílech.

**Výkon při práci.** Na referenční VM a samostatně na vyhrazeném NVMe se stejným vydáním změříme (1) spuštění pevně určeného statického ELF až po ukončení procesu, (2) zápis 1 MiB do připraveného souboru na odemčeném ext4 včetně dokončení `fsync` a (3) lokální `tools.call` pro čtení stavu již připravené služby včetně kontroly oprávnění a návratu odpovědi. Každému scénáři předchází 10 zahřívacích běhů a následuje 100 měřených běhů za stejné konfigurace. Protokol uvede medián, 95. percentil, špičku RAM a počet chyb. Uloží konfiguraci VM či disku a jeho cache i hash testovací binárky. První převzaté vydání stanoví výchozí hodnoty. Další vydání uvedou změnu proti této referenci a zdůvodní každé zhoršení mimo rozptyl opakovaných měření. Čas vzdáleného modelu se do lokální operace nezapočte. Sekundový cíl startu se nadále ověřuje s produkčními parametry Argon2id podle tohoto oddílu.

## 10. Vývoj, testování a kvalita

Projekt musí od začátku obsahovat:

- jediný dokumentovaný příkaz pro sestavení bootovatelného obrazu,
- jediný dokumentovaný příkaz pro spuštění ve VirtualBoxu přes VBoxManage,
- automatické unit testy hardwarově nezávislých částí,
- integrační boot testy ve VirtualBoxu s časovým limitem,
- testy syscall ABI z uživatelského prostoru,
- testy poškozených vstupů, nedostatku paměti a timeoutů zařízení,
- formátování, statickou analýzu a zákaz nevysvětlených warningů,
- měření velikosti obrazu, času startu a spotřeby paměti,
- strukturovaný kernelový log dostupný přes sériovou konzoli,
- panic výpis s registry CPU a zásobníkem, pokud jsou dostupné.

VirtualBox slouží pro automatizované testy. Stejný kernelový obraz musí projít také akceptační zkouškou na referenčním notebooku.

## 11. Realizační celky a akceptační kritéria

### Úplná funkčnost jako podmínka převzetí

Každá funkce požadovaná pro dané vydání musí být plně implementovaná a použitelná běžnou cestou v dodávaném systému. Úspěch smí systém ohlásit až po splnění podmínek příslušné operace. Při chybě musí volající obdržet odpovídající chybu podle dokumentovaného rozhraní.

Pro převzetí se na každé platformě, pro kterou je funkce požadována, ověří její pozorovatelný výsledek. Například u přenosu dat test porovná obsah u příjemce. U trvalého zápisu ověří obsah po synchronizaci a restartu na témže zařízení. Protokol rozliší ověřené operace podle zařízení a platformy.

Zástupné implementace, pevně vracené výsledky, simulovaná zařízení v samotném jádře a speciální chování pro rozpoznaný test nebo aplikaci nesplňují podmínky převzetí. Testovací náhrady lze používat v izolovaných jednotkových testech. Ve VirtualBoxu musí dodávaný ovladač skutečně obsloužit virtuální zařízení a na notebooku příslušný fyzický hardware. Pokud povinná funkce chybí, funguje částečně nebo její výsledek nebyl ověřen, zůstává daný celek otevřený a blokuje stabilní vydání.

### Celek A — Boot a diagnostika

Bootloader načte jádro, ukončí Boot Services podle § 4.1 a předá řízení. Jádro v referenčním VM vypíše stejnou identifikační zprávu na framebuffer i sériovou konzoli. Na fyzickém profilu postačuje framebuffer.

### Celek B — Paměť, přerušení a SMP

Výsledek je přijat, když jádro bezpečně spravuje fyzickou a virtuální paměť, obsluhuje výjimky bez poškození stavu a spustí řízenou úlohu na všech dostupných CPU.

### Celek C — Uživatelský režim

Na HP přes klávesnici a vestavěný displej a ve VirtualBoxu také přes sériový terminál uživatel z čistého startu odemkne svazek, přihlásí se, spustí příkaz s rourou a přesměrováním, zkontroluje výsledek a odhlásí se. Test se provede s distribučním obrazem první verze bez grafického serveru. Textové klienty správy a agentů ověří navazující zkoušky v celku G.

Výsledek je přijat, když ELF program běží v odděleném uživatelském adresním prostoru, používá systémová volání a jeho chyba ani neplatný ukazatel neshodí jádro.

### Celek D — Zařízení a soubory

**Převzetí první instalace.** Z podepsaného USB se OS nainstaluje na vyhrazený interní NVMe v HP. Po vyjmutí USB musí notebook z vypnutého stavu samostatně spustit podepsaný systém z NVMe, odemknout jeho LUKS2, přihlásit správce a zobrazit soubor uložený a synchronizovaný na tomto NVMe před restartem. V protokolu bude identita cílového disku i skutečný zdroj startu. Samostatně se ověří řádný restart a vypnutí se zápisem otevřeným v systémové službě. Po dalším startu musí být dokončená data čitelná.

Na kopiích testovacího VDI se přeruší první instalace po zápisu GPT, po vytvoření LUKS2, po vytvoření ext4 a během založení správce. Každý běh musí bezpečně pokračovat nebo skončit jednoznačnou diagnostikou podle § 6.2. Při opětovném spuštění nad dokončenou instalací musí přežít kontrolní soubor i existující účty. Při nedostupnosti všech povolených zdrojů entropie musí být cílový VDI bajtově shodný s výchozím obrazem. Ve všech instalačních variantách se nezávisle porovná hash obsahu dalšího, necílového VDI před a po zkoušce.

**Převzetí obnovy celého disku.** Na obou platformách se vytvoří úplná záloha podle § 6.3 a původní disk se odpojí. Na novém VDI, respektive na prázdném vyhrazeném interním NVMe, se ověří samostatný start, nový údaj k odemčení, přihlášení dvou původních účtů, jejich vlastnictví a sdílená i soukromá práva, odkazy, kontrolní součty souborů a načtení konfigurace služby. Na kopii zálohy se změní část obsahu a ověří se odmítnutí takové obnovy před aktivací cíle.

Na obou platformách systém spustí první uživatelský proces z read-only initramfs a přijme příkaz z klávesnice podle § 3. Ve VirtualBoxu ověří zápis, synchronizaci a čtení po restartu na samostatném testovacím VDI přes AHCI. Notebook nabootuje z vyhrazeného USB média, ověří čtení GPT interního NVMe v režimu pouze pro čtení a stejnou zkoušku zápisu provede na vyhrazeném datovém oddílu testovacího USB média. Na interním displeji zobrazí výsledek.

Na testovacím VDI, USB a vyhrazeném interním NVMe ověří uživatelský proces operace z § 6 včetně práv a odkazů. Soubor zapsaný vlastním OS přečte po čistém odpojení také Linux a soubor následně zapsaný Linuxem přečte vlastní OS. Porovná se obsah i metadata.

Obnova se ověří na vyhrazených kopiích VDI. Test synchronizuje výchozí soubor i jeho adresář, zapíše novou verzi do dočasného souboru, zavolá na něj `fsync`, atomicky jej přejmenuje přes původní soubor a synchronizuje adresář. Běhy se přeruší bez čistého vypnutí před přejmenováním, během potvrzování změny i po úspěšné synchronizaci adresáře. Po obnově musí být pod původním jménem celá stará nebo celá nová verze, v posledním případě vždy nová. Po čistém odpojení obnoveného svazku musí offline kontrola `e2fsck -fn` skončit bez chyb. Tím se ověří i výsledek obnovy provedené vlastním ovladačem.

**Akceptace šifrování.** Zápisové testy používají výhradně testovací VDI, vyhrazené USB a vyhrazený interní NVMe podle § 3. Na obou platformách platí následující kritéria.

1. Po studeném startu neplatná fráze, chybný kód i klíč pro obnovu účtu ponechají svazek zamčený. Platná fráze a v samostatném běhu diskový obnovovací kód otevřou tentýž svazek se shodným kontrolním souborem. V obou případech ještě následuje přihlášení účtu.
2. Vlastní OS zapíše známý soubor a řádně se vypne. Na zamčeném obrazu je rozpoznatelná hlavička LUKS2 a přímé připojení jako ext4 selže. Referenční Linux oddíl otevře pomocí standardního `cryptsetup`, připojí ext4, ověří obsah a provede vlastní zápis. Vlastní OS po dalším odemčení přečte přesně tato data. Všechny kontroly `e2fsck` podle celku D probíhají na odemčeném blokovém zařízení s odpojeným ext4.
3. Po ztrátě testovací fráze se pomocí diskového obnovovacího kódu nastaví nová. Po restartu stará fráze selže, nová funguje a obsah souborů zůstane shodný. Na kopii VDI se navíc přeruší rotace před odebráním starého slotu a ověří se zachovaná cesta k datům.
4. Na kopii VDI se poškodí hlavička i oblast slotů. Test projde obnovou z odpovídající externí zálohy a ověří obsah původních souborů. Pokus o obnovu se zálohou jiného svazku musí skončit před zápisem. Protokol ověří, že bootovací ani diagnostické výstupy neobsahují použité testovací tajné údaje.

### Celek E — Síť

Kromě základního síťového testu se na vlastním modelovém serveru ověří úspěšné TLS spojení po přidání lokální CA. Při chybném jménu, neznámé CA, prošlém certifikátu, nevěrohodném čase a po odebrání vlastní CA musí nový pokus skončit před předáním pověření či testovacího kontextu. Potvrdí to záznam přijímajícího serveru a kontrolní údaj v požadavku při úspěšném běhu. Lokální konzole musí zůstat použitelná ve všech případech.

Výsledek je přijat, když systém automaticky získá adresu přes DHCP, přeloží DNS jméno a úspěšně přenese data přes TCP bez aktivního pollingu.

### Celek F — Linux ABI

Součástí vydání je verzovaná tabulka podporovaných volání x86-64, příznaků, chyb a testovacích binárek. Minimální síťová zkouška používá na Linuxu i vlastním jádře stejný statický ELF s musl. Dva procesy přes loopback použijí `socket` (AF_INET, SOCK_STREAM), `bind`, `listen`, `connect`, `accept`, `read`, `write` a `close`. Příjemce zaregistruje spojení pomocí `epoll_create1(0)` a `epoll_ctl(EPOLL_CTL_ADD, EPOLLIN)`. Před odesláním musí `epoll_wait` s konečným timeoutem vrátit nulu, po odeslání musí probudit příjemce, který ověří přesný obsah a délku zprávy. Rodič koordinuje odeslání až po prvním timeoutu. Protokol ověří skutečně použitá syscall čísla včetně případných variant volaných knihovnou a porovná výsledky i chybovou větev pro neplatný popisovač.

Na referenčním Linuxu i vlastním jádře se spustí totožné statické binárky s evidovaným SHA-256, verzí a konfigurací sestavení. Testovací sada spustí BusyBox `sh` se skriptem, který pomocí `cat` a `wc -c` prověří soubor, rouru a přesměrování. Druhý skript otevře chybějící soubor a ověří chybový návrat. Samostatná binárka s musl vytvoří dvě vlákna, ověří oddělené hodnoty TLS, probuzení čekajícího vlákna a ukončení přes `pthread_join`. Porovnává se výstup i návratový kód za stejných vstupů a se stejným locale. Testy mají konečný časový limit.

### Celek G — První stabilní vydání

**Akceptace spolupráce s agenty.** Na notebooku i ve VirtualBoxu uživatel zadá diagnostický úkol podle § 4.6. Skutečný agent připojený k modelu načte aktuální událost z určené služby a zapíše zprávu do povoleného souboru. Test v každém běhu vloží do události jiný identifikátor a zkontroluje jeho vazbu na správnou službu i výsledek na disku. Druhý klient protokolu převezme dílčí úkol a ověří se zachování užšího pověření. Pokus číst sousední soukromý soubor, připojit se k nepovolenému cíli nebo rozšířit oprávnění instrukcí vloženou do logu musí selhat. Po odvolání úlohy se ověří zamítnutí dalšího zápisu i dříve předaným popisovačem. Výpadek spojení s modelem musí ukončit čekání ve stanoveném čase a ponechat konzoli použitelnou. Protokol doloží skutečné operace a výsledky podle § 11.

Na obou referenčních platformách musí projít následující zkoušky přihlášení a oprávnění. Použijí se skutečné relace účtů A a B a datový oddíl ext4 podle § 6.

**Testy agentního protokolu.** Akceptační sada ověří následující scénáře přes veřejné IPC pomocí dvou samostatných klientů.

- Klient získá stránkovaný katalog, načte schéma a přečte povolené záznamy jedné služby. Volání se stejným nástrojem nad nepovolenou službou selže. Test ověří také chybné argumenty a obnovení seznamu po zneplatnění kurzoru.
- Ztráta odpovědi a zopakování delegace se stejným `operation_id` vytvoří jedinou podúlohu. Cizí agent ji nepřevezme. Určený řešitel po přijetí vrátí povolený výsledek, který rodič načte. Samostatný běh ověří odvolání za běhu a další běh vypršení nepřijaté nabídky.
- Agent požádá o zápis do jednoho souboru. Před rozhodnutím, po zamítnutí i po vypršení zůstane obsah stejný. Po jednorázovém souhlasu proběhne právě jeden ze dvou souběžných zápisů. Opakování úspěšné operace se stejným ID vrátí tentýž výsledek bez další změny souboru. Pozdní schválení po zrušení rodiče ani pokus obejít rozsah přes potomka práva neudělí.

**Izolace agentů při přímých systémových voláních.**

Izolaci agentů ověří navíc skutečný potomek spuštěný jako linuxový ELF uvnitř agentní úlohy. Přímým systémovým voláním se pokusí otevřít soukromý soubor, ke kterému úloha nemá právo. Test pak nechá potomka zdědit popisovač povoleného výstupu a potvrdí první zápis. Po dokončeném odvolání celé úlohy nesmí přes původní ani duplikovaný popisovač přibýt další data. Výsledek ověří nezávislý proces porovnáním obsahu souboru a audit doloží zamítnutí nebo ukončení potomka. Žádný z pokusů o přístup nepoužije agentní IPC nástroj.

**Testy účtů a oprávnění.**

1. Po restartu správné heslo otevře shell se správným UID a skupinami. Chybné heslo relaci neotevře, opakované pokusy vyvolají prodlevu a odhlášení vrátí konzoli k výzvě. Na testovací kopii databáze se ověří obnova podle § 8.1 včetně zamítnutí neplatného obnovovacího klíče.
2. A vytvoří soukromý soubor s režimem `0600` v domovském adresáři `0700`. A ho přečte. B se pokusí o totéž nativním programem i linuxovým BusyBoxem. Oba přístupy skončí odepřením bez vydání dat. Test systémového volání ověří chybu `EACCES`.
3. A uloží tentýž obsah do sdíleného adresáře `0750` se souborem `0640`, obojí s přidělenou sdílenou skupinou. B před přidáním do skupiny soubor neotevře. Po přidání a novém přihlášení jej B přečte nativně i přes Linux ABI. Pokusy B soubor přepsat, přejmenovat či smazat musí na obou rozhraních selhat a obsah i jméno zůstat zachované.
4. B nesmí změnit vlastní UID na správcovské, změnit účet A ani získat přímý zápis na blokové zařízení. Správce po opětovném ověření provede vybranou změnu účtu. Následující privilegovaná operace musí znovu projít autorizací. Audit doloží identitu, operaci a výsledek bez zachycení tajných údajů.

**Akceptace Secure Bootu a aktualizací.** Na HP z vyhrazeného USB a ve VirtualBoxu z VDI projde platně podepsané vydání až k odemčení a přihlášení. Odděleně se změní jediný bajt v kódu bootloaderu, v sekci ELF a v initramfs po podpisu. U všech tří variant, nepodepsaného obrazu i obrazu podepsaného cizím klíčem se ověří odmítnutí před spuštěním daného obrazu. Na izolované VM se navíc ověří odmítnutí odvolaného obrazu přes `dbx`, funkční start aktuálního servisního média a odmítnutí produkčního startu při vypnutém Secure Bootu.

Na obou platformách proběhne platná aktualizace A → B včetně opětovného startu potvrzeného B a kontroly dat. Změněný manifest, cizí podpis, jiný obsah nebo nabídka starší verze musí zachovat aktivní vydání. Na kopii VDI se přeruší zápis kandidáta, potvrzení a také zkušební start před přihlášením. Po každém přerušení musí běžnou cestou nabootovat konzistentní povolené vydání. Protokol zaznamená použitý obraz, stav Secure Bootu, důvod odmítnutí či návratu a ověřený obsah testovacích dat. Na instalaci na vyhrazeném NVMe ověříme přechod A → B bez připojeného USB. Platně podepsaný novější manifest obsahující správný hash staršího, také platně podepsaného EFI, musí skončit chybou neshody verzí před změnou slotu či BootNext. Na kopii VDI se během startu kandidáta před potvrzením ukončí přihlašovací služba. Po restartu musí být aktivní původní vydání.

Vydání splní celky A až F, výkonové limity podle § 9 ve VM a funkční zkoušku na fyzickém notebooku. Dvě čistá sestavení se stejnými zdroji, nástroji a vstupy musí vytvořit bajtově shodný obraz EFI před podpisem. Z téhož výsledného podepsaného artefaktu se reprodukovatelně sestaví distribuční médium. Manifest identifikuje přesné podepsané bajty ověřené při převzetí. Vydání obsahuje výsledky měření a instalační i vývojářskou dokumentaci.

## 12. Výslovně zakázané zkratky

- Linux nesmí být skrytě použit jako vlastní jádro systému.
- Kompatibilita nesmí být řešena spuštěním celého Linuxu ve virtuálním stroji.
- Do jádra se nesmějí kopírovat binární ovladače pro jiný operační systém.
- Nesmí vzniknout nezdokumentované systémové volání nebo nestabilní veřejné ABI.
- Nesmí se optimalizovat bez měření ani přidávat subsystém bez konkrétního použití.
- Bezpečnostní kontroly se nesmějí vypínat kvůli dosažení benchmarku.
- Do první stabilní verze se nesmějí přidávat funkce mimo stanovený rozsah na úkor dokončení základních celků.

## 13. Definice úspěchu projektu

Projekt dosáhne prvního hlavního cíle vydáním podle celku G. Rozsah deklarované podpory určují vyzkoušené hardwarové konfigurace a linuxové binárky uvedené v protokolu vydání.
