# Odredba URSIV št. 386-62/2026-1544-2 in skripta

Odredba Urada Vlade RS za informacijsko varnost z dne 21. 10. 2026 (na podlagi devetega odstavka 37. člena ZInfV-1)
odreja nujne ukrepe zavezancem v zvezi s CVE-2026-109618 in CVE-2026-109619. Ta dokument je pregled, kaj od
ukrepov pokriva `php2shell_check.py`. **Ni pravni nasvet; veljavno besedilo je odredba, ki jo prejme zavezanec.**
Rokovi tečejo od seznanitve z odredbo.

| Točka | Ukrep in rok | Skripta |
|---|---|---|
| I. Identifikacija | Popis vseh aplikacij in sistemov na PHP, prednostno z interneta; vključno z vgrajenim PHP. 24 ur | Korak 1 najde PHP binarke in module na standardnih poteh. **Vgrajenih PHP-jev v aplikacijah ne najde.** |
| II. Popravki | PHP 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 ali popravljeni paketi; po namestitvi ponovni zagon vseh PHP procesov in preverjanje. 48 ur (internet), 7 dni (ostalo) | Korak 1 (verzije, changelog paketa), korak 3 (delavci, ki še tečejo s staro binarko) |
| III. Če popravek ni mogoč | `memory_limit=-1` z `php_admin_value`, omejitev pomnilnika na ravni vsebnika/cgroup, `post_max_size` 8M/32M, omejitve na spletnem strežniku, zavrnitev multiparta, `session.upload_progress.enabled=0`, `fatal_error_backtraces=0` (8.5), `pm.max_requests=1`, ponovni zagon; sicer izolacija | Korak 2 pokrije PHP nastavitve. **Ne preverja** omejitev na spletnem strežniku/proxyju, cgroup omejitve, nastavitev na ravni, ki velja pred razčlenjevanjem zahteve (`.user.ini`, `ini_set`) |
| IV. Različice brez podpore | 8.1 in starejše: popravki distributerja/ESM ali minimalni popravki izvorne kode; sicer nadgradnja; do takrat izolacija. Rok kot II. | Korak 1 označi stare veje. Izolacije ne preverja |
| V. Spremljanje znakov izkoriščanja | Fatal error zaradi pomnilnika (posebej multipart), sesutja delavcev, nepričakovani procesi in datoteke pod web uporabnikom, webshelli; **ohranitev dnevnikov** | Koraki 3, 4, 6, 7 (od 2.3.0 gruče OOM napak). **Ne ohranja dnevnikov**: pred rotacijo jih skopiraj |
| VI. Priglasitev incidentov | Pomembni incidenti CSIRT po 30. členu ZInfV-1; ostali zavezanci prostovoljno po 35. členu | Ni del skripte |
| VII. Poročanje | O ukrepih I–V pristojnemu CSIRT, 72 ur, nato ob vsaki spremembi; način določa varnostno navodilo CSIRT | Ni del skripte; izpis (`--json`) lahko služi kot dokaz o opravljenih preverjanjih |
