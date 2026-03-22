# Physical-CVSS Přizpůsobená potřebám fyzické bezpečnosti

Webová kalkulačka pro hodnocení zranitelností fyzické bezpečnosti postavená na standardu CVSSv4.
Projekt upravuje metriky a jejich popis tak, aby odpovídaly potřebám fyzické bezpečnosti.

**Autor:** Andrea Steckerová

---

## Prohlášení o použití nástrojů umělé inteligence
V průběhu zpracování tohoto projektu bylo využito těchto podpůrných nástrojů umělé inteligence:
- Google Gemini – jako podpora při debuggingu skriptu kalkulačky "Physical-CVSSv4",
- Claude Code - jako další podpora při debuggingu skriptu a vytvoření index.html (HTML, CSS) webového rozhraní kalkulačky "Physical-CVSSv4".

---

## O projektu

Standardní CVSS (Common Vulnerability Scoring System) verze 4.0 byl navržen pro hodnocení zranitelností v kybernetickém prostoru. 
Tento projekt součástí bakalářské práce přizpůsobuje jeho metriky (prostřednictvím mapování) a terminologii prostředí fyzické bezpečnosti a zranitelnostem nacházejícím se v této doméně. Projekt může být využíván bezpečnostním specialistou k hodnocení zranitelností fyzické bezpečnosti a možnosti následného srovnání zranitleností fyzické a kybernetické bezpečnosti. 

Výpočet skóre probíhá dle oficiální knihovny `cvss` (pip), přemapování metrik je vlastní logika autora, která zohledňuje např. bezpečnostní zónování, techniky sociálního inženýrství ve fyzickém světě (např. tailgating, piggybacking, pretexting).

---

## Funkce

- Interaktivní kalkulačka s tlačítky pro každou metriku
- Automatický výpočet skóre po každém výběru
- Zobrazení výsledného CVSS vektoru (možnost následného zkopírování a další práce)
- Metriky přeloženy a přizpůsobeny fyzické bezpečnosti
- Jednoduché spuštění lokálně i nasazení na cloud či jako integraci do již existující webové aplikace

---

## Technologie

| Vrstva | Technologie |
|---|---|
| Backend | Python, Flask |
| Výpočet skóre | pip `cvss` (CVSSv4) |
| Frontend | HTML, CSS, JavaScript |
| Deployment | Render.com, Gunicorn |

---

## Instalace a spuštění

**Požadavky:** Python 3.10+, VS Code (doporučeno)

```bash
# 1. Klonuj repozitář
git clone https://github.com/axyndys/physical-cvss.git
cd physical-cvss

# 2. Vytvoř virtuální prostředí
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # Mac / Linux

# 3. Nainstaluj závislosti
pip install -r requirements.txt

# 4. Spusť aplikaci
python app.py
```

Otevři v prohlížeči: `http://127.0.0.1:5000`

---

## Struktura projektu

```
physical-cvss/
├── app.py              # Flask webový framewrork (routes)
├── p_cvss.py           # Definice metrik a sestavení vektoru
├── templates/
│   └── index.html      # Hlavní stránka kalkulačky
├── requirements.txt    # Závislosti
└── README.md
```

---

## Závislosti
Zobrazeny v souboru requirements.txt

## Nasazení (Render.com)

1. Nahraj projekt na GitHub
2. Na [render.com](https://render.com) vytvoř nový **Web Service**
3. Propoj GitHub repozitář
4. Nastav:
   - **Build command:** `pip install -r requirements.txt`
   - **Start command:** `gunicorn app:app`
5. Klikni Deploy

Před nasazením přidej do projektu soubor `Procfile`:

```
web: gunicorn app:app
```

---

## Licence

Tento projekt je volně dostupný pro vzdělávací a výzkumné účely.
CVSS je standard organizace [FIRST.org](https://www.first.org/cvss/).