# Definice metrik P-CVSSv4 a sestavení vektoru pro knihovnu cvss
# ------------------------------------------------------
# Struktura metrik: kod_metriky -> label, krok, options
# Hodnoty metrik: CVSS_kod -> přemapování hodnot
# ------------------------------------------------------

METRIKY = {
    # 1. ZÁKLADNÍ METRIKA (BASE METRICS - Exploitability Metrics) - ČÁST 1

    "AV": {
        "label": "AV - Vektor útoku",
        "krok": "Krok 1: V jaké bezpečnostní zóně se nachází identifikovaná zranitelnost?",
        "options": {
            "N": "Veřejná zóna",
            "A": "Kontrolovaná zóna",
            "L": "Chráněná zóna",
            "P": "Zabezpečená zóna",
        }
    },

    "AC": {
        "label": "AC - Složitost útoku",
        "krok": "Krok 2: Jaký typ složitosti bezpečnostních mechanismů musí útočník obejít?",
        "options": {
            "L": "Nižší složitosti",
            "H": "Vyšší složitosti",
        }
    },

    "AT": {
        "label": "AT - Podmínky pro útok",
        "krok": "Krok 3: Vyžaduje útok specifické podmínky pro jeho provedení?",
        "options": {
            "N": "Nevyžaduje",
            "P": "Vyžaduje",
        }
    },

    "PR": {
        "label": "PR - Úroveň požadovaných oprávnění",
        "krok": "Krok 4: Jakou úroveň požadovaných oprávnění potřebuje útočník před zahájením útoku?",
        "options": {
            "N": "Nepotřebuje žádná oprávnění",
            "L": "Potřebuje základní oprávnění (běžný uživatel)",
            "H": "Potřebuje vysoká oprávnění (administrátor)",
        }
    },

    "UI": {
        "label": "UI - Lidský činitel",
        "krok": "Krok 5: Potřebuje útočník k provedení útoku pomoc jiné osoby?",
        "options":{
            "N": "Nepotřebuje interakci jiné osoby",
            "L": "Potřebuje omezenou interakci jiné osoby",
            "A": "Potřebuje aktivní interakci jiné osoby",
        }
    },

    # 1. ZÁKLADNÍ METRIKA (BASE METRICS - Vulnerable System Impact Metrics) - ČÁST 2

    "VC": {
        "label": "VC - Důvěrnost",
        "krok": "Krok 6: Jaká bude míra narušení důvěrnosti bezpečnostního opatření?",
        "options":{
            "H": "Vysoká",
            "L": "Nízká",
            "N": "Žádná",
        }
    },

    "VI": {
        "label": "VI - Integrita",
        "krok": "Krok 7: Jaká bude míra narušení integrity bezpečnostního opatření?",
        "options": {
            "H": "Vysoká",
            "L": "Nízká",
            "N": "Žádná",
        }
    },

    "VA": {
        "label": "VA - Dostupnost",
        "krok": "Krok 8: Jaká bude míra narušení dostupnosti bezpečnostního opatření?",
        "options": {
            "H": "Vysoká",
            "L": "Nízká",
            "N": "Žádná",
        }
    },

    # 1. ZÁKLADNÍ METRIKA (BASE METRICS - Subsequent System Impact Metrics) - ČÁST 3

    "SC": {
        "label": "SC - Důvěrnost",
        "krok": "Krok 9: Jaká bude míra narušení důvěrnosti aktiva dotčeného zneužitím zranitelnosti bezpečnostního opatření?",
        "options": {
            "H": "Vysoká",
            "L": "Nízká",
            "N": "Žádná",
        }
    },

    "SI": {
        "label": "SI - Integrita",
        "krok": "Krok 10: Jaká bude míra narušení integrity aktiva dotčeného zneužitím zranitelnosti bezpečnostního opatření?",
        "options": {
            "H": "Vysoká",
            "L": "Nízká",
            "N": "Žádná",
        }
    },

    "SA": {
        "label": "SA - Dostupnost",
        "krok": "Krok 11: Jaká bude míra narušení dostupnosti aktiva dotčeného zneužitím zranitelnosti bezpečnostního opatření?",
        "options": {
            "H": "Vysoká",
            "L": "Nízká",
            "N": "Žádná",
        }
   },

    # 2. METRIKA - DOPLŇKOVÁ METRIKA (SUPPLEMENTAL METRICS)

    "S": {
        "label": "S - Bezpečnost - zdraví, život",
        "krok": "Krok 12: Do jaké míry může zneužití této zranitelnosti ovlivnit lidské zdraví/život?",
        "options": {
            "P": "Vysoká / Střední",
            "N": "Nízká / Žádná",
        }
    },

    # 3. METRIKA - METRIKA PROSTŘEDÍ (ENVIRONMENTAL - SECURITY REQUIREMENTS METRICS)

    "CR": {
        "label": "CR - Požadavky na důvěrnost",
        "krok": "Krok 13: Jak kritická je důvěrnost zasaženého aktiva (využitím zranitelnosti) v daném prostředí?",
        "options": {
            "X": "Nedefinováno",
            "H": "Vysoká",
            "M": "Střední",
            "L": "Nízká/Žádná",
        }
    },

    "IR": {
        "label": "CI - Požadavky na integritu",
        "krok": "Krok 14: Jak kritická je integrita zasaženého aktiva (využitím zranitelnosti) v daném prostředí?",
        "options": {
            "X": "Nedefinováno",
            "H": "Vysoká",
            "M": "Střední",
            "L": "Nízká/Žádná",
        }
    },

    "AR": {
        "label": "AR - Požadavky na dostupnost",
        "krok": "Krok 15: Jak kritická je dostupnost zasaženého aktiva (využitím zranitelnosti) v daném prostředí?",
        "options": {
            "X": "Nedefinováno",
            "H": "Vysoká",
            "M": "Střední",
            "L": "Nízká/Žádná",
        }
    },

    # 4. METRIKA - METRIKA HROZEB (THREAT METRICS)

    "E": {
        "label": "E - Rozšířenost metody zneužití zranitelnosti",
        "krok": "Krok 16: Jaký je stav a rozšířenost metod zneužití této zranitelnosti?",
        "options": {
            "A": "Aktivně využívaná",
            "P": "Omezeně využívaná",
            "U": "Vzácně využívaná",
        }
    }
}
# ------------------------------------------------------
# POŘADÍ METRIK VE VEKTORU
# Knihovna cvss vyžaduje přesné pořadí – neměnit!
# ------------------------------------------------------

VEKTOR_POŘADÍ = [  #VEKTOR_POŘADÍ (velkými písmeny jako konvence v .py - psaní konstant)
    "AV", "AC", "AT", "PR", "UI",
    "VC", "VI", "VA",
    "SC", "SI", "SA",
    "S",
    "CR", "IR", "AR",
    "E",
]

# ------------------------------------------------------
# SESTAVENÍ VEKTORU
# Přijme dict (slovník) { "AV": "N", "AC": "L", ... }
# Vrátí string "CVSS:4.0/AV:N/AC:L/..."
# ------------------------------------------------------

def sestavit_vektor(selections: dict) -> str: #definuj funkci: "sestav_vektor", kt přijme parametr selections (výběr uživatele) a vrátí str 
                    # (ve tvaru: dict - datové typu párů klíč (AV) : hodnota (N))
    parts = [
        f"{k}:{selections[k]}" #f"...." (jako f-string) - pro sestavení textu s proměnnými (k, selections [k])
        # proměnná k - jako klíč metriky ("AV") --> 
        #                                           {k} dosadí aktuální klíč metriky (AV)
        # proměnná selections [k] - jako  hodnota metriky ("N") --> 
        #                                           {selections [k]} dosadí aktuálního hodnotu metriky (N)

        for k in VEKTOR_POŘADÍ #projde metriky ve správném pořadí
        if k in selections #přeskočí metriky, kt uživatel ještě nevybrals
    ]
    return "CVSS:4.0/" + "/".join(parts) #prefix + spojení "parts" lomítkem