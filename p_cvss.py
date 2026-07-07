# Definice metrik P-CVSSv4 a sestavení vektoru pro knihovnu cvss
# Struktura metrik: kod_metriky -> label_key, step_key, options
# Hodnoty metrik: CVSS_kod -> přemapování hodnot
#
# POZNÁMKA K LOKALIZACI:
# Slovník neobsahuje žádné hotové české texty určené pro uživatele.
# Místo toho obsahuje univerzální anglické klíče (label_key, step_key, option klíče), které se ve frontendu/šabloně přeloží pomocí slovníku
# překladů (např. cs.json / en.json). Díky tomu tento soubor vrací jen "čistá data" a lokalizace se řeší mimo něj.
# ------------------------------------------------------

METRIKY = {
    # 1. ZÁKLADNÍ METRIKA (BASE METRICS - Exploitability Metrics) - ČÁST 1
    "AV": {
        "label_key": "metric_av_label",
        "step_key": "metric_av_step",
        "options": {
            "N": "av_option_public_zone",
            "A": "av_option_controlled_zone",
            "L": "av_option_protected_zone",
            "P": "av_option_secured_zone",
        },
    },
    "AC": {
        "label_key": "metric_ac_label",
        "step_key": "metric_ac_step",
        "options": {
            "L": "ac_option_low_complexity",
            "H": "ac_option_high_complexity",
        },
    },
    "AT": {
        "label_key": "metric_at_label",
        "step_key": "metric_at_step",
        "options": {
            "N": "at_option_not_required",
            "P": "at_option_required",
        },
    },
    "PR": {
        "label_key": "metric_pr_label",
        "step_key": "metric_pr_step",
        "options": {
            "N": "pr_option_none",
            "L": "pr_option_low",
            "H": "pr_option_high",
        },
    },
    "UI": {
        "label_key": "metric_ui_label",
        "step_key": "metric_ui_step",
        "options": {
            "N": "ui_option_none",
            "L": "ui_option_limited",
            "A": "ui_option_active",
        },
    },
    # 1. ZÁKLADNÍ METRIKA (BASE METRICS - Vulnerable System Impact Metrics) - ČÁST 2
    "VC": {
        "label_key": "metric_vc_label",
        "step_key": "metric_vc_step",
        "options": {
            "H": "impact_high",
            "L": "impact_low",
            "N": "impact_none",
        },
    },
    "VI": {
        "label_key": "metric_vi_label",
        "step_key": "metric_vi_step",
        "options": {
            "H": "impact_high",
            "L": "impact_low",
            "N": "impact_none",
        },
    },
    "VA": {
        "label_key": "metric_va_label",
        "step_key": "metric_va_step",
        "options": {
            "H": "impact_high",
            "L": "impact_low",
            "N": "impact_none",
        },
    },
    # 1. ZÁKLADNÍ METRIKA (BASE METRICS - Subsequent System Impact Metrics) - ČÁST 3
    "SC": {
        "label_key": "metric_sc_label",
        "step_key": "metric_sc_step",
        "options": {
            "H": "impact_high",
            "L": "impact_low",
            "N": "impact_none",
        },
    },
    "SI": {
        "label_key": "metric_si_label",
        "step_key": "metric_si_step",
        "options": {
            "H": "impact_high",
            "L": "impact_low",
            "N": "impact_none",
        },
    },
    "SA": {
        "label_key": "metric_sa_label",
        "step_key": "metric_sa_step",
        "options": {
            "H": "impact_high",
            "L": "impact_low",
            "N": "impact_none",
        },
    },
    # 2. METRIKA - DOPLŇKOVÁ METRIKA (SUPPLEMENTAL METRICS)
    "S": {
        "label_key": "metric_s_label",
        "step_key": "metric_s_step",
        "options": {
            "P": "s_option_high_medium",
            "N": "s_option_low_none",
        },
    },
    # 3. METRIKA - METRIKA PROSTŘEDÍ (ENVIRONMENTAL - SECURITY REQUIREMENTS METRICS)
    "CR": {
        "label_key": "metric_cr_label",
        "step_key": "metric_cr_step",
        "options": {
            "X": "req_undefined",
            "H": "req_high",
            "M": "req_medium",
            "L": "req_low_none",
        },
    },
    "IR": {
        "label_key": "metric_ir_label",
        "step_key": "metric_ir_step",
        "options": {
            "X": "req_undefined",
            "H": "req_high",
            "M": "req_medium",
            "L": "req_low_none",
        },
    },
    "AR": {
        "label_key": "metric_ar_label",
        "step_key": "metric_ar_step",
        "options": {
            "X": "req_undefined",
            "H": "req_high",
            "M": "req_medium",
            "L": "req_low_none",
        },
    },
    # 4. METRIKA - METRIKA HROZEB (THREAT METRICS)
    "E": {
        "label_key": "metric_e_label",
        "step_key": "metric_e_step",
        "options": {
            "A": "e_option_active",
            "P": "e_option_limited",
            "U": "e_option_rare",
        },
    },
}
# ------------------------------------------------------
# POŘADÍ METRIK VE VEKTORU
# Knihovna cvss vyžaduje přesné pořadí – neměnit!
# ------------------------------------------------------

VEKTOR_POŘADÍ = [  # VEKTOR_POŘADÍ (velkými písmeny jako konvence v .py - psaní konstant)
    "AV",
    "AC",
    "AT",
    "PR",
    "UI",
    "VC",
    "VI",
    "VA",
    "SC",
    "SI",
    "SA",
    "S",
    "CR",
    "IR",
    "AR",
    "E",
]

# ------------------------------------------------------
# SESTAVENÍ VEKTORU
# Přijme dict (slovník) { "AV": "N", "AC": "L", ... }
# Vrátí string "CVSS:4.0/AV:N/AC:L/..."
# (Vektor obsahuje jen CVSS kódy, žádný lidský text - lokalizace se ho netýká.)
# ------------------------------------------------------


def sestavit_vektor(
    selections: dict,
) -> str:  # definuj funkci: "sestav_vektor", kt přijme parametr selections (výběr uživatele) a vrátí str
    # (ve tvaru: dict - datové typu párů klíč (AV) : hodnota (N))
    parts = [
        f"{k}:{selections[k]}"  # f"...." (jako f-string) - pro sestavení textu s proměnnými (k, selections [k])
        # proměnná k - jako klíč metriky ("AV") -->
        #                                           {k} dosadí aktuální klíč metriky (AV)
        # proměnná selections [k] - jako  hodnota metriky ("N") -->
        #                                           {selections [k]} dosadí aktuálního hodnotu metriky (N)
        for k in VEKTOR_POŘADÍ  # projde metriky ve správném pořadí
        if k in selections  # přeskočí metriky, kt uživatel ještě nevybrals
    ]
    return "CVSS:4.0/" + "/".join(parts)  # prefix + spojení "parts" lomítkem
