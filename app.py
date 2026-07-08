# app.py
# Flask backend pro P-CVSSv4 kalkulačku

import json
import os

from cvss import CVSS4
from flask import Flask, request, jsonify, render_template, session

from p_cvss import METRIKY, sestavit_vektor, urcit_kritickost

app = Flask(__name__)

# Session potřebuje podepisovací klíč (bez něj Flask uložení jazyka do
# session odmítne). V produkci (serveru) přes proměnnou prostředí.
app.secret_key = os.environ.get(
    "SECRET_KEY",
    "moje-domaci-tajne-heslo-21354350454dsfdfd4561dfqqcdfklshdhqtgufbbymeoiw658fg5f6odzkuisv4d6fdff35",
)

# Vícejazyčnost (i18n)
# Slovníky překladů jsou v /lang/cs.json a /lang/en.json
# Klíč se do slovníku podívá podle jazyka uloženého v session,
# případně podle URL parametru ?lang=xx, který má přednost
# a zároveň se session přepíše, aby si prohlížeč jazyk "pamatoval".


LANG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "lang")
SUPPORTED_LANGUAGES = ["cs", "en"]
DEFAULT_LANGUAGE = "cs"


def nacti_preklady():
    """Načte oba jazykové slovníky ze souborů do paměti (při startu apky)"""
    preklady = {}
    for lang in SUPPORTED_LANGUAGES:
        cesta = os.path.join(LANG_DIR, f"{lang}.json")
        with open(cesta, encoding="utf-8") as f:
            preklady[lang] = json.load(f)
    return preklady


# Slovníky se načtou jen jednou při startu serveru, ne při každém requestu
PREKLADY = nacti_preklady()


def zjisti_jazyk() -> str:
    """
    Zjistí, jaký jazyk se má použít:
    1) pokud přijde URL parametr ?lang=cs/en, použije se a uloží do session
    2) jinak se použije jazyk uložený v session (uživatel si ho zvolil dříve)
    3) jinak výchozí jazyk (čeština)
    """
    lang_z_url = request.args.get("lang")

    if lang_z_url in SUPPORTED_LANGUAGES:
        session["lang"] = lang_z_url
        return lang_z_url

    return session.get("lang", DEFAULT_LANGUAGE)


# HLAVNÍ STRÁNKA
# Předá definici metrik i přeložené texty do HTML šablony –
# šablona z nich dynamicky vygeneruje tlačítka a popisky


@app.route("/")
def index():
    aktualni_jazyk = zjisti_jazyk()
    t = PREKLADY[aktualni_jazyk]  # slovník textů pro aktuální jazyk

    # Rozdělení metrik do skupin pro šablonu
    metriky_skupiny = {
        "Základní metriky_1": {
            k: METRIKY[k] for k in ["AV", "AC", "AT", "PR", "UI"] if k in METRIKY
        },
        "Základní metriky_2": {
            k: METRIKY[k] for k in ["VC", "VI", "VA"] if k in METRIKY
        },
        "Základní metriky_3": {
            k: METRIKY[k] for k in ["SC", "SI", "SA"] if k in METRIKY
        },
        "Doplňková metrika": {k: METRIKY[k] for k in ["S"] if k in METRIKY},
        "Metrika prostředí": {
            k: METRIKY[k] for k in ["CR", "IR", "AR"] if k in METRIKY
        },
        "Metrika hrozeb": {k: METRIKY[k] for k in ["E"] if k in METRIKY},
    }
    return render_template(
        "index.html",
        metriky=METRIKY,
        metriky_skupiny=metriky_skupiny,
        t=t,
        lang=aktualni_jazyk,
    )


# VÝPOČET SKÓRE
# Frontend pošle JSON: { "selections": {"AV":"N", "AC":"L", "AT":"N"} }
# Backend sestaví vektor, spočítá skóre, vrátí výsledek


@app.route("/calculate", methods=["POST"])
def calculate():
    data = request.get_json()  # "request" objekt z Flask knihovny (HTTP požadavek z prohlížeče); "get_json()" vytáhne JSON data
    # proměnná "data" příjme výsledek metody "get_json()" objektu "request"

    if not data:
        return jsonify(
            {"status": "error", "message": "error_no_data"}
        ), 400  # "400" jako bad request

    selections = data.get("selections", {})
    # ".get" - metoda dictu - vytáhne hodnotu z dictu "data"

    if not selections:
        return jsonify(
            {"status": "error", "message": "error_no_selections"}
        ), 400  # pokud selections neexistuje, použij prázdný dict

    # metrika S - pokud je S:P, přepíše SC, SI, SA na H
    if selections.get("S") == "P":
        selections["SC"] = "H"
        selections["SI"] = "H"
        selections["SA"] = "H"
        # pokud je S:N, SC/SI/SA zůstanou jak uživatel nastavil

    # Sestavení vektoru z výběrů uživatele
    vektor = sestavit_vektor(selections)
    # fce "sestavit_vektor" přijme parametr "selections"
    # zpracuje parametr a vrátí výsledek, kt se uloží do proměnné "vektor"

    try:
        c = CVSS4(vektor)  # "c" z knihovny cvss
        skore = float(c.base_score)
        return jsonify(
            {
                "status": "success",
                "score": skore,
                "severity_key": urcit_kritickost(skore),
                "vector": c.clean_vector(),
            }
        )
    except Exception as e:  # pokud nastane jakákoliv chyba "Exception", ulož ji do proměnné "e" (program při chybě nespadne)
        return jsonify({"status": "error", "message": str(e)}), 400


# SPUŠTĚNÍ SERVERU

if __name__ == "__main__":
    # Server se na lokálu spustí v debug módu.
    # Pokud by to náhodou někdo spustil přímo v produkci, debug se vypne.
    is_production = os.environ.get("FLASK_ENV") == "production"

    app.run(debug=not is_production, host="127.0.0.1", port=5000)
