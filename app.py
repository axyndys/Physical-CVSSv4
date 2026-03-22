# app.py
# Flask backend pro P-CVSSv4 kalkulačku

import os
from cvss import CVSS4
from flask import Flask, request, jsonify, render_template

from p_cvss import METRIKY, sestavit_vektor

app = Flask(__name__)


# ------------------------------------------------------
# HLAVNÍ STRÁNKA
# Předá definici metrik do HTML šablony –
# šablona z nich dynamicky vygeneruje tlačítka
# ------------------------------------------------------

@app.route("/")
def index():
    # Rozdělení metrik do skupin pro šablonu
    metriky_skupiny = {
        "Základní metriky_1": {k: METRIKY[k] for k in ["AV","AC","AT","PR","UI"] if k in METRIKY},
        "Základní metriky_2": {k: METRIKY[k] for k in ["VC", "VI", "VA"] if k in METRIKY},
        "Základní metriky_3": {k: METRIKY[k] for k in ["SC", "SI", "SA"] if k in METRIKY},
        "Doplňková metrika": {k: METRIKY[k] for k in ["S"] if k in METRIKY},
        "Metrika prostředí": {k: METRIKY[k] for k in ["CR","IR","AR"] if k in METRIKY},
        "Metrika hrozeb": {k: METRIKY[k] for k in ["E"] if k in METRIKY},
    }
    return render_template("index.html", metriky=METRIKY, metriky_skupiny=metriky_skupiny)


# ------------------------------------------------------
# VÝPOČET SKÓRE
# Frontend pošle JSON: { "selections": {"AV":"N", "AC":"L", "AT":"N"} }
# Backend sestaví vektor, spočítá skóre, vrátí výsledek
# ------------------------------------------------------

@app.route("/calculate", methods=["POST"])
def calculate():
    data = request.get_json()       # "request" objekt z Flask knihovny (HTTP požadavek z prohlížeče); "get_json()" vytáhne JSON data
    # proměnná "data" příjme výsledek metody "get_json()" objektu "request"

    if not data:
        return jsonify({"status": "error", "message": "Žádná data"}), 400       # "400" jako bad request

    selections = data.get("selections", {})        
    # ".get" - metoda dictu - vytáhne hodnotu z dictu "data" 

    if not selections:
        return jsonify({"status": "error", "message": "Žádné výběry"}), 400     # pokud selections neexistuje, použij prázdný dict
    
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
        c = CVSS4(vektor) # "c" z knihovny cvss
        return jsonify({
            "status": "success",
            "score": float(c.base_score),
            "rating": c.severities()[0],  # None / Low / Medium / High / Critical
            "vector": c.clean_vector()
        })
    except Exception as e:      # pokud nastane jakákoliv chyba "Exception", ulož ji do proměnné "e" (program při chybě nespadne)
        return jsonify({"status": "error", "message": str(e)}), 400


# ------------------------------------------------------
# SPUŠTĚNÍ SERVERU
# ------------------------------------------------------

if __name__ == "__main__": # při spouštění souboru app.py, spusť flask server
    app.run(debug=True)
    # debug=True = server se restartuje při každém uložení souboru