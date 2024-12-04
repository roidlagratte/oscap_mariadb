import mysql.connector
from lxml import etree
from datetime import datetime

# Connexion à la base de données MySQL
db_connection = mysql.connector.connect(
    host="localhost",
    user="oscap",  # Remplacez par votre utilisateur MySQL
    password="oscap",  # Remplacez par votre mot de passe MySQL
    database="oscap"  # Remplacez par le nom de votre base de données
)

cursor = db_connection.cursor()

# Chemin vers votre fichier XML
file_path = 'oscap-xccdf-result.xml'

# Charger le fichier XML
tree = etree.parse(file_path)
root = tree.getroot()

# Définir les namespaces utilisés dans le fichier XML
namespaces = {
    'xccdf': 'http://checklists.nist.gov/xccdf/1.2',  # Remplacez par le namespace réel dans votre XML
}

# Recherche des balises <TestResult>
test_results = root.findall('.//xccdf:TestResult', namespaces)

# Parcours des résultats de TestResult
for test_result in test_results:
    # Extraire l'attribut id et start-time de la balise <TestResult>
    test_id = test_result.get('id')
    start_time = test_result.get('start-time')

    # Convertir start_time au format DATETIME compatible MySQL (sans fuseau horaire)
    try:
        start_time = datetime.fromisoformat(start_time.replace("Z", "+00:00")).strftime('%Y-%m-%d %H:%M:%S')
    except ValueError:
        print(f"Invalid start-time format: {start_time}")
        continue


    # Recherche de la balise <target> dans le même TestResult
    target = test_result.find('.//xccdf:target', namespaces)

    # Si la balise <target> existe, récupérer son texte
    if target is not None:
        target_text = target.text
    else:
        target_text = 'Not found'

    # Recherche de la balise <score>
    score_element = test_result.find('.//xccdf:score', namespaces)

    # Extraire la valeur de la balise <score>
    if score_element is not None:
        score_value = score_element.text
    else:
        score_value = 'Not found'

    evaluation_type = "conformite"
    # Insérer l'évaluation dans la table "evaluation"
    insert_eval_query = """
        INSERT INTO evaluation (serveur, datetest, profil, score, type)
        VALUES (%s, %s, %s, %s, %s)
    """


    cursor.execute(insert_eval_query, (target_text, start_time, test_id, score_value, evaluation_type))
    db_connection.commit()

    # Récupérer l'id de l'évaluation insérée (pour l'utiliser dans la table details)
    eval_id = cursor.lastrowid

    # Recherche des balises <rule-result> dans le même TestResult
    rule_results = test_result.findall('.//xccdf:rule-result', namespaces)

    # Parcours des résultats de rule-result
    for rule_result in rule_results:
        # Extraire les attributs idref et severity de la balise <rule-result>
        rule_idref = rule_result.get('idref')
        severity = rule_result.get('severity')

        # Trouver la balise imbriquée <result>
        result_element = rule_result.find('xccdf:result', namespaces)

        # Extraire la valeur de la balise <result>
        if result_element is not None:
            result_value = result_element.text
        else:
            result_value = 'Not found'

        # Insérer les détails dans la table "details"
        insert_details_query = """
            INSERT INTO details (eval, rule, severity, test)
            VALUES (%s, %s, %s, %s)
        """
        cursor.execute(insert_details_query, (eval_id, rule_idref, severity, result_value))
        db_connection.commit()

# Fermer la connexion à la base de données
cursor.close()
db_connection.close()

