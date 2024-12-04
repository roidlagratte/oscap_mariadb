import xml.etree.ElementTree as ET
import re
import mysql.connector

def analyze_xml_and_patch(xml_file):
    try:

        conn = mysql.connector.connect(
            host='localhost',  # Remplacez par votre hôte
            user='oscap',  # Remplacez par votre utilisateur
            password='oscap',  # Remplacez par votre mot de passe
            database='oscap'  # Remplacez par le nom de votre base
        )
        cursor = conn.cursor()
        # Charger et analyser le fichier XML
        tree = ET.parse(xml_file)
        root = tree.getroot()
        # Définir les namespaces pour la recherche

        # Tableau pour stocker les valeurs trouvées
        definitions_found = []
        patch_definitions_found = []

        # 0. récuperation des informations de base 
        namespaces = {
            'oval': 'http://oval.mitre.org/XMLSchema/oval-common-5',
            'unix-sys': 'http://oval.mitre.org/XMLSchema/oval-system-characteristics-5#unix',
            'ind-sys': 'http://oval.mitre.org/XMLSchema/oval-system-characteristics-5#independent',
            'lin-sys': 'http://oval.mitre.org/XMLSchema/oval-system-characteristics-5#linux',
            'win-sys': 'http://oval.mitre.org/XMLSchema/oval-system-characteristics-5#windows',
            '': 'http://oval.mitre.org/XMLSchema/oval-system-characteristics-5',
        }

        # Extraction des éléments nécessaires
        primary_host_name = root.find('.//system_info/primary_host_name', namespaces)
        timestamp = root.find('.//generator/oval:timestamp', namespaces)

        # Affichage des résultats
        if timestamp is not None and primary_host_name is not None:
            timestamp = timestamp.text
            nom = primary_host_name.text
        else:
            print("erreur: Date ou Nom du serveur non trouve")
            exit()

        namespaces = {
            '': 'http://oval.mitre.org/XMLSchema/oval-results-5',  # Espace de noms par défaut
        }

        # 1. Recherche des balises <definition> contenant l'attribut result="true"
        for definition in root.findall('.//definition[@result="true"]', namespaces):
            definition_id = definition.get('definition_id')
            version = definition.get('version')
            result = definition.get('result')
            #Stockage dans tableau
            if definition_id and version and result == "true":
                definitions_found.append({
                    'definition_id': definition_id,
                    'version': version,
                    'result': result
                })

        if definitions_found:
            print("Définitions trouvées avec result='true' :")
        else:
            print("Aucune définition avec result='true' n'a été trouvée.")

        # 2. Recherche des balises <definition> avec class="patch" et correspondances de definition_id
        score = 0
        nb_vuln = 0
        namespaces2 = {
            '': 'http://oval.mitre.org/XMLSchema/oval-definitions-5',  # Espace de noms par défaut
        }
        for definition in root.findall('.//definitions/definition[@class="patch"]', namespaces2):
            definition_id = definition.get('id')
            version = definition.get('version')
            class_attr = definition.get('class')

            for item in definitions_found:
                if item['definition_id'] == definition_id:
                    title = None
                    description = None
                    severity = None
                    for child in definition:
                        if child.tag.endswith('metadata'):
                            for metadata_child in child:
                                if metadata_child.tag.endswith('title'):
                                    title = metadata_child.text
                                    match = re.search(r'\((.*?)\)', title)
                                    if match:
                                        severity = match.group(1)
                                        nb_vuln +=1
                                        if severity == "Low":
                                            score += 1
                                        elif severity == "Medium":
                                            score += 2
                                        elif severity == "Important":
                                            score += 3
                                        elif severity == "Critical":
                                            score += 4


                                if metadata_child.tag.endswith('description'):
                                    description = metadata_child.text



                    patch_definitions_found.append({
                        'definition_id': definition_id,
                        'version': version,
                        'class': class_attr,
                        'titre': title,
                        'description': description,
                        'severity': severity,
                    })


        print("Date :" + timestamp)
        print("SERVEUR:" + nom)
        print("SCORE:" + str(score))
        print("NOMBRE VULN:" + str(nb_vuln))
        score_moyenne = round(score / nb_vuln,1) if nb_vuln else 0
        print("SCORE MOYEN:" + str(score_moyenne))

        # Insertion des données dans la base
        insert_query = """
            INSERT INTO evaluation (serveur, datetest, profil, score, type, nb_vuln)
            VALUES (%s, %s, %s, %s, %s, %s)
        """
        cursor.execute(insert_query, (nom, timestamp, "oscap-oval", score, "vulnerabilites", nb_vuln))
        conn.commit()


        # Récupération de l'ID de l'évaluation
        select_query = """
            SELECT id FROM evaluation WHERE serveur = %s AND datetest = %s
        """
        cursor.execute(select_query, (nom, timestamp))
        eval_id = cursor.fetchone()[0]


        if patch_definitions_found:
            for item in patch_definitions_found:
                insert_patch_query = """
                    INSERT INTO vulnerability (eval, titre, severity, description)
                    VALUES (%s, %s, %s, %s)
                """
                cursor.execute(insert_patch_query, (eval_id, item['titre'], item['severity'], item['description']))
                conn.commit()
                #print(f"ID NEW:{item['definition_id']}, Version: {item['version']}, Class: {item['class']}, Titre: {item['titre']}, Description: {item['description']}, Severity: {item['severity']}")
                print(f"ID NEW:{item['definition_id']}, Version: {item['version']}, Class: {item['class']}, Severity  {item['severity']}")
        else:
            print("\nAucune définition avec class='patch' n'a été trouvée.")

    except FileNotFoundError:
        print(f"Le fichier {xml_file} est introuvable.")
    except ET.ParseError:
        print(f"Le fichier {xml_file} est mal formé.")
    except Exception as e:
        print(f"Erreur inattendue : {e}")

# Exemple d'appel de la fonction
xml_file = 'oscap-oval-result.xml'  # Remplacez par le chemin correct de votre fichier XML
analyze_xml_and_patch(xml_file)

