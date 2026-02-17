import pymysql

def get_info_from_bdd(uid):
    """
    Récupère les informations d'une carte et de l'utilisateur associé.
    Retourne une liste avec 0 ou 1 dict selon si la carte existe.
    """
    result = []

    connection = pymysql.connect(
        host='127.0.0.1',
        user='root', #nfc',
        password='root',#mif4reisbrok3n',
        database='company_users',
        cursorclass=pymysql.cursors.DictCursor
    )

    try:
        with connection.cursor() as cursor:
            # On récupère la carte avec le uid
            sql_card = "SELECT num_card, uid, access_rights FROM cards WHERE uid = %s"
            cursor.execute(sql_card, (uid,))
            cards = cursor.fetchall()
            print(cards)
            if len(cards) == 0:
                # Carte non trouvée
                return []

            card_info = cards[0]

            # On récupère l'utilisateur associé via num_card
            sql_user = """
                SELECT last_name, first_name, entry_date, exit_date, email, role
                FROM users
                WHERE num_card = %s
            """
            cursor.execute(sql_user, (card_info["num_card"],))
            users = cursor.fetchall()

            if len(users) == 1:
                user_info = users[0]
                # Convertir dates en ISO et droits en string
                user_info["entry_date"] = user_info["entry_date"].isoformat()
                user_info["exit_date"] = user_info["exit_date"].isoformat()
                #card_info["access_rights"] = card_info["access_rights"]

                # Fusionner infos carte + utilisateur
                merged = {**card_info, **user_info}
                result.append(merged)

    finally:
        connection.close()

    return result
    
def create_blocks_from_bdd(info):
    """
    Crée la liste de blocs exactement comme la carte attend :
    blocs 4-5 : nom/prénom
    blocs 8-9 : entry_date / exit_date
    """
    def str_to_block(s):
        # Convertit string en bytes + padding 16
        b = bytes(s, "ascii")
        return b.ljust(16, b'\x00')
    
    lastName = str_to_block(info[0]["last_name"])
    firstName = str_to_block(info[0]["first_name"])

    entryDate_clean = ''.join(c for c in info[0]["entry_date"] if c.isdigit())
    exitDate_clean  = ''.join(c for c in info[0]["exit_date"] if c.isdigit())
    entryDate = str_to_block(entryDate_clean)
    exitDate  = str_to_block(exitDate_clean)

    # bloc vide ici
    accessRights = b"\x00" * 16

    # On retourne un dict bloc → bytes pour pouvoir écrire directement sur les bons blocs
    return {
        4: lastName,
        5: firstName,
        8: entryDate,
        9: exitDate,
        10: accessRights
    }
