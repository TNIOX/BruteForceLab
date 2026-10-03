================================================================================
  BruteForceLab v1.0
  Outil PEDAGOGIQUE d'essai de mots de passe sur formulaire de connexion web
================================================================================

  Fichiers de ce dossier
  -----------------------
    bruteforce.py      L'OUTIL PRINCIPAL. Interface interactive et ligne de
                       commande. C'est celui-la qu'on utilise.
    lab_server.py      Laboratoire local : un formulaire de connexion
                       volontairement vulnerable, pour s'entrainer sans
                       risque sur aucune vraie cible. 7 profils reproduisent
                       le comportement de DVWA, WordPress, Mutillidae,
                       phpMyAdmin, WebGoat et Tomcat Manager.
    test.py            Inspecteur de formulaire. A lancer AVANT toute attaque :
                       il revele les noms de champs, la methode HTTP et les
                       indices permettant de detecter une reussite.
    bruteforcessh.py   Version simplifiee et commentee du script d'origine,
                       conservee pour comparaison pedagogique.
    MANUEL.md          Manuel d'utilisation complet (cours, exercices, cas
                       particuliers, depannage).
    readme.txt         Ce fichier.
    requirements.txt   Dependance : requests.
    dico_labo.txt      Dictionnaire de demonstration : 20 mots, utilise par
                       le demarrage rapide et les exercices du manuel.
    dico_metasploitable.txt
                       Identifiants par defaut documentes de la VM
                       Metasploitable2 (DVWA, Mutillidae, phpMyAdmin,
                       Tomcat, WebGoat). Voir la section METASPLOITABLE2.
    dico.txt           Dictionnaire principal : 10 000 mots de passe courants.
    common_roots.txt   Second dictionnaire (racines de mots de passe).
    tests/             Suite de tests (70 tests) et recette bout en bout :
                       tests/recette/lancer_recette.sh.
    resultats/         Dossier des rapports, cree automatiquement.

  La documentation detaillee est dans MANUEL.md. Ce fichier est un resume.


================================================================================
  AVERTISSEMENT
================================================================================

  Cet outil sert a DEMONTRER une faiblesse de securite, dans un cadre
  pedagogique : laboratoire local, machines virtuelles d'un atelier de
  cybersecurite, ou cible couverte par un contrat de tests d'intrusion
  ecrit.

  En dehors de ces cadres, l'essai automatise de mots de passe constitue une
  atteinte aux systemes de traitement automatise de donnees (article 323-1 du
  code penal) et un acces frauduleux a un systeme informatique.

  Par defaut, l'outil REFUSE toute cible qui n'est pas en reseau prive
  (localhost, 10/8, 172.16/12, 192.168/16, .local, .test...). Pour une autre
  cible, il faut ajouter --i-have-authorization, ce qui consigne votre
  responsabilite dans le rapport.


================================================================================
  INSTALLATION
================================================================================

  Prerequis : Python 3.8 ou superieur, et le module requests.

      cd BruteForce
      python3 -m pip install -r requirements.txt

  Si l'installation globale est refusee (Debian, Ubuntu), utilisez un
  environnement virtuel :

      python3 -m venv .venv
      source .venv/bin/activate
      python3 -m pip install -r requirements.txt

  Verification :

      python3 bruteforce.py --version


================================================================================
  DEMARRAGE RAPIDE (5 MINUTES)
================================================================================

  TERMINAL A - lancer le laboratoire :

      python3 lab_server.py --port 8080

      Le compte du laboratoire est  admin / Lab2024!
      (volontairement trivial : on travaille la methode, pas la resistance)

  TERMINAL B - inspecter la cible (toujours avant d'attaquer) :

      python3 bruteforce.py --inspect -u http://127.0.0.1:8080/login

  TERMINAL B - lancer les essais (dico_labo.txt pour un resultat
  reproductible ; le mot de passe y est en 6e position) :

      python3 bruteforce.py -u http://127.0.0.1:8080/login -U admin \
             -l login -p pass -w dico_labo.txt -d 0.2

      -> 6 essais, MOT DE PASSE TROUVE : admin : Lab2024!

  TERMINAL B - decouvrir l'interface guidee :

      python3 bruteforce.py

  Pour observer une protection efficace, relancez le laboratoire avec
  verrouillage de compte ; l'outil s'arretera de lui-meme :

      python3 lab_server.py --port 8081 --lockout 5


================================================================================
  LES DEUX OPTIONS ESSENTIELLES
================================================================================

  Ce sont les deux informations que la majorite des scripts oublient, et la
  cause n°1 de l'echec d'un brute force.

  -l, --login-field      nom du champ identifiant
                         (attribut name="..." du formulaire)
  -p, --password-field   nom du champ mot de passe

  Pour les trouver, deux possibilites :

    1. L'outil les devine :

           python3 bruteforce.py --inspect -u URL_DU_FORMULAIRE

        Il affiche un tableau des champs du formulaire, le role devine pour
        chacun, et les valeurs a passer a -l et -p.

    2. Vous regardez le code source de la page (clic droit > "Afficher le
       code source") et vous relevez les attributs name= du <form>.


================================================================================
  MODE INTERACTIF
================================================================================

  Lancez sans aucun argument :

      python3 bruteforce.py

  L'outil pose les questions une par une, en pre-remplissant ce qu'il peut
  deviner (URL d'action, methode HTTP, noms de champs, champs caches).
  Appuyez sur Entree pour accepter les valeurs proposees entre crochets.

  Etapes : 1. cible  2. formulaire detecte  3. methode et champs
           4. identifiants et dictionnaire  5. rythme et detection
  Puis un recapitulatif, et une confirmation. Rien n'est envoye avant votre
  accord. Ctrl+C arrete proprement et enregistre le rapport.


================================================================================
  EXEMPLES EN LIGNE DE COMMANDE
================================================================================

  Formulaire web classique :

      python3 bruteforce.py -u http://192.168.1.54/login.php -U admin \
          -l login -p pass -d 0.5

  Deux identifiants :

      python3 bruteforce.py -u URL -U admin,root -l login -p pass

  Essai rapide sur une cible de laboratoire :

      python3 bruteforce.py -u URL -U admin -w dico_labo.txt -d 0.2

  Formulaire en GET :

      python3 bruteforce.py -u URL -U admin -m GET -l identifiant -p motdepasse

  API JSON :

      python3 bruteforce.py -u https://api.interne.fr/auth -U sarah -T json \
          -l username -p password -H "Authorization: Bearer ABC"

      Sur le laboratoire local :

      python3 bruteforce.py -u http://127.0.0.1:8080/api/login -U admin \
          -T json -l login -p pass -w dico_labo.txt -d 0.2 \
          --success-pattern '"status": *"ok"'

  Avec detection explicite par motifs (le plus fiable) :

      python3 bruteforce.py -u URL -U admin \
          --success-pattern "Connexion reussie" \
          --failure-pattern "Mot de passe invalide"

  Avec reussite signalee par une redirection :

      python3 bruteforce.py -u URL -U admin --success-on-redirect

  Champ supplementaire (case "se souvenir de moi", domaine, langue...) :

      python3 bruteforce.py -u URL -U admin -e "remember=1" -e "lang=fr"

  Voir la requete sans envoyer d'authentification :

      python3 bruteforce.py -u URL -U admin --dry-run

  Reprendre un dictionnaire interrompu a la ligne 5000 :

      python3 bruteforce.py -u URL -U admin -s 5000

  Liste complete des options :

      python3 bruteforce.py --help


================================================================================
  OPTIONS PRINCIPALES
================================================================================

  Cible et champs
    -u, --url URL                URL de la page de connexion (obligatoire)
    -U, --user IDENTIFIANT        identifiant a tester, -U a -U b ou "a,b"
    -l, --login-field NOM         nom du champ identifiant   (defaut : login)
    -p, --password-field NOM      nom du champ mot de passe  (defaut : pass)
    -m, --method GET|POST         methode HTTP               (defaut : POST)
    -T, --body-type form|json     encodage du corps POST     (defaut : form)
    -e, --extra-field CLE=VALEUR  champ supplementaire, repetable
        --profil NOM               dvwa, wordpress, mutillidae, phpmyadmin,
                                   webgoat ou tomcat : preremplit les options
                                   de l'application

  Dictionnaire et rythme
    -w, --dictionary FICHIER      fichier de mots de passe   (defaut : dico.txt)
    -d, --delay SECONDES          delai entre deux essais    (defaut : 0.5)
    -k, --max-attempts N          nombre maximum d'essais
    -s, --start N                 reprendre a la ligne N
    -t, --timeout SECONDES        delai d'attente reseau     (defaut : 10)

  Detection de la reussite
        --success-pattern REGEX   texte present en cas de reussite
        --failure-pattern REGEX   texte present en cas d'echec
        --success-on-redirect    une redirection 3xx vaut reussite
        --no-success-on-redirect l'inverse, pour neutraliser un profil
--no-calibration         ne pas envoyer de requete sonde
         --follow-redirects       suivre les 3xx pour comparer la page atteinte
         --no-follow-redirects    l'inverse, pour neutraliser un profil
         --refresh-csrf           recharger le jeton CSRF avant chaque essai
        --no-refresh-csrf        l'inverse, pour neutraliser un profil
        --stop-on-suspect        s'arreter sur une reponse inhabituelle
        --basic-auth              authentification HTTP Basic : les
                                   identifiants vont dans l'en-tete
                                   Authorization, pas dans un formulaire

  Reseau
    -H, --header "CLE: VALEUR"    en-tete supplementaire, repetable
    -c, --cookie CLE=VALEUR       cookie supplementaire, repetable
    -I, --insecure                ignorer la verification du certificat TLS
        --user-agent TEXTE        valeur de l'en-tete User-Agent

  Divers
        --inspect                 analyser le formulaire et proposer les valeurs
        --dry-run                 afficher la requete sans l'envoyer
        --results-dir DOSSIER     dossier des rapports (defaut : resultats)
        --i-have-authorization    autoriser une cible hors reseau prive
    -V, --version                 version
    -h, --help                    aide complete


================================================================================
  COMMENT L'OUTIL DETECTE-T-IL UNE REUSSITE ?
================================================================================

  C'est le point delicat du brute force, et la principale correction apportee
  au script d'origine.

  Le script d'origine faisait :

      if "Mot de passe invalide" in r.text :
          print("Perdu")
      else :
          print("Trouve")        <-- FAUX

  Cette logique est fausse : tout ce qui n'est PAS le message d'erreur est
  interprete comme une reussite. Une erreur 500 du serveur, une page de
  maintenance, un delai dépassé, un proxy d'entreprise : l'outil annonce un
  mot de passe trouve alors que c'est faux.

  L'outil applique trois strategies, de la plus fiable a la moins fiable :

  1. MOTIFS EXPLICITES. Vous donnez le texte de la reussite et de l'echec.
     C'est exact. A utiliser des que vous le connaissez.

         --success-pattern "Connexion reussie" --failure-pattern "invalide"

  2. CALIBRATION (mode par defaut). Avant l'attaque, l'outil envoie une
     requete avec un mot de passe aleatoire de 30 caracteres, impossible a
     deviner. La reponse obtenue EST la reponse d'echec de reference, et
     toutes les reponses suivantes sont comparees a cette reference.

         + Calibration effectuee - reference d'echec : HTTP 401 | 2885 o

  3. STATISTIQUES (seulement avec --no-calibration). L'outil regroupe les
     reponses identiques et considere que le groupe le plus frequent est
     l'echec.

  Pour comparer deux reponses, l'outil nettoie d'abord la page de ses parties
  variables (jeton CSRF, date, numero de tentative) puis calcule une
  empreinte : code HTTP + longueur + empreinte SHA-256 du contenu.

  Chaque essai est classe en :

    ECHEC    la reponse est identique a la reference
    SUCCES   la reponse differe nettement, l'essai s'arrete
    SUSPECT  meme taille qu'un echec mais contenu different : A VERIFIER

  Pour savoir quel critere employer sur votre cible, lancez l'inspecteur avec
  un mot de passe que vous supposez valide ; il affiche les deux reponses
  cote a cote :

      python3 test.py -u URL -U admin -P 'LE_BON_MOT_DE_PASSE'


================================================================================
  RESULTATS
================================================================================

  A l'ecran :

      [##########..............]  40.0%  400/1000  4.8/s  restant 01:02

  (sur un terminal, la ligne est reecrite en place ; dans un fichier de log,
  un point de suivi est affiche tous les 100 essais)

  Sur disque, dans resultats/ (ou --results-dir) :

      rapport_AAAAMMJJ_HHMMSS.json   donnees structurees, pour un traitement
                                     automatique
      rapport_AAAAMMJJ_HHMMSS.txt    rapport lisible, a joindre a un audit

  Codes de sortie (utiles pour enchainer les commandes) :

      0    mot de passe trouve, ou --inspect / --dry-run reussi
      1    erreur : cible refusee, dictionnaire introuvable, reseau injoignable
      2    aucun mot de passe trouve (dictionnaire entierement epuise)
      130  essai interrompu par Ctrl+C : resultat PARTIEL, a ne pas confondre
           avec le code 2

  Avec --no-calibration, les DEUX premieres reponses ne sont pas classifiables
  (aucune reference d'echec n'existe encore). Le rapport indique le nombre :

      Non classifiables    2 reponse(s) avant etablissement de la reference


================================================================================
  PROBLEMES COURANTS
================================================================================

  "Aucun mot de passe trouve" et 0 essay
      Nom du champ du mot de passe incorrect. Verifiez avec --dry-run.

  "Dictionnaire introuvable" / "Fichier introuvable"
      Chemin incorrect. Utilisez un chemin complet : -w /chemin/dico.txt

  "Aucun formulaire <form> detecte"
      La connexion se fait par JavaScript. Ouvrez les outils de developpement
      du navigateur, onglet Network, et relevez l'URL de l'API appelee.

  Arret sur "Blocage detecte"
      La cible se protege. C'est le comportement attendu d'une application
      correctement configuree. NE TENTEZ PAS de le contourner.
      Pour continuer a s'entrainer : relancez le lab avec --lockout 0.

  Reponses toutes classees SUSPECT
      La page d'erreur est dynamique. Ajoutez --failure-pattern, ou
      --no-calibration.

  Trop lent
      Reduisez -d (0.1 en laboratoire) et -t (5).

  "La cible n'est pas un reseau prive"
      Ajoutez --i-have-authorization si vous avez une autorisation ecrite.


================================================================================
  SE PROTEGER : CE QU'IL FAUT RETENIR
================================================================================

  1. LA LONGUEUR BAT LA COMPLEXITE. 12 caracteres aleatoires, ou une phrase de
     passe de 5 mots, resistent a un dictionnaire. Un mot de passe court et
     compliqué, non.

  2. VERROUILLER ET LIMITER LE DEBIT. Apres 5 a 10 echecs : blocage du compte ET
     limitation par adresse IP. C'est la protection la plus efficace contre le
     brute force. Prevoyez un deverrouillage automatique, sinon vous creerez un
     deni de service.

  3. AJOUTER UN SECOND FACTEUR. Un mot de passe vole ou devine ne suffit plus.

  4. REPONDRE DE FACON UNIFORME. Meme message, meme code HTTP, meme temps de
     reponse pour "identifiant inconnu" et "mot de passe faux", sinon
     l'enumeration des comptes devient possible.

  5. SURVEILLER LES ECHECS. Alerter sur un pic d'echecs d'authentification :
     c'est ainsi qu'une attaque est detectee en cours.

  6. NE JAMAIS TRANSMETTRE LES IDENTIFIANTS EN GET. Ils restent dans
     l'historique du navigateur, les journaux du serveur, les mandataires et
     l'en-tete Referer.

  7. HACHER CORRECTEMENT. bcrypt, scrypt ou Argon2, avec sel. MD5 et SHA-1 se
     cassent hors ligne a des vitesses records.

  8. REFUSER LES MOTS DE PASSE DEJAS VOLES. Peu couteux, tres efficace.


================================================================================
  CONVENTIONS DU SERVEUR DE LABORATOIRE
================================================================================

  python3 lab_server.py [options]

      --host ADRESSE      adresse d'ecoute      (defaut : 127.0.0.1)
      --port PORT         port d'ecoute         (defaut : 8080)
      --user NOM          identifiant valide    (defaut : admin)
      --password MDP      mot de passe valide    (defaut : Lab2024!)
      --lockout N         bloquer apres N echecs (defaut : 0, desactive)
      --latency SEC       delai artificiel par requete
      --quiet             reduire la verbosite

  Pages disponibles :

      /login      formulaire de connexion (POST, et GET si des parametres
                  sont passes dans l'URL)
      /api/login  meme authentification en JSON (POST), pour le mode -T json
      /dashboard  espace connecte (apres authentification reussie)
      /stats      statistiques des tentatives recues
      /health     etat du serveur, au format JSON

  Le serveur n'ecoute que sur 127.0.0.1 par defaut : le laboratoire reste sur
  votre machine. Utiliser --host 0.0.0.0 le rend accessible au reseau local et
  declenche un avertissement.


================================================================================
  DICTIONNAIRES
================================================================================

  Format : un mot de passe par ligne. Les lignes vides et celles commencant
  par # sont ignorees. Lecture en UTF-8.

  dico_labo.txt     20 mots de demonstration. Utilise par le demarrage rapide
                    et les exercices du manuel : resultats reproductibles.
                    Lab2024! y est en 6e position.
  dico.txt          10 000 mots de passe courants, tries par frequence.
                    Les premiers sont password, 123456, 12345678...
                    ATTENTION : le mot de passe du laboratoire n'y figure pas,
                    une attaque complete ne le trouvera donc pas.
  common_roots.txt  4 725 racines de mots de passe, a combiner avec des
                    annees et des chiffres.

  Creer un dictionnaire de mots de passe themes d'un site donne :

      curl -s https://exemple.fr/robots.txt > brut.txt
      grep -oE '[A-Za-z0-9._-]{6,20}' brut.txt | sort -u > dico_cible.txt

  Rappel : ces listes ne servent que sur des cibles autorisees.


================================================================================
  METASPLOITABLE2 : DEMONSTRATIONS
================================================================================

  Metasploitable2 regroupe plusieurs applications web volontairement
  vulnerables. L'outil s'y utilise tel quel. Ce qu'il faut connaitre :

  Application   URL                        Champs         Reussite
  -----------   -------------------------   ------------   ----------------
  DVWA          /dvwa/login.php            username      302 vers
                                           password       /dvwa/index.php
                                           + bouton Login
Mutillidae    /mutillidae/index.php      username      page d'accueil :
                  ?page=login.php           password       "Not Logged In"
                                           + bouton       devient "Logged In"
  WordPress     /wp-login.php              log, pwd      302 vers /wp-admin/
phpMyAdmin    :80/phpMyAdmin/            pma_username  page d'accueil
                 index.php                 pma_password  ("server version")
  WebGoat       :8180/WebGoat/attack       AUCUN champ : 200 sur la page
                                             en-tete HTTP  d'accueil
                                             Basic
  Tomcat        :8180                      AUCUN champ : 200 sur la page
                  /manager/html              en-tete HTTP  d'accueil
                                            Basic

  Sept details verifies sur une vraie VM, contre-intuitifs :

    - DVWA n'expose aucun user_token sur sa page de connexion : c'est le
      BOUTON "Login" qui compte. Sans lui, le serveur renvoie la page du
      formulaire sans dire non : l'outil prendrait un refus muet pour un
      echec d'authentification. --inspect le repere et l'envoie tout seul.
    - MUTILLIDAE se connecte avec admin/adminpass, et sa page d'erreur
      rafraichit la requete SQL complete (identifiant et mot de passe
      visibles). Chaque essai change donc la longueur de la page. L'outil
      masque la valeur qu'il vient d'envoyer quand elle revient dans une
      affectation d'identifiant, sinon il annonce une reussite au 1er essai.
    - PHPMYADMIN repondait 302 avec un corps VIDE, que la connexion reussisse
      ou non : le profil active donc --follow-redirects, et c'est la page
      atteinte qui distinguait "#1045 - Access denied" de l'accueil. Ce n'est
      plus le cas sur l'image actuelle (constate le 2026-10-03) : GET
      /phpMyAdmin/ repond 200 avec le formulaire, et le POST de connexion
      donne 2390 o sur succes contre 3379 o en echec. Les empreintes se
      distinguent donc sans suivre la redirection ; --follow-redirects reste
      actif par precaution, il est inoffensif dans les deux cas.
    - PHPMYADMIN est sur le port 80 et la casse compte : /phpMyAdmin/ est
      servi, /phpmyadmin/ repond 404.
    - TOMCAT n'ecoute pas sur 8080 : ici c'est 8180 (AJP sur 8009). Tester
      le port avant de lancer la commande.
    - WEBGOAT n'a AUCUN formulaire, contrairement a ce que la plupart des
      cours montrent. Sa page web.xml ne declare qu'un login-config BASIC, et
      son code ne contient ni Acegi ni filtre de formulaire : la seule
      authentification est celle de Tomcat. On attaque donc WebGoat exactement
      comme le Manager, avec --profil tomcat et -U webgoat. Viser
      /WebGoat/attack, pas /WebGoat/ : la racine n'a pas de fichier
      d'accueil. Elle repond 401 tant qu'on n'est pas authentifie (la
      contrainte de securite Tomcat couvre tout /WebGoat/*), puis 404 une
      fois les identifiants fournis. L'outil compte les deux comme echec, mais
      il ne faut pas les confondre en demonstrations.

  WORDPRESS et WEBGOAT repondent 404 dans l'image Metasploitable2 d'origine :
  ce sont des paquets optionnels, absents par defaut. Ils ont ete installes a
  la main sur la VM de l'atelier (voir MANUEL.md, section 8.9) ; le
  laboratoire les reproduit de toute facon.

  IMAGE DE LA VM

  L'image utilisee pour les demonstrations ci-dessous n'est pas celle
  d'origine : WordPress et WebGoat y ont ete installes a la main. Elle est
  telechargeable ici :

      https://drive.google.com/file/d/1sdb6pebI5dAUI139IEtLd3DdyVOgCHah/view

  Fichier : metasploitable2-2026-10-03.ova, 1,01 Go, archive TAR simple
  (non compressee). VirtualBox l'importe tel quel, sans decompression
  prealable (Fichier > Importer un appliance). Son contenu :
  Ubuntu 8.04, Apache 2.2.8, MySQL 5.0.51a, Tomcat 5.5, WordPress 3.9.2,
  WebGoat 5.3. Les identifiants figurent dans MANUEL.md, section 8.9.

  L'adresse IP de la VM est attribuee par DHCP et change : ne jamais
  l'ecrire en dur, utiliser adresse_vm.sh, qui la retrouve par l'adresse MAC
  de la carte (seule chose stable) :

      VM=$(./adresse_vm.sh)

  Ce script ne renvoie aucune adresse de repli : introuvable, il sort en
  erreur. Viser l'adresse d'une autre machine serait pire que de ne rien
  lancer. La VM est sur un reseau prive : l'outil ne demande pas
  --i-have-authorization. Il refuserait une adresse publique.

  --- 1. REPETER LA DEMONSTRATION HORS LIGNE (RECOMMANDE) -------------------

  Le laboratoire reproduit le comportement de chacune de ces applications :
  memes champs, memes codes HTTP, memes messages. Il amplifie volontairement
  deux points pour rester pedagogique : le profil dvwa exige un user_token
  et le profil mutillidae laisse entrer n'importe quel couple.
  On prepare donc la demonstration sans solliciter la VM.

  TERMINAL A - la cible :

      python3 lab_server.py --port 8080 --profil dvwa

  TERMINAL B - l'attaque :

      python3 bruteforce.py --profil dvwa \
          -u http://127.0.0.1:8080/dvwa/login.php \
          -U admin -w dico_metasploitable.txt -d 0.3

  Resultat attendu : "MOT DE PASSE TROUVE - admin : password" au 1er essai.

  --profil dvwa active 4 options : -l username, -p password, --refresh-csrf
  et --success-on-redirect. Une option ecrite a la main gagne sur le profil,
  et --no-refresh-csrf / --no-success-on-redirect / --no-follow-redirects
  le neutralisent. Le profil ne fait que preremplir des options : la commande
  sans profil reste entierement lisible :

      python3 bruteforce.py -u http://127.0.0.1:8080/dvwa/login.php \
          -U admin -l username -p password -w dico_metasploitable.txt \
          --refresh-csrf --success-on-redirect -d 0.3

  Viser seulement la racine marche aussi : chaque profil redirige "/" vers
  sa propre page, ce qui evite le 404 puis le "aucun couple trouve" sans
  explication. Le profil interne sert directement sa page a la racine.

  Profils du laboratoire :
      interne     intranet : echec 401, reussite par une page
      dvwa        echec 200 "Login failed", reussite 302, jeton verifie
      wordpress   champs log/pwd, echec 200 "ERROR: ...", reussite 302
      mutillidae  connexion ouverte : n'importe quel couple passe
      phpmyadmin  champs pma_username/pma_password, redirections suivies
      webgoat     echec 200 "Invalid credentials", jeton csrf, reussite 302
      tomcat      authentification HTTP Basic : echec 401, reussite 200

  Une nuance sur le profil webgoat du laboratoire : il imite un WebGoat
  dote d'un FORMULAIRE (username, password, jeton csrf), parce que c'est la
  version que les cours de l'OWASP decrivent. Le WebGoat 5.3 reellement
  deploye sur la VM ne l'a pas : voir le detail plus haut. Sur la vraie VM,
  preferer donc --profil tomcat -U webgoat.

  --- 1 bis. TOMCAT : PAS DE FORMULAIRE, MAIS UN EN-TETE --------------------

  Tomcat ne propose aucun formulaire : /manager/html repond aussitot

      HTTP/1.1 401 Unauthorized
      WWW-Authenticate: Basic realm="Tomcat Manager Application"

  Le nom du realm change avec la version ("Manager Tomcat" sur les Tomcat
  recentes). Sans importance pour l'attaque, utile pour identifier la VM.

  Les identifiants voyagent dans l'en-tete Authorization, en base64 - un
  simple encodage, pas un chiffrement :

      Authorization: Basic dG9tY2F0OnRvbWNhdA==   # « tomcat:tomcat »

  L'option --basic-auth (dej incluse dans --profil tomcat) place les
  identifiants dans l'en-tete au lieu d'un corps de requete :

      python3 bruteforce.py --profil tomcat \
          -u http://127.0.0.1:8080/manager/html \
          -U tomcat -w dico_metasploitable.txt -m GET

  Sur la VM Tomcat du chapitre Metasploitable2, remplacer 127.0.0.1:8080 par
  l'adresse de la VM et le port 8180.

  Resultat attendu : "MOT DE PASSE TROUVE - tomcat : tomcat".

  Deux pieges utiles en cours :
    - le 401 est une REPONSE D'ECHEC : sans identifiants, toutes les
      tentatives rendent la meme page, et l'outil doit conclure qu'il n'y
      a rien a trouver ;
    - le port n'est pas 80 : 8080 sur la VM d'origine, 8180 sur une
      installation de Tomcat par les paquets Debian. Sur le bon chemin mais
      le mauvais port, on tombe sur la page d'accueil ou sur un 404, et on
      croit l'application absente. Tester d'abord a la main :
          for p in 80 8080 8180; do
              timeout 2 bash -c "echo > /dev/tcp/IP/$p" 2>/dev/null \
                  && echo "$p ouvert" || echo "$p ferme"
          done

  --- 2. SUR LA VRAIE VM ---------------------------------------------------

      # 1. L'adresse de la VM (Vagrant, ou la valeur notee a l'installation)
      ping -c1 192.168.56.4

      # 2. Analyser le formulaire : aucune authentification n'est envoyee
      python3 bruteforce.py --inspect -u http://192.168.56.4/dvwa/login.php

      # 3. Voir la requete qui partirait, toujours sans l'envoyer
      python3 bruteforce.py --profil dvwa -U admin \
          -u http://192.168.56.4/dvwa/login.php --dry-run

      # 4. L'attaque, limitee a vingt essais
      python3 bruteforce.py --profil dvwa -U admin -k 20 -d 0.5 \
          -u http://192.168.56.4/dvwa/login.php \
          -w dico_metasploitable.txt

  L'etape 2 evite les mauvaises surprises : --inspect affiche les noms de
  champs trouves et les valeurs suggerees.

  Pendant l'essai, dans la VM :

      sudo tail -f /var/log/apache2/access.log

  C'est la demonstration la plus parlante du cout reel d'un brute force : les
  lignes defilent, et le journal se remplit.

  --- 3. LE PIEGE DU JETON DE SESSION (A MONTRER EN COURS) ------------------

  Le profil dvwa du laboratoire regenere user_token a chaque affichage de
  page et le verifie a chaque envoi. Sur la VM testee ici, ce formulaire n'a
  pas de jeton : c'est le bouton Login qui fait foi.
  Sans --refresh-csrf, la requete de calibration consomme le jeton :
  tous les essais suivants sont rejetes, l'outil affiche "aucun couple
  trouve" et renvoie le code 2, alors que la cible a bien recu les requetes.

  1. Lancer sans --refresh-csrf      -> aucun couple trouve, code 2
  2. Montrer access.log dans la VM   -> les requetes SONT bien arrivees
  3. Relancer avec --refresh-csrf    -> le mot de passe est trouve

  Avec le laboratoire local, la meme demonstration en une commande :

      python3 bruteforce.py --profil dvwa --no-refresh-csrf -k 4 \
          -u http://127.0.0.1:8080/dvwa/login.php -U admin \
          -w dico_metasploitable.txt

  --- 4. REMETTRE LA VM A ZERO ENTRE DEUX DEMONSTRATIONS --------------------

      DVWA        bouton "Reset Database" sur la page d'accueil
      Mutillidae  lien "Reset DB" dans le menu
      WordPress   rien a faire

  Si les journaux saturent le disque de la VM, redemarrer la machine suffit.

  --- 5. CE QUE CHAQUE APPLICATION ENSEIGNE ----------------------------------

  DVWA       un jeton lie a la session n'arrete pas une attaque automatique :
             il oblige a recharger la page, donc a doubler le nombre de
             requetes - et rend l'attaque deux fois plus visible.
  Mutillidae sa page d'erreur renvoie la requete SQL complete, identifiant
             et mot de passe inclus. C'est une mine d'or pour l'attaquant et
             un piege pour l'outil : sa reponse "differente" n'est que
             l'echo de l'essai. Une bonne detection doit savoir se taire.
  WordPress  des noms de champs non conventionnels (log, pwd) suffisent a
             faire echouer un script qui suppose username/password.
             --inspect evite l'erreur.
  phpMyAdmin un prefixe pma_ passe inapercu, et la reponse est un 302 au
             corps VIDE dans les deux cas. Sans suivre la redirection, rien
             n'est comparable : le profil active --follow-redirects.

  Pour toutes, la parade reste le verrouillage de compte, la limitation de
  debit et le second facteur. Voir le chapitre 11 de MANUEL.md.

================================================================================
  VERIFIER QUE TOUT FONCTIONNE
================================================================================

  La suite de tests demarre elle-meme le laboratoire sur un port libre et ne
  touche que 127.0.0.1. Aucune dependance supplementaire.

      python3 tests/test_outils.py           # 70 tests, environ 40 s
      python3 tests/test_outils.py -v        # une ligne par test
      python3 tests/test_outils.py detection # une seule classe

  Recette complete (tests + pilotes bout en bout, 127.0.0.1 uniquement) :

      ./tests/recette/lancer_recette.sh

  Elle couvre l'analyse du formulaire, les trois strategies de detection, le
  mode --dry-run, les redirections, le verrouillage du compte, le contenu des
  rapports, la barre de progression dans un vrai terminal et le code 130 apres
  Ctrl+C, les 6 profils d'applications, le rechargement du jeton de session
  et l'authentification HTTP Basic de Tomcat.


================================================================================
  POUR ALLER PLUS LOIN
================================================================================

  - MANUEL.md : le manuel complet (cours, 7 exercices avec corrige, cas
    particuliers, depannage, annexes)
  - OWASP Testing Guide, chapitre Authentication : la reference pour planifier
    un test d'authentification
  - OWASP Password Storage Cheat Sheet : les bonnes pratiques de hachage
  - RFC 6585 : le code HTTP 429 Too Many Requests


================================================================================
  BruteForceLab v1.0 - outil pedagogique.
  Utilisez-le uniquement sur des cibles autorisees.
================================================================================
