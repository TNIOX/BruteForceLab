# BruteForceLab — Manuel d'utilisation

Outil pédagogique d'essai de mots de passe sur un formulaire de connexion web,
avec son propre laboratoire hors ligne pour s'entraîner.

**Cadre d'utilisation.** Cet outil sert à Demonstrer une faiblesse de sécurité
dans un cadre pédagogique : laboratoire local, machines virtuelles d'un atelier
de cybersécurité, ou cible couverte par un contrat de tests d'intrusion
écrit. Hors de ces cadres, l'essai automatisé de mots de passe est une
atteinte penalized en France (article 323-1 du code pénal) et constitutive
d'intrusion dans un système informatique dans la plupart des pays. L'outil
refuse par défaut toute cible hors réseau privé : voir § 2.4.

---

## Table des matières

1. [Ce que fait l'outil](#1-ce-que-fait-loutil)
2. [Installation](#2-installation)
3. [Démarrage rapide en 5 minutes](#3-démarrage-rapide-en-5-minutes)
4. [Mode interactif, pas à pas](#4-mode-interactif-pas-à-pas)
5. [Mode ligne de commande](#5-mode-ligne-de-commande)
6. [Détecter la réussite : le point délicat](#6-détecter-la-réussite-le-point-délicat)
7. [Lire les résultats](#7-lire-les-résultats)
8. [Cas particuliers](#8-cas-particuliers)
9. [Dépannage](#9-dépannage)
10. [Exercices guidés](#10-exercices-guidés)
11. [Sécuriser son application](#11-sécuriser-son-application)
12. [Annexes](#12-annexes)

---

## 1. Ce que fait l'outil

`bruteforce.py` envoie des requêtes HTTP d'authentification en essayant les
mots de passe d'un dictionnaire, un par un, jusqu'à trouver le bon ou à épuiser
la liste. Il s'arrête à la première réussite.

Il se distingue d'un script naïf sur quatre points, qui sont précisément les
défauts du script d'origine de ce dossier :

| Problème classique | Traitement ici |
|---|---|
| URL, identifiant et message d'erreur écrits en dur dans le code | Tout est paramétrable, ou saisi dans une interface guidée |
| Détection de la réussite par « si ce n'est pas le message d'erreur, c'est réussi » | Trois stratégies de détection, de la plus fiable à la moins fiable (§ 6) |
| Rafale de requêtes sans délai, qui bloque ou fait tomber la cible | Délai réglable, et arrêt immédiat si la cible se protège |
| `exit()` en cas de succès : aucune trace, aucun rapport | Rapport JSON et texte horodaté, interruption propre par `Ctrl+C` |

Points supplémentaires :

- détection automatique du formulaire et **suggestion des noms de champs** ;
- conservation des **champs cachés** (jetons CSRF), souvent oubliés et
  responsable de l'échec de la plupart des scripts ;
- arrêt automatique sur **verrouillage de compte** ou limitation de débit ;
- **laboratoire intégré** (`lab_server.py`) pour s'entraîner sans risque ;
- code et documentation en français.

---

## 2. Installation

### 2.1 Prérequis

- Python 3.8 ou plus récent (testé sur 3.14) ;
- le module `requests` ;
- aucune autre dépendance : l'analyse HTML utilise la bibliothèque standard.

### 2.2 Installation

```bash
cd BruteForce
python3 -m pip install -r requirements.txt
```

Si l'installation globale est refusée (Debian, Ubuntu), utilisez un
environnement virtuel :

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
```

Vérification :

```bash
python3 bruteforce.py --version
python3 bruteforce.py --help
```

### 2.3 Fichiers du dossier

| Fichier | Rôle |
|---|---|
| `bruteforce.py` | **L'outil principal.** Interface interactive et ligne de commande. |
| `lab_server.py` | Laboratoire local : formulaire de connexion volontairement vulnérable. Sept profils (`interne`, `dvwa`, `wordpress`, `mutillidae`, `phpmyadmin`, `webgoat`, `tomcat`) reproduisent le comportement d'applications de Metasploitable2. |
| `test.py` | Inspecteur de formulaire. À lancer **avant** toute attaque : il révèle les champs, la méthode et les indices de détection. |
| `bruteforcessh.py` | Version simplifiée et commentée du script d'origine, pour comparaison. |
| `MANUEL.md` | Ce manuel. |
| `readme.txt` | Résumé rapide en texte brut. |
| `dico_labo.txt` | Dictionnaire de démonstration : 20 mots, utilisé par le démarrage rapide et les exercices. |
| `dico_metasploitable.txt` | Identifiants par défaut documentés de la VM Metasploitable2, pour valider l'outil en un ou deux essais (§8.8). |
| `dico.txt` | Dictionnaire principal : 10 000 mots de passe courants. |
| `common_roots.txt` | Second dictionnaire (racines de mots de passe). |
| `resultats/` | Rapports générés (créé automatiquement). |

### 2.4 Contrôle d'accès à la cible

Par défaut, l'outil **accepte uniquement** les cibles suivantes :

- `localhost`, `127.0.0.0/8`, `::1` ;
- réseaux privés `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` ;
- adresses lien-local `169.254.0.0/16` ;
- noms de domaine internes `.local`, `.lan`, `.internal`, `.test`, `.home.arpa`.

Pour toute autre cible, l'outil s'arrête et le demande :

```
$ python3 bruteforce.py -u https://exemple.fr/login -U admin
  ! La cible exemple.fr n'est pas un réseau privé (10/8, 172.16/12, 192.168/16, localhost).
  i Cet outil pédagogique est prévu pour un laboratoire isolé ou une cible testée.
  x Utilisez --i-have-authorization si cette cible est couverte par une autorisation.
```

Si vous disposez d'une autorisation écrite, ajoutez `--i-have-authorization` :
vous assumez alors la responsabilité de l'opération, et l'outil le consigne
dans le rapport.

---

## 3. Démarrage rapide en 5 minutes

Le laboratoire intégré permet de s'entraîner sans toucher aucune vraie cible.

### Étape 1 — Ouvrir deux terminaux

**Terminal A**, lancer le laboratoire :

```bash
python3 lab_server.py --port 8080
```

```
==================================================================
  Serveur de laboratoire — cible d'entraînement BruteForceLab
==================================================================
  Adresse      : http://127.0.0.1:8080/login
  Compte       : admin / Lab2024!
  Verrouillage : désactivé
  Statistiques : http://127.0.0.1:8080/stats
  Arrêt        : Ctrl+C
==================================================================
```

Le compte du laboratoire est volontairement trivial : `admin` / `Lab2024!`.
Le but est de montrer la **méthode**, pas de prétendre que ce mot de passe est
sûr.

### Étape 2 — Inspecter la cible (obligatoire avant toute attaque)

**Terminal B** :

```bash
python3 bruteforce.py --inspect -u http://127.0.0.1:8080/login
```

Vous obtenez les noms de champs à utiliser, la méthode HTTP, et les champs
cachés à renvoyer :

```
── Formulaire de connexion analysé (formulaire n°1) ────────────────
  Action               http://127.0.0.1:8080/login
  Méthode              POST
  -----------------------------------------------------------------
  name        type      Rôle probable  Traitement  value
  -----------------------------------------------------------------
  csrf_token  hidden    champ caché    conserver   f9e84ed2685f4949
  login       text      identifiant ?  candidat
  pass        password  MOT DE PASSE   à tester
  -----------------------------------------------------------------
── Valeurs suggérées pour la ligne de commande ─────────────────────
  --login-field        login
  --password-field     pass
  Champs cachés        csrf_token
  i Ils sont envoyés automatiquement ; utilisez --extra-field pour les fixer.
```

### Étape 3 — Lancer l'attaque

On utilise ici `dico_labo.txt`, un dictionnaire de démonstration de 20 mots
livré avec l'outil, pour que le résultat soit reproductible. Le mot de passe
`Lab2024!` y est en 6ᵉ position.

```bash
python3 bruteforce.py -u http://127.0.0.1:8080/login -U admin \
       -l login -p pass -w dico_labo.txt -d 0.2
```

```
  + Champs cachés détectés et conservés : csrf_token
  + Calibration effectuée — référence d'échec : HTTP 401 | 2691 o | #dd0c33f2

── Essais en cours ─────────────────────────────────────────────────
  * SUCCÈS — admin : Lab2024!
  Empreinte            HTTP 200 | 2495 o | #8846591e

── Bilan ───────────────────────────────────────────────────────────
  Cible                http://127.0.0.1:8080/login
  Essais               6/20
  Durée                00:01
  Débit                4.8 tentatives/seconde
  Détection            calibration (requete sonde)
  Résultat             MOT DE PASSE TROUVÉ
   Essai n°6           admin : Lab2024!
  Rapport JSON         resultats/rapport_20260101_143022.json
  Rapport texte        resultats/rapport_20260101_143022.txt
```

### Étape 4 — Observer la protection

Relancez le laboratoire avec verrouillage, et recommencez :

```bash
python3 lab_server.py --port 8081 --lockout 5
```

L'outil s'arrête de lui-même :

```
  Remarque             Blocage détecté à l'essai 5 (HTTP 429).
                       La cible se protège : arrêt immédiat.
```

C'est le résultat attendu d'une application correctement configurée.

### Étape 5 — Découvrir l'interface guidée

```bash
python3 bruteforce.py
```

L'outil pose les questions une par une, en pré-remplissant ce qu'il peut
deviner. Voir § 4.

---

## 4. Mode interactif, pas à pas

Lancer sans aucun argument :

```bash
python3 bruteforce.py
```

### 4.1 Étape 1 — la cible

```
── 1. Cible ──────────────────────────────────────────────────────
  ? URL de la page de connexion
    >
```

Saisissez l'adresse. Le schéma `http://` est ajouté s'il est absent.

L'outil va chercher la page et **analyser le formulaire**, puis présenter le
résultat :

```
── 2. Formulaire détecté automatiquement ─────────────────────────
  -----------------------------------
  name        type      rôle probable
  -----------------------------------
  csrf_token  hidden    champ caché
  login       text      identifiant ?
  pass        password  mot de passe
  -----------------------------------
  Action détectée      http://192.168.1.54/login.php
  ? Utiliser cette URL d'action ? (O/n)
```

Si le formulaire envoie vers une autre page que celle visitée (fréquent :
`action="/connexion"`), répondez `o` pour suivre cette action.

### 4.2 Étape 2 — méthode et champs

```
── 3. Méthode et champs ─────────────────────────────────────────
  ? Méthode HTTP (GET/POST) [POST]
  i champ caché détecté : csrf_token (sera envoyé automatiquement)
  ? Nom du champ LOGIN (attribut name) [login]
  ? Nom du champ MOT DE PASSE (attribut name) [pass]
  ? Type de corps (form ou json) [form]
  ? Ajouter un champ supplémentaire (clé=valeur) ? (o/N)
```

- **Appuyez sur Entrée** pour accepter la valeur proposée entre crochets.
- Les champs cachés sont transmis automatiquement : ne les saisissez pas.
- `form` pour une application web classique, `json` pour une API.
- Le champ supplémentaire sert aux cas particuliers : case « se souvenir de
  moi », domaine, langue, `redirect_uri`…

### 4.3 Étape 3 — identifiants et dictionnaire

```
── 4. Identifiants et dictionnaire ───────────────────────────────
  ? Identifiant(s) à tester (séparés par des virgules) [admin]
  ? Chemin du dictionnaire [dico.txt]
```

Séparez plusieurs identifiants par des virgules : `admin,root,test`. Chaque
identifiant est testé avec tout le dictionnaire. Attention à l'explosion
combinatoire : 3 identifiants × 10 000 mots = 30 000 requêtes.

Le dictionnaire est un fichier texte, **un mot de passe par ligne**. Les
lignes vides et celles commençant par `#` sont ignorées.

### 4.4 Étape 4 — rythme et détection

```
── 5. Rythme et détection ───────────────────────────────────────
  ? Délai entre deux essais en secondes [0.5]
  ? Nombre maximum d'essais (0 = tout le dictionnaire) [0]
  ? Texte/regle marquant une RÉUSSITE (Entée = détection automatique)
  ? Texte/regle marquant un ÉCHEC (Entée = détection automatique)
```

- **Délai.** `0.5` s est un rythme raisonnable. `0` envoie les requêtes en
  rafale : réservé à votre laboratoire local.
- **Nombre maximum.** Utile pour estimer la vitesse, ou pour borner un essai
  d'outil.
- **Les deux motifs.** Laissez vides pour la détection automatique (§ 6). Si
  vous les connaissez, ils rendent la détection infaillible.

### 4.5 Récapitulatif et confirmation

Rien n'est envoyé avant votre accord. Vérifiez la ligne `Cible` et la ligne
`Essais prévus` — c'est le dernier moment pour rattraper une erreur de
saisie.

```
── Récapitulatif — vérifiez avant de lancer ──────────────────────
  Cible                http://192.168.1.54/login.php
  Méthode              POST (form)
  Champ login          name="login"
  Champ mot de passe   name="pass"
  Utilisateurs         admin
  Dictionnaire         10000 mots
  Essais prévus        10000
  Délai                0.5 s
  ? Lancer les essais ? (o/N)
```

`Ctrl+C` à tout moment arrête proprement et enregistre ce qui a été trouvé.

---

## 5. Mode ligne de commande

### 5.1 Modèle de base

```bash
python3 bruteforce.py -u URL -u nCHAMPS -l CHAMP_LOGIN -p CHAMP_MDP [options]
```

```bash
# Formulaire web classique
python3 bruteforce.py -u http://192.168.1.54/login.php -U admin \
    -l login -p pass -d 0.5

# API JSON
python3 bruteforce.py -u https://api.interne.fr/auth -U sarah -T json \
    -l username -p password -H "Authorization: Bearer abc"

# Formulaire en GET
python3 bruteforce.py -u http://192.168.1.54/connexion -U admin -m GET \
    -l identifiant -p motdepasse
```

### 5.2 Toutes les options

#### Cible et champs

| Option | Défaut | Rôle |
|---|---|---|
| `-u`, `--url` | — | URL de la page de connexion. **Obligatoire** hors mode interactif. |
| `-U`, `--user` | — | Identifiant à tester. Répétable (`-U a -U b`) ou séparé par des virgules. **Obligatoire**. |
| `-l`, `--login-field` | `login` | Valeur de l'attribut `name` du champ identifiant. |
| `-p`, `--password-field` | `pass` | Valeur de l'attribut `name` du champ mot de passe. |
| `-m`, `--method` | `POST` | `GET` ou `POST`. |
| `-T`, `--body-type` | `form` | `form` (application/x-www-form-urlencoded) ou `json`. |
| `-e`, `--extra-field` | — | Champ supplémentaire `CLE=VALEUR`, répétable. |
| `--profil` | — | Préremplir les options pour une application connue : `dvwa`, `wordpress`, `mutillidae`, `phpmyadmin`, `webgoat`, `tomcat`. Une option écrite à la main garde la priorité. Voir §8.8. |

#### Dictionnaire et rythme

| Option | Défaut | Rôle |
|---|---|---|
| `-w`, `--dictionary` | `dico.txt` | Fichier de mots de passe. |
| `-d`, `--delay` | `0.5` | Délai en secondes entre deux essais, plus une variation aléatoire. |
| `-k`, `--max-attempts` | tout | Nombre maximum d'essais. |
| `-s`, `--start` | `0` | Reprendre le dictionnaire à partir de cette ligne. |
| `-t`, `--timeout` | `10` | Délai d'attente réseau en secondes. |

#### Détection de la réussite

| Option | Rôle |
|---|---|
| `--success-pattern` | Expression régulière présente en cas de réussite. Répétable. |
| `--failure-pattern` | Expression régulière présente en cas d'échec. Répétable. |
| `--success-on-redirect` | Considérer une redirection 3xx comme une réussite. |
| `--no-success-on-redirect` | L'inverse, pour neutraliser un profil. |
| `--no-calibration` | Ne pas envoyer de requête sonde avant l'attaque. |
| `--follow-redirects` | Suivre les redirections 3xx pour comparer la page atteinte. |
| `--no-follow-redirects` | L'inverse, pour neutraliser un profil. |
| `--stop-on-suspect` | S'arrêter aussi sur une réponse inhabituelle. |
| `--refresh-csrf` | Recharger la page et son jeton CSRF avant chaque essai. |
| `--no-refresh-csrf` | L'inverse, pour neutraliser un profil. |
| `--basic-auth` | Authentification HTTP Basic : les identifiants vont dans l'en-tête `Authorization`, pas dans un formulaire. Voir §8.8.6. |

#### Réseau

| Option | Rôle |
|---|---|
| `-H`, `--header` | En-tête supplémentaire `CLE: VALEUR`, répétable. |
| `-c`, `--cookie` | Cookie supplémentaire `CLE=VALEUR`, répétable. |
| `-I`, `--insecure` | Ne pas vérifier le certificat TLS (laboratoires avec certificat auto-signé). |
| `--user-agent` | Valeur de l'en-tête `User-Agent`. |

#### Divers

| Option | Rôle |
|---|---|
| `--inspect` | Analyser le formulaire et afficher les valeurs suggérées. |
| `--dry-run` | Afficher la requête qui serait envoyée, sans authentification. |
| `--results-dir` | Dossier des rapports (`resultats` par défaut). |
| `--i-have-authorization` | Confirmer l'autorisation hors réseau privé. |
| `-V`, `--version` | Version. |
| `-h`, `--help` | Aide complète. |

### 5.3 Vérifier avant d'envoyer

```bash
python3 bruteforce.py -u http://127.0.0.1:8080/login -U admin --dry-run
```

Affiche la requête exacte, jeton CSRF compris, sans tenter de s'authentifier.
À utiliser systématiquement : c'est le moyen le plus rapide de détecter un
nom de champ mal orthographié.

---

## 6. Détecter la réussite : le point délicat

C'est le vrai problème du brute force. Envoyer les requêtes est la partie
facile ; savoir si la 4 217ᵉ réponse est une réussite, non.

Le script d'origine utilisait cette logique :

```python
if "Mot de passe invalide" in r.text:
    print("Perdu")
else:
    print("Trouvé")   # FAUX
```

Elle est fausse pour une raison simple : **tout ce qui n'est pas le message
d'erreur est interprété comme une réussite**. Une page 500 du serveur, un
délai dépassé, une page de maintenance, un proxy d'entreprise : l'outil
annonce un mot de passe trouvé. Le rapport est alors faux, et l'apprenant
retient une mauvaise leçon.

### 6.1 Les trois stratégies de l'outil

L'outil en applique une, de la plus fiable à la moins fiable.

**Stratégie 1 — motifs explicites.** Vous indiquez le texte exact de la
réussite et de l'échec. C'est exact, et c'est le meilleur réglage dès que
vous le connaissez.

```bash
--success-pattern "Connexion réussie" --failure-pattern "Mot de passe invalide"
```

Les motifs sont des **expressions régulières** (module `re`), insensibles à la
casse.

**Stratégie 2 — calibration.** C'est le mode par défaut. Avant l'attaque,
l'outil envoie une requête avec un mot de passe aléatoire de 30 caractères,
pratiquement impossible à deviner. La réponse obtenue est, par construction, la
**réponse d'échec de référence**. Toutes les réponses suivantes sont comparées
à cette référence.

```
  + Calibration effectuée — référence d'échec : HTTP 401 | 2885 o | #a1b2c3d4
```

Pour neutraliser les parties variables d'une page — jetons CSRF, dates,
horodatages, numéros de tentative — le corps de la réponse est *normalisé* avant
d'être empreinté. Sans cette étape, chaque réponse aurait une empreinte
différente et l'outil signalerait tout comme suspect.

**Stratégie 3 — statistiques.** Utilisée seulement avec `--no-calibration`.
L'outil regroupe les réponses par code HTTP, longueur et redirection, et
considère que le groupe le plus fréquent correspond à l'échec. Plus solide sur
un site qui renvoie des pages quelque peu différentes à chaque tentative.

Cette stratégie a un **angle mort assumé** : elle a besoin d'au moins
**deux réponses** pour savoir à quoi ressemble un échec. Les deux premières
sont donc comptées comme « non classifiables » et ne peuvent pas être
considérées comme des réussites. Le rapport indique ce nombre :

```
  Non classifiables    2 reponse(s) avant etablissement de la reference d'echec
```

C'est la raison principale de ne pas utiliser cette stratégie sur un mot de
passe susceptible d'être trouvé dès les premiers essais. Préférez la
calibration.

### 6.2 Ce que l'outil compare

L'**empreinte** d'une réponse est le triplet :

```
code HTTP | longueur après normalisation | empreinte SHA-256 du contenu
```

Deux réponses d'échec ont normalement la même empreinte. Un mot de passe
valide produit presque toujours une page différente : c'est un succès. Le
longueur seule est un mauvais critère — la page d'erreur peut mentionner le
nombre d'essais restants, ce qui change sa taille à chaque tentative. C'est
pourquoi l'empreinte est calculée sur le contenu *nettoyé*.

### 6.3 Les trois verdicts

| Verdict | Signification |
|---|---|
| `ECHEC` | La réponse est identique à la référence : le mot de passe est faux. |
| `SUCCES` | La réponse diffère nettement : le mot de passe est trouvé. L'essai s'arrête. |
| `SUSPECT` | Même taille et même code qu'un échec, mais contenu différent. **À vérifier manuellement.** |

Le verdict `SUSPECT` est important. Une page qui change sans que la longueur
change peut signifier que le mot de passe est presque correct, ou que le
site affiche un message dynamique (bandeau publicitaire, compteur, nom de
session). L'outil ne tranche pas et vous laisse juger : c'est plus honnête
qu'un faux positif affirmative.

#### 6.3.1 Quand la page d'erreur renvoie l'identifiant

Certaines applications réaffiche la valeur essayée dans leur message d'erreur,
parfois jusqu'à la requête SQL complète. C'est une faille d'information : le
réflexe de l'attaquant, c'est de s'en servir. L'outil, lui, doit **s'en
défendre**, car sinon chaque tentative change la longueur de la page et il
conclut à une réussite dès le premier essai — le faux positif le plus
trompeur qui soit, puisqu'il a l'air de fonctionner.

La parade est appliquée avant le calcul de l'empreinte : la valeur qu'on vient
d'envoyer est remplacée par `<ESSAI>` lorsqu'elle revient dans une affectation
d'identifiant (`password='...'`, `username='...'`, `value="..."`). Le
balisage du formulaire, lui, n'est pas touché — `type="password"` et
`name="password"` sont du HTML, pas la trace d'un essai, et les masquer ferait
varier l'empreinte dans le mauvais sens.

Le résultat : sur une application qui refuse tout le monde, toutes les pages
d'erreur partagent une empreinte, et l'outil conclut honnêtement « aucun couple
trouvé » au lieu d'annoncer une réussite.

### 6.4 Choisir la bonne stratégie

| Situation | Réglage |
|---|---|
| Vous connaissez les messages de la page | `--success-pattern` + `--failure-pattern` |
| Page d'erreur et page d'accueil très différentes | Calibration (par défaut), souvent `--success-on-redirect` |
| Le serveur redirige vers un tableau de bord | `--success-on-redirect` |
| Réponses toutes différentes (horodatage,/pub) | `--failure-pattern` seul |
| Many sites d'authentification turnover | Calibration + `--refresh-csrf` |

Pour savoir quoi utiliser, lancez `test.py` avec un mot de passe que vous
supposez valide : il affiche côte à côte la réponse d'échec et la réponse de
réussite, et vous indique quel critère les distingue.

```bash
python3 test.py -u http://127.0.0.1:8080/login -U admin -P 'Lab2024!'
```

```
6. Comparaison des deux réponses
------------------------------
  Code HTTP   : échec=401  réussite=200   DIFFERENT
  Taille      : échec=2856  réussite=2672   DIFFERENT
  Redirection : échec=False  réussite=False

  Indices à retenir pour la détection automatique :
    - le code HTTP suffit à distinguer les deux cas
```

---

## 7. Lire les résultats

### 7.1 À l'écran

La ligne de progression affiche en direct la barre, le pourcentage, le débit
et une estimation du temps restant :

```
  [##########..............]  40.0%  400/1000  4.8/s  restant 01:02  dernier: admin: azerty
```

### 7.2 Les rapports

Deux fichiers sont écrits dans `resultats/` (ou `--results-dir`), horodatés au
format `rapport_AAAAMMJJ_HHMMSS` :

- `.json` — données structurées, pour un traitement automatique ;
- `.txt` — rapport lisible, à joindre au compte rendu d'audit.

Extrait du rapport texte :

```
======================================================================
 BruteForceLab v1.0 — rapport d'essai de mots de passe
======================================================================
Date              : 2026-01-01T14:30:20
Cible             : http://192.168.1.54/login.php
Méthode           : POST
Champ login       : login
Champ mot de passe: pass
Utilisateurs      : admin
Dictionnaire      : dico_labo.txt
Stratégie         : calibration (requete sonde)
Tentatives        : 6/20
Durée             : 00:01  (4.8 essais/s)

MOT DE PASSE TROUVÉ (1) :
  - admin : Lab2024!  [HTTP 200 | 2495 o | #8846591e]

Empreintes observées (tri par fréquence) :
       5 x  HTTP 401 | 2691 o | #dd0c33f2
       1 x  HTTP 200 | 2495 o | #8846591e
```

La section des empreintes est particulièrement utile en audit : elle montre que
**59 réponses sur 60 étaient identiques**. C'est la démonstration chiffrée que
la protection par mot de passe est le seul obstacle.

Contenu du rapport JSON :

```json
{
  "outil": "BruteForceLab",
  "version": "1.0",
  "cible": "http://192.168.1.54/login.php",
  "methode": "POST",
  "champs": { "login": "login", "password": "pass" },
  "utilisateurs": ["admin"],
  "tentatives_effectuees": 6,
  "tentatives_prevues": 20,
  "strategie_detection": "calibration (requete sonde)",
  "duree_s": 1.2,
  "debit_tentatives_s": 4.8,
  "verrouillage_detecte": false,
  "interrompu": false,
  "reponses_non_classifiables": 0,
  "reussites": [
    { "utilisateur": "admin", "mot_de_passe": "Lab2024!",
      "empreinte": "HTTP 200 | 2495 o | #8846591e", "http": 200, "essai": 6 }
  ],
  "suspects": []
}
```

### 7.3 Codes de sortie

Utiles pour enchaîner les commandes dans un script.

| Code | Signification |
|---|---|
| `0` | Mot de passe trouvé, ou `--inspect` / `--dry-run` réussi, ou annulation. |
| `1` | Erreur : cible refusée, dictionnaire introuvable, réseau injoignable, aucun formulaire. |
| `2` | Aucun mot de passe trouvé dans le dictionnaire fourni (dictionnaire épuisé). |
| `130` | Essai interrompu par `Ctrl+C` : le résultat est **partiel**, le dictionnaire n'a pas été épuisé. |

Distinguer `2` de `130` compte dans un script : `2` veut dire « j'ai tout
essayé et ce n'est pas dans ce dictionnaire », `130` veut dire « je me suis
arrêté, ce qui reste n'a pas été testé ».

---

## 8. Cas particuliers

### 8.1 Jeton CSRF

Beaucoup d'applications exigent un champ caché généré à chaque affichage du
formulaire. L'outil le détecte et le transmet automatiquement :

```
  + Champs cachés détectés et conservés : csrf_token
```

L'option `--refresh-csrf` recharge la page **avant chaque essai** et renvoie
le nouveau jeton dans la requête suivante. À utiliser dès que le jeton est lié
à une session, comme sur DVWA (voir §8.8) :

```bash
python3 bruteforce.py -u URL -U admin --refresh-csrf
```

Le coût est une requête de page en plus par essai : sur une cible qui limite le
débit, `-d 0.5` devient `-d 1`.

**Piège classique.** Sans `--refresh-csrf`, l'outil affiche quand même
« aucun couple trouvé » alors que la cible a bien reçu toutes les requêtes : le
jeton de la requête de calibration a été consommé, et les essais suivants
sont rejetés. C'est le premier réflexe à prendre quand une démonstration ne
trouve rien.

### 8.2 Formulaire en GET

Les applications anciennes transmettent parfois les identifiants dans l'URL.
Fonctionnel, mais les identifiants restent dans l'historique du navigateur, les
journaux du serveur, les mandataires et l'en-tête `Referer`.

```bash
python3 bruteforce.py -u http://serveur/connexion -U admin -m GET \
    -l identifiant -p motdepasse
```

L'outil avertit de cette faiblesse à l'écran. C'est un point à relever dans
votre rapport d'audit.

### 8.3 API JSON

```bash
python3 bruteforce.py -u https://api.interne.fr/v1/login -U sarah -T json \
    -l username -p password -H "Authorization: Bearer TOKEN" \
    --success-pattern '"status":"ok"'
```

Pour s'entraîner, le laboratoire expose le même type de route :

```bash
python3 bruteforce.py -u http://127.0.0.1:8080/api/login -U admin \
    -T json -l login -p pass -w dico_labo.txt -d 0.2 \
    --success-pattern '"status": *"ok"'
```

Le corps envoyé est alors du JSON (`{"login": "...", "pass": "..."}`) au lieu
d'un formulaire encodé.

Notez l'authentification à deux facteurs : l'API renvoie un jeton intermédiaire,
que l'outil doit renvoyer dans l'en-tête. Utilisez `-H` pour le définir une fois
pour toutes.

### 8.4 Redirection sur réussite

Si une connexion réussie redirige vers un tableau de bord, l'outil ne suit pas
les redirections par défaut (pour ne pas masquer la différence entre un échec et
une réussite) et classe la réponse `3xx` comme inhabituelle. Ajoutez :

```bash
--success-on-redirect
```

Vérifiez d'abord avec `test.py` que la cible redirige bien.

### 8.5 Authentification à plusieurs étapes

Certains portails demandent un code par SMS ou par courriel après le mot de
passe. L'outil ne gère pas cette étape : l'authentification à deux facteurs est
précisément ce qui bloque le brute force. C'est un point à souligner en
formation, pas une limite à contourner.

### 8.6 Reprendre un essai interrompu

```bash
python3 bruteforce.py -u URL -U admin -s 5000
```

Reprend le dictionnaire à la 5 001ᵉ ligne. Le rapport de l'essai interrompu
indique le nombre d'essais effectués.

### 8.7 plusieurs identifiants

```bash
python3 bruteforce.py -u URL -U admin,root,test -d 1
```

Teste chaque identifiant avec tout le dictionnaire. Sur une cible qui verrouille
les comptes, cela verrouille les trois : préférez un seul identifiant à la fois.

### 8.8 Applications de laboratoire de Metasploitable2

Metasploitable2 regroupe plusieurs applications web volontairement vulnérables.
L'outil s'y utilise tel quel, à condition de connaître les noms de champs et la
façon dont chaque application signale la réussite.

| Application | URL | Champs | Réussite |
|---|---|---|---|
| DVWA | `/dvwa/login.php` | `username`, `password` + bouton `Login` | redirection 302 vers `/dvwa/index.php` |
| Mutillidae | `/mutillidae/index.php?page=login.php` | `username`, `password` + bouton `login-php-submit-button` | page d'accueil : `Not Logged In` devient `Logged In Admin:` |
| WordPress | `/wp-login.php` | `log`, `pwd` | redirection 302 vers `/wp-admin/` |
| phpMyAdmin | port 80, `/phpMyAdmin/index.php` | `pma_username`, `pma_password` | 302 **puis** page à cadres ; d'où `--follow-redirects` |
| WebGoat | port 8180, `/WebGoat/attack` | aucun : en-tête `Authorization: Basic` | HTTP 200 sur la page d'accueil |
| Tomcat Manager | port 8180, `/manager/html` | aucun : en-tête `Authorization: Basic` | HTTP 200 sur la page d'accueil |

Les identifiants par défaut sont `admin`/`password` (DVWA), `admin`/`adminpass`
(Mutillidae), `admin`/`admin` (WordPress), `root`/`toor` (phpMyAdmin),
`webgoat`/`webgoat` (WebGoat), `tomcat`/`tomcat` (Tomcat).

Six détails ont été vérifiés sur une VM réelle, et sont contre-intuitifs :

- **DVWA n'exige pas de jeton sur sa page de connexion.** Les versions
  anciennes affichent `user_token` ; ici le formulaire ne contient que `username`,
  `password` et le bouton `Login`. Sans `Login=Login`, le serveur renvoie
  bêtement la page du formulaire, sans message d'erreur : l'outil prendrait
  un refus silencieux pour un échec d'authentification. C'est pourquoi
  `--inspect` repère le bouton et l'envoie tout seul (§8.8.6).
- **Mutillidase connecte, mais sa base s'appelle `owasp10`.** La page de refus
  est identique pour tous les couples, *et* elle réaffiche la requête SQL
  complète, identifiant et mot de passe inclus. Sans aménagement, chaque
  essai change la longueur de la page et l'outil conclut à une réussite au
  premier essai. L'outil masque donc les valeurs qu'il vient d'envoyer
  lorsqu'elles reviennent dans une affectation d'identifiant
  (`password='...'`, `value="..."`) — sans quoi Mutillidae ne peut servir
  qu'à démontrer un faux positif.
- **phpMyAdmin répond 302 et un corps vide, que la connexion réussisse ou
  non.** Le corps de la réponse fait zéro octet dans les deux cas : sans suivre
  la redirection, toutes les empreintes sont identiques et la calibration ne
  peut rien conclure. Le profil active donc `--follow-redirects` : c'est la
  page atteinte après le 302 qui distingue `#1045 - Access denied` de la page
  à cadres de l'accueil.
- **phpMyAdmin est sur le port 80 et sa casse compte.** Le chemin est
  `/phpMyAdmin/` ; `/phpmyadmin/` répond `404` sur une installation standard.
- **Tomcat n'est pas sur 8080.** Sur cette VM il écoute sur **8180**
  (AJP sur 8009) ; `/manager/html` répond `401` sans identifiants. Vérifiez le
  port avant de lancer la commande.
- **WebGoat n'a aucun formulaire, contrairement à tous les cours.** Son
  `web.xml` ne déclare qu'un `login-config` `BASIC`, et son code ne contient ni
  Acegi ni filtre de formulaire : la seule authentification est celle de
  Tomcat, gérée par `tomcat-users.xml`. On attaque donc WebGoat exactement
  comme le Manager :

  ```bash
  VM=$(./adresse_vm.sh)
  python3 bruteforce.py --profil tomcat -U webgoat -k 8 -d 0.4 \
      -u http://$VM:8180/WebGoat/attack -w dico_metasploitable.txt
  ```

  Viser `/WebGoat/attack` et non `/WebGoat/` : la racine n'a pas de fichier
  d'accueil. Elle répond `401` tant qu'on n'est pas authentifié (la contrainte
  de sécurité Tomcat couvre tout `/WebGoat/*`), puis `404` une fois les
  identifiants fournis. L'outil s'en sort parce qu'en mode Basic un `401`
  **et** un `404` comptent tous deux comme échec ; ne pas confondre les deux.

`WordPress` et `WebGoat` sont facultatifs et absents de l'image
Metasploitable2 d'origine, où ils répondent `404`. Ils ont été installés à la
main sur la VM de l'atelier (§8.9) ; le laboratoire les reproduit de toute
façon. **Attention :** le profil `webgoat` du laboratoire imite un WebGoat
*avec* formulaire, parce que c'est la version que décrit l'OWASP Testing
Guide. Sur la vraie VM, c'est `--profil tomcat -U webgoat` qu'il faut employer.

Metasploitable2 est sur un réseau privé, d'où l'absence de
`--i-have-authorization`. L'outil refuserait une adresse publique, et c'est
exactement le comportement souhaité. Son IP est attribuée par DHCP et change :
ne jamais l'écrire en dur, passer par `./adresse_vm.sh` qui retrouve la VM par
son adresse MAC.

#### 8.8.1 Répéter la démonstration hors ligne

Le laboratoire sait reproduire le comportement de chacune de ces applications :
mêmes noms de champs, mêmes codes HTTP, mêmes messages, même jeton de session.
Cela permet de répéter la démonstration autant de fois que nécessaire sans
solliciter la VM, et de vérifier que la recette fonctionne avant le cours.

Terminal A — la cible :

```bash
python3 lab_server.py --port 8080 --profil dvwa
```

Les six profils du laboratoire reproduisent les six applications :

```bash
python3 lab_server.py --port 8080 --profil dvwa        # /dvwa/login.php
python3 lab_server.py --port 8080 --profil wordpress   # /wp-login.php
python3 lab_server.py --port 8080 --profil mutillidae  # /mutillidae/index.php
python3 lab_server.py --port 8080 --profil phpmyadmin # /phpmyadmin/index.php
python3 lab_server.py --port 8080 --profil webgoat     # /webgoat/login
python3 lab_server.py --port 8080 --profil tomcat      # /manager/html (Basic)
```

Viser seulement `http://127.0.0.1:8080/` marche aussi : chaque profil
redirige la racine vers sa propre page, ce qui évite le 404 puis le « aucun
couple trouvé » sans explication. Le profil `interne` sert directement sa
page à la racine.

Terminal B — l'attaque :

```bash
python3 bruteforce.py --profil dvwa \
    -u http://127.0.0.1:8080/dvwa/login.php \
    -U admin -w dico_metasploitable.txt -d 0.3
```

`--profil dvwa` active exactement quatre choses : `-l username`,
`-p password`, `--refresh-csrf` et `--success-on-redirect`. Trois règles :

- une option écrite à la main gagne toujours sur le profil ;
- `--no-refresh-csrf`, `--no-success-on-redirect` et `--no-follow-redirects`
  neutralisent un profil ;
- `--profil` ne fait que préremplir des options : la commande équivalente reste
  entièrement lisible, et le comportement de l'outil ne change pas.

Les sept profils du laboratoire :

| Profil | Ce qu'il reproduit |
|---|---|
| `interne` | Intranet d'entreprise : échec 401, réussite par une page, jeton informatif. |
| `dvwa` | Échec 200 avec `Login failed`, réussite 302, `user_token` vérifié. |
| `wordpress` | Champs `log` / `pwd`, échec 200 avec `ERROR: ...`, réussite 302. |
| `mutillidae` | Connexion ouverte : n'importe quel couple passe. |
| `phpmyadmin` | Champs préfixés `pma_`, échec 200, réussite 302. |
| `webgoat` | Échec 200 avec `Invalid credentials`, jeton `csrf` vérifié, réussite 302. |
| `tomcat` | Authentification HTTP Basic : échec 401 avec `WWW-Authenticate`, réussite 200. |

Le laboratoire reproduit une weakness supplémentaire, pour que le scénario
reste pédagogique sans la VM : `mutillidae` laisse entrer n'importe quel couple
alors que la vraie application exige `admin`/`adminpass`. Tout le reste — noms
de champs, codes HTTP, messages, port de Tomcat — est calqué sur le réel.

#### 8.8.2 Sur la vraie VM

Toujours commencer par **résoudre l'adresse**, puis **vérifier le port**, parce
qu'il ne correspond pas toujours à celui qu'on attend :

```bash
# l'IP est attribuée par DHCP : jamais d'adresse en dur
VM=$(./adresse_vm.sh) || exit 1

# ports fermés : ce n'est pas une erreur, c'est une information
for p in 80 8080 8180; do
    timeout 2 bash -c "echo > /dev/tcp/$VM/$p" 2>/dev/null \
        && echo "$p ouvert" || echo "$p fermé"
done
```

Metasploitable2 place normalement Tomcat et phpMyAdmin sur 8080. Sur la VM de
ce cours, c'est différent : **phpMyAdmin est servi par Apache sur le port 80**
(`/phpMyAdmin/`) et **Tomcat écoute sur 8180**, le port 8080 étant fermé. Une
installation de Tomcat faite à partir des paquets Debian, ou une VM
reconfigurée, peut écouter sur 8180 — et si Apache est arrêté, le port 80 ne
répond plus du tout, ce qui fait croire à tort que les applications web ont
disparu.

```bash
# 1. L'adresse vient du script, qui interroge VirtualBox pour la MAC
VM=$(./adresse_vm.sh) || exit 1

# 2. Analyser le formulaire : aucune requête d'authentification n'est envoyée
python3 bruteforce.py --inspect -u http://$VM/dvwa/login.php

# 3. Voir la requête qui partirait, toujours sans l'envoyer
python3 bruteforce.py --profil dvwa -U admin \
    -u http://$VM/dvwa/login.php --dry-run

# 4. L'attaque, limitée à vingt essais
python3 bruteforce.py --profil dvwa -U admin -k 20 -d 0.5 \
    -u http://$VM/dvwa/login.php -w dico_metasploitable.txt
```

L'étape 2 est celle qui évite les mauvaises surprises : `--inspect` affiche les
noms de champs trouvés et les valeurs suggérées, y compris quand le formulaire
est servi par une application inhabituelle.

Dans la VM, `sudo tail -f /var/log/apache2/access.log` montre le flot de
requêtes pendant l'essai : c'est la démonstration la plus parlante du coût
réel d'un brute force, et de la raison pour laquelle il se voit.

#### 8.8.3 Le piège du jeton de session

Le profil `dvwa` du laboratoire régénère `user_token` à chaque affichage de page
et le vérifie à chaque envoi, comme les versions de DVWA qui l'utilisent.
Conséquence : sans `--refresh-csrf`, la requête de calibration consomme
le jeton, et tous les essais suivants sont rejetés. L'outil affiche « aucun
couple trouvé » et renvoie le code `2` — alors que la cible a bien reçu les
requêtes.

Sur la VM testée ici, le formulaire de connexion n'expose aucun `user_token` :
c'est le bouton `Login` qui fait foi. `--refresh-csrf` ne gêne donc pas et peut
rester activé par le preset.

C'est une démonstration en soi, en trois gestes :

1. Lancer sans `--refresh-csrf` : aucun couple trouvé, code `2`.
2. Montrer `/var/log/apache2/access.log` dans la VM : les requêtes sont bien
   arrivées, ce ne sont donc pas les identifiants qui sont en cause.
3. Relancer avec `--refresh-csrf` : le mot de passe est trouvé.

#### 8.8.4 Choisir un dictionnaire

`dico_metasploitable.txt` contient les identifiants par défaut documentés de ces
applications de laboratoire : `password` (DVWA), `admin` (WordPress), `toor`
(phpMyAdmin), `tomcat` (Tomcat), `webgoat` (WebGoat). Ces mots sont absents de
`dico.txt`, ce qui permet de vérifier d'un coup d'œil quel dictionnaire a servi.

Pour une démonstration plus réaliste, utiliser `dico.txt` (10 000 mots classés
par fréquence) et `-k` pour borner la durée :

```bash
python3 bruteforce.py --profil dvwa -U admin -w dico.txt -k 200 -d 0.3 \
    -u http://$VM/dvwa/login.php
```

`Lab2024!` n'est volontairement présent dans aucun de ces dictionnaires : c'est
le mot de passe du laboratoire local (§3), pas celui de la VM.

#### 8.8.5 Remise à zéro entre deux démonstrations

| Application | Action |
|---|---|
| DVWA | Bouton **Reset Database** sur la page d'accueil. |
| Mutillidae | Lien **Reset DB** dans le menu. |
| WordPress | Rien à faire ; l'état de la cible ne change pas. |
| phpMyAdmin | Rien à faire. |
| WebGoat | Supprimer le compte créé dans **WebGoat → Register** si l'on veut repartir de zéro. |
| Tomcat | Rien à faire ; l'état de la cible ne change pas. |

Si les journaux de la VM saturent le disque, redémarrer la machine suffit.

#### 8.8.6 Tomcat : pas de formulaire, mais un en-tête

Tomcat ne propose pas de formulaire de connexion : `/manager/html` répond
immédiatement `401 Unauthorized` avec un en-tête qui précise le mécanisme :

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Basic realm="Tomcat Manager Application"
```

Le nom du *realm* change avec la version : « Manager Tomcat » sur les Tomcat
récentes, « Tomcat Manager Application » sur le Tomcat 5.5 embarqué dans
Metasploitable2. Peu importe pour l'attaque — l'en-tête est envoyé tel quel —
mais c'est un bon indice de version en cours de route.

Les identifiants voyagent alors dans l'en-tête `Authorization`, encodés en
base64 — ce qui n'est **pas** du chiffrement, seulement un encodage :

```
Authorization: Basic dG9tY2F0OnRvbWNhdA==     # « tomcat:tomcat »
```

L'outil gère ce cas avec `--basic-auth` (directement inclus dans
`--profil tomcat`) :

```bash
python3 bruteforce.py --profil tomcat \
    -u http://$VM:8180/manager/html -U tomcat \
    -w dico_metasploitable.txt -m GET -k 10
```

Trois points méritent d'être montrés en cours :

1. **Le 401 est une réponse d'échec.** L'outil ne peut pas se contenter de
   chercher « une réponse différente » : sans identifiants, *toutes* les
   tentatives renvoient le même 401. C'est pourquoi la calibration sert de
   référence : si l'empreinte ne change jamais, il n'y a rien à trouver.
2. **`--dry-run` montre l'en-tête.** Le corps de la requête est vide, tout est
   dans les en-têtes ; c'est la façon la plus rapide de voir ce qui est
   réellement envoyé.
3. **Le port et la casse comptent.** Tomcat n'écoute ni sur 80 ni sur 8080 :
   selon l'installation, c'est 8180. Et phpMyAdmin est sur le port 80, avec une
   casse exacte : `/phpMyAdmin/` répond `200`, `/phpmyadmin/` répond `404`. Sur le
   bon chemin mais le mauvais port, on tombe sur la page d'accueil de la machine
   — ou sur une erreur 404 — et l'outil conclut à tort qu'il n'y a pas de
   formulaire. Le tester à la main d'abord est la seule parade.

#### 8.8.7 Ce que chaque application enseigne

| Cible | Leçon |
|---|---|
| DVWA | Le jeton de session n'arrête pas une attaque automatique : il oblige à recharger la page, donc à doubler le nombre de requêtes — et rend l'attaque deux fois plus visible dans les journaux. |
| Mutillidae | Sa page d'erreur réaffiche la requête SQL, identifiant et mot de passe inclus. C'est une mine d'or pour l'attaquant et un piège pour l'outil : sa réponse « différente » n'est que l'écho de l'essai. Une bonne détection doit savoir se taire. |
| WordPress | Des noms de champs non conventionnels (`log`, `pwd`) suffisent à faire échouer un script qui suppose `username` / `password`. `--inspect` évite l'erreur. |
| phpMyAdmin | Même problème avec un préfixe (`pma_` qui ne saute pas aux yeux), et une difficulté plus subtile : la réponse est un `302` au corps **vide** dans les deux cas. Rien à comparer tant qu'on n'a pas suivi la redirection — d'où `--follow-redirects`. |
| WebGoat | Sur le laboratoire, le jeton de session ne protège que si on le recharge : sans `--refresh-csrf`, toutes les tentatives échouent avec la même erreur. Sur la vraie VM, il n'y a pas de jeton du tout : l'authentification est un en-tête HTTP Basic (§8.8). |
| Tomcat | Une page qui n'affiche aucun formulaire n'est pas une cible vide : l'authentification est dans un en-tête HTTP, et le serveur répond 401 avant même de servir la page. |

Pour toutes, la parade reste le verrouillage de compte, la limitation de
débit et le second facteur : voir le chapitre 11.

### 8.9 Installer WordPress et WebGoat sur la VM d'atelier

Ni WordPress ni WebGoat ne font partie de l'image Metasploitable2 : ce sont
des paquets optionnels, et la VM n'a ni accès à `wordpress.org` ni à
`github.com`. Les deux ont été installés à la main le **2026-10-02**. Ce
procédé est reproductible, mais il n'est nécessaire que pour ces deux
démos : tout le reste fonctionne sur l'image d'origine.

**WordPress 3.9.2** — le plus simple des deux. Il faut PHP avec MySQL, déjà
présents sur la VM ; l'obstacle est PHP 5.2.4, trop ancien pour les versions
récentes de WordPress.

```bash
curl -O http://wordpress.org/wordpress-3.9.2.tar.gz
tar xzf wordpress-3.9.2.tar.gz
sudo mv wordpress /var/www/wordpress
mysql -u root -ptoor -e "CREATE DATABASE wordpress;"
sudo cp /var/www/wordpress/wp-config-sample.php \
        /var/www/wordpress/wp-config.php
```

Puis renseigner dans `wp-config.php` :

```php
define( 'DB_NAME', 'wordpress' );
define( 'DB_USER', 'root' );      // le compte root de la VM
define( 'DB_PASSWORD', 'toor' );
define( 'DB_HOST', 'localhost' );
```

et donner à Apache la propriété du dossier. Créer ensuite le compte
`admin`/`admin` depuis `http://VM/wp-admin/install.php`.

> Sur une VM de cours, réutiliser `root` évite de multiplier les comptes. En
> production, créez au contraire un utilisateur MySQL dédié, limité à cette
> seule base : c'est le principe du moindre privilège.


**WebGoat 5.3** — nettement plus pénible, pour trois raisons cumulées.

1. **Java.** Le WAR est compilé pour Java 5/6 ; la VM ne fournit que
   `java-gcj-compat` (GNU Classpath), qui ne suffit pas. Installer
   `openjdk-6-jre-headless` (204 Mo), puis redémarrer Tomcat.
2. **Les rôles.** WebGoat n'a pas de base de comptes : il s'appuie sur
   `tomcat-users.xml`, et son `web.xml` impose les rôles exacts
   `webgoat_user`, `webgoat_admin` et `webgoat_challenge`. Sans eux, Tomcat
   répond `403` — pas `401`, ce qui ne mène nulle part. Ajouter :

   ```xml
   <role rolename="webgoat_user"/>
   <role rolename="webgoat_admin"/>
   <role rolename="webgoat_challenge"/>
   <user username="webgoat" password="webgoat"
         roles="webgoat_user,webgoat_admin,webgoat_challenge"/>
   ```

3. **Le `SecurityManager`.** Toutes les pages renvoient `500` avec
   `AccessControlException: access denied
   (java.lang.RuntimePermission accessClassInPackage.org.apache.coyote)`.
   Ajouter l'accord dans `/etc/tomcat5.5/policy.d/50user.policy` ne suffit
   pas : le script d'initialisation de Debian *écrase* `TOMCAT5_SECURITY=yes`
   dans `/etc/init.d/tomcat5.5`, et `/etc/default/tomcat5.5` est ignoré. Il
   faut modifier la ligne 65 de l'init script. Original sauvegardé dans
   `/root/sauvegarde/init.d-tomcat5.5-avant-webgoat`.

Le tas de 128 Mo laissé par défaut suffit. En revanche, la VM ne dispose que
de 1010 Mo de RAM et **sans swap** : ne pas monter `-Xmx` au-delà de 192 Mo,
sous peine de swap permanent.

Une fois déployé, WebGoat se comporte comme le Manager Tomcat — voir la
commande donnée en §8.8. Le WAR reste dans
`/var/lib/tomcat5.5/webapps/WebGoat.war` (37 Mo).

---

## 9. Dépannage

| Symptôme | Cause probable | Solution |
|---|---|---|
| `Dictionnaire introuvable` | Mauvais chemin | Chemin absolu, ou `-w /chemin/dico.txt` |
| `Aucun formulaire <form> détecté` | Connexion par JavaScript | Inspecter la page dans le navigateur, relever l'URL de l'API |
| `Fichier introuvable` (champ) | Réponse d'erreur du serveur | Relancer `--inspect` ; vérifier `-e` pour les champs manquants |
| Aucun mot de passe trouvé, 0 trying | Nom de champ du mot de passe erroné | `--dry-run` pour voir la requête ; corriger `-p` |
| Tous les verdicts sont `SUSPECT` | Page d'erreur dynamique | `--failure-pattern`, ou `--no-calibration` |
| Arrêt sur « Blocage détecté » | La cible se protège | **Comportement attendu.** Relancer le lab avec `--lockout 0` |
| `La cible n'est pas un réseau privé` | Cible hors `10/8`, `172.16/12`, `192.168/16` | `--i-have-authorization` si vous êtes autorisé |
| Trop lent | Délai trop grand, ou latence réseau | `-d 0.1` (laboratoire uniquement), `-t 5` |
| `Erreur réseau` répétés | Cible injoignable ou coupée | Vérifier `-t`, la connectivité, le pare-feu |
| `Le dictionnaire est vide` | Fichier vide ou mal encodé | Vérifier le fichier ; l'outil accepte l'UTF-8 avec remplacement |
| Trouvé au 1ᵉʳ essai | Compte déjà connu | Faux positif de configuration : revoyez `--success-pattern` |

---

## 10. Exercices guidés

Chaque exercice utilise le laboratoire local. Terminal A : `python3
lab_server.py --port 8080`.

### Exercice 1 — Lire un formulaire

```bash
python3 bruteforce.py --inspect -u http://127.0.0.1:8080/login
```

1. Quel est le nom du champ identifiant ? du champ mot de passe ?
2. Quel champ est de type `hidden` ? Pourquoi faut-il le renvoyer ?
3. Quelle valeur de `-m` utiliser ? Que se passerait-il avec `GET` ?

<details><summary>Corrigé</summary>

1. `login` et `pass`.
2. `csrf_token`. Le serveur le compare à celui qu'il a généré : sans lui, la
   requête est rejetée.
3. `POST`. En `GET`, les identifiants passeraient dans l'URL et resteraient
   dans l'historique et les journaux.

</details>

### Exercice 2 — Trouver le mot de passe

```bash
python3 bruteforce.py -u http://127.0.0.1:8080/login -U admin -w dico_labo.txt -d 0.1
```

1. Combien d'essais pour trouver `Lab2024!` ?
2. Que contient la section « empreintes observées » du rapport ?
3. Ouvrez `http://127.0.0.1:8080/stats` : que voit le serveur ?

<details><summary>Corrigé</summary>

1. Le mot de passe est en 6ᵉ position du dictionnaire → 6 essais (vérifiez
   `Essais 6/20` dans le bilan).
2. 5 réponses d'échec avec une empreinte identique, 1 réponse de réussite avec
   une empreinte différente. La différence de longueur (2 691 contre 2 495
   caractères) est ce qui permet la détection.
3. Le serveur compte les tentatives par identifiant : c'est la trace de
   l'attaque côté serveur. En production, cette page n'existerait pas — mais
   les journaux contiendraient la même information.

</details>

### Exercice 3 — Prouver que la détection par motif est fragile

```bash
python3 bruteforce.py -u http://127.0.0.1:8080/login -U admin -w dico_labo.txt -d 0.5
# puis Ctrl+C après 3 essais
```

Le script d'origine aurait conclu « trouvé » dès la première réponse anormale.
Expliquez en une phrase pourquoi « pas le message d'erreur » ne prouve pas
« réussite ».

<details><summary>Corrigé</summary>

Parce que la page peut être différente pour une raison sans rapport avec le
mot de passe : erreur 500, page de maintenance, expiration de session, proxy
d'entreprise, CAPTCHA. Seule la présence d'un **critère positif** de réussite
(page d'accueil, redirection vers un espace privé) permet de conclure.

</details>

### Exercice 4 — Observer une protection efficace

```bash
# Terminal A
python3 lab_server.py --port 8081 --lockout 5
# Terminal B
python3 bruteforce.py -u http://127.0.0.1:8081/login -U admin -w dico_labo.txt -d 0.1
```

1. À quel essai l'outil s'arrête-t-il ?
2. Que se passerait-il si le brute force ignorait le code 429 ?

<details><summary>Corrigé</summary>

1. À l'essai 5, sur le code HTTP 429.
2. Le compte resterait bloqué, et l'attaquant pourrait_epuiser tous les
   comptes : c'est un déni de service. D'où l'intérêt de combiner le
   verrouillage avec une **limitation de débit par adresse IP** et un
   déverrouillage automatique après un délai.

</details>

### Exercice 5 — Trouver le message de réussite

```bash
python3 test.py -u http://127.0.0.1:8080/login -U admin -P 'Lab2024!'
```

1. Quel critère distingue la réussite de l'échec ?
2. Rejouez l'attaque en forçant ce critère :

```bash
python3 bruteforce.py -u http://127.0.0.1:8080/login -U admin -w dico_labo.txt -d 0.1 \
    --success-pattern "Connexion réussie" --failure-pattern "Mot de passe invalide"
```

<details><summary>Corrigé</summary>

1. Le code HTTP : 401 pour l'échec, 200 pour la réussite. La taille aussi
   (2 856 contre 2 672 caractères), mais c'est un critère fragile.
2. Avec les motifs explicites, la stratégie affichée devient « motifs
   explicites » et le résultat est identique — mais sans requête de calibration
   préalable, donc un essai de moins.

</details>

### Exercice 6 — Formulaire en GET

```bash
python3 bruteforce.py -u http://127.0.0.1:8080/login -U admin -m GET -w dico_labo.txt -d 0.1
```

1. Le compte est-il trouvé ?
2. Ouvrez `/stats`, puis `/health` : quelles consequences pour l'exploitation ?
3. Citez deux endroits où les identifiants en GET laissent une trace.

<details><summary>Corrigé</summary>

1. Oui, la page `/login` du laboratoire accepte aussi les paramètres en GET.
2. Les identifiants apparaissent dans l'URL : historique du navigateur,
   journaux d'accès du serveur, mandataires, et en-tête `Referer` transmis aux
   sites tiers, et captures d'écran. C'est une fuite de données, pas seulement
   un défaut de style.
3. L'historique du navigateur et les journaux du serveur.

</details>

### Exercice 7 — Rédiger la conclusion d'audit

À partir de vos essais, rédigez en dix lignes la section « constat et
recommandation » d'un rapport d'audit pour l'administrateur du laboratoire.
Attendez-vous aux éléments suivants : criticité, preuve (chiffres), cause
racine, remédiation par ordre de coût, et mention du verrouillage déjà en
place.

---

## 11. Sécuriser son application

L'outil affiche ces leçons à la fin de chaque exécution. Voici la version
complète, dans l'ordre de coût croissant.

**1. La longueur bat la complexité.** Douze caractères aléatoires
(`k7#Rm2!pQ9zX`) ou une phrase de passe de cinq mots sont plus
résistants qu'un mot de passe court et compliqué. Un mot de passe d' milliards
de milliards de combinaisons ne se trouve pas avec un dictionnaire.

**2. Verrouiller et limiter le débit.** Après 5 à 10 échecs, blocage temporaire
du compte *et* limitation par adresse IP. C'est la protection la plus efficace
contre le brute force : elle transforme un essai infini en essai impossible.
Attention au déni de service qu'un blocage peut provoquer — d'où la
limitation par IP et le déverrouillage automatique.

**3. Ajouter un second facteur.** Un mot de passe volé ou deviné ne suffit
plus. C'est la réponse la plus efficace aujourd'hui.

**4. Répondre de façon uniforme.** Le même message, le même code HTTP et le
même temps de réponse pour « identifiant inconnu » et « mot de passe faux »,
sinon l'énumération des comptes devient possible.

**5. Surveiller les échecs.** Alerter sur un pic d'échecs
d'authentification : c'est ainsi qu'une attaque est détectée en cours, et non
à la lecture d'un rapport.

**6. Ne jamais transmettre les identifiants en GET.**Ni dans l'URL, ni dans un
en-tête lisible. Utiliser `POST` sur `https`, et jamais de mot de passe dans un
paramètre d'URL.

**7. Hacher correctement.** bcrypt, scrypt ou Argon2, avec sel. Un algorithme
rapide (MD5, SHA-1) se casse hors ligne à des vitesses records.

**8. Entester le mot de passe contre les mots de passe compromis.** Un serveur
peut vérifier un mot de passe contre une base de mots de passe déjà volés
(HIBP) et refuser les plus courants. C'est peu coûteux et très efficace.

---

## 12. Annexes

### 12.1 Structure du dossier

```
BruteForce/
├── bruteforce.py          outil principal
├── lab_server.py          laboratoire local (4 profils d'applications)
├── test.py                inspecteur de formulaire
├── bruteforcessh.py       version simplifiée commentée
├── MANUEL.md              ce manuel
├── readme.txt             résumé en texte brut
├── requirements.txt       dépendances
├── dico_labo.txt          20 mots (démo, exercices, laboratoire local)
├── dico_metasploitable.txt  identifiants par défaut de la VM Metasploitable2
├── dico.txt               10 000 mots de passe
├── common_roots.txt       racines de mots de passe
├── AGENTS.md              notes de reprise pour une session de travail
├── tests/
│   ├── test_outils.py     suite de tests (70 tests, sans dépendance)
│   └── recette/           pilotes de recette bout en bout + lanceur
└── resultats/             rapports (créé automatiquement)
```

### 12.2 Créer son dictionnaire

```bash
# Mots de passe Themes d'un site donne
curl -s https://exemple.fr/robots.txt > brut.txt
grep -oE '[A-Za-z0-9._-]{6,20}' brut.txt | sort -u > dico_cible.txt

# Variantes d'un mot de passe connu (concatenation d'annees courantes)
python3 - <<'PY'
base, annees = input("racine : "), ["", "2024", "2025", "2026", "!", "123"]
with open("dico_variantes.txt", "w") as f:
    for suffixe in annees:
        f.write(f"{base}{suffixe}\n")
PY
```

Rappel : ces listes ne servent que sur des cibles autorisées.

### 12.3 Vérifier que tout fonctionne

La suite de tests démarre elle-même le laboratoire sur un port libre et ne
touche que `127.0.0.1`. Aucun paquet supplémentaire n'est nécessaire.

```bash
python3 tests/test_outils.py          # 70 tests, environ 40 secondes
python3 tests/test_outils.py -v       # une ligne par test
python3 tests/test_outils.py detection  # une seule classe
```

Elle vérifie notamment ce qui est difficile à voir à l'écran :

- la détection des trois champs du formulaire, jeton CSRF compris ;
- les trois stratégies de détection, dont le nombre de réponses non
  classifiables en mode `--no-calibration` ;
- que `--dry-run` n'envoie aucune requête d'authentification ;
- que `--success-on-redirect` n'est actif que si on le demande ;
- que `--follow-redirects` est ce qui permet de distinguer un 302 au
  corps vide d'une vraie réussite ;
- l'arrêt immédiat sur verrouillage du compte ;
- le contenu exact des rapports JSON ;
- la barre de progression dans un vrai terminal (réutilisation de ligne et
  effacement avant le bilan) ;
- le code de sortie `130` et le rapport partiel après `Ctrl+C` ;
- que `test.py` et `bruteforcessh.py` donnent les bons résultats ;
- que `--refresh-csrf` recharge réellement le jeton, en le prouvant sur le
  profil `dvwa` : sans l'option, rien n'est trouvé malgré des requêtes
  envoyées ; avec elle, le mot de passe est trouvé ;
- les six profils d'applications de laboratoire (`dvwa`, `wordpress`,
  `mutillidae`, `phpmyadmin`, `webgoat`, `tomcat`) et le poids de `--profil` ;
- que `--basic-auth` est indispensable sur Tomcat : sans lui, aucune
  authentification n'est envoyée et l'outil conclut à juste titre qu'il n'y a
  rien à trouver ;
- que viser la racine du laboratoire fonctionne pour les six profils, au lieu
  de se heurter à un 404 trompeur ;
- que les pages qui renvoient les identifiants Essays (le cas réel de
  Mutillidae) ne déclenchent pas de fausse réussite.

En cas d'échec, la sortie indique le test, la valeur obtenue et la valeur
attendue — les tests sont écrits pour être lus autant que pour passer.

#### 12.3.1 La recette complète

La suite ci-dessus est automatique et rapide. `tests/recette/` va plus loin :
sept pilotes font tourner l'outil dans des situations réelles (les six
profils du laboratoire, les trois méthodes HTTP, le mode interactif, les
options de rapport, la barre de progression dans un vrai terminal). Une seule
commande les enchaîne, compile d'abord les modules et nettoie à la fin :

```bash
./tests/recette/lancer_recette.sh
```

Elle se termine par `Recette complète : tout est conforme.` ou signale les
lignes `ECHEC`. Comme la suite de tests, elle ne joint que `127.0.0.1`.

### 12.4 Bonnes pratiques d'audit

- Ne lancez un brute force sur une cible sans mandat écrit.
- Préférez toujours `--dry-run` puis `--inspect` avant tout envoi massif.
- Commencez par un dictionnaire restreint (`-k 20`) pour valider la
  configuration.
- Fixez toujours un délai (`-d`), ne même pas en laboratoire : c'est le
  réflexe qui évite les accidents.
- L'outil s'arrête seul sur blocage : ne cherchez pas à le contourner.
- Conservez les rapports : ils sont la preuve de votre demonstration.

### 12.4 Aller plus loin

- `requests` — la bibliothèque HTTP utilisée par l'outil.
- `html.parser` — l'analyse des formulaires, sans dépendance externe.
- OWASP **Testing Guide**, chapitre *Authentication* : la référence pour
  planifier un test d'authentification.
- OWASP **Password Storage Cheat Sheet** : les bonnes pratiques de hachage.
- RFC 6585 — le code HTTP 429 *Too Many Requests*.

---

*BruteForceLab v1.0 — outil pédagogique. Utilisez-le uniquement sur des cibles
autorisées.*
