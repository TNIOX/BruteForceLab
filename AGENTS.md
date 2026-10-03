# AGENTS.md — BruteForceLab

Notes de reprise pour toute session future sur ce dépôt.
Dernière mise à jour : 2026-10-02.

## 1. Ce qu'est ce projet

Outil pédagogique de brute force HTTP (`bruteforce.py`) accompagné d'un
laboratoire multi-profils (`lab_server.py`) qui imite des applications
volontairement vulnérables de Metasploitable2. Le tout est documenté pour un
cours : `MANUEL.md` (référence complète) et `readme.txt` (résumé).

**Cadre d'usage : cibles autorisées uniquement.** La VM d'atelier est sur le
réseau privé, donc `--i-have-authorization` n'y est pas demandé ; l'outil
refuse une adresse publique, ce qui est le comportement souhaité.

## 2. Environnement

- Python `3.14.4`, seule dépendance `requests>=2.32.5` (`requirements.txt`).
- Dépôt git présent depuis le 2026-10-03 : `https://github.com/TNIOX/BruteForceLab`
  (branche `master`). Pousser après toute modification : `git add -A`,
  `git commit`, `git push origin master`.
- Codes de sortie de `bruteforce.py` : `0` succès, `1` erreur, `2` échec
  (dictionnaire épuisé ou erreur argparse), `130` interruption.

## 3. Vérifications à lancer après toute modification

Une seule commande suffit :

```bash
cd /home/thierry/Documents/DevOps/CyberTools4Pentesters/BruteForce
./tests/recette/lancer_recette.sh
```

Elle compile les modules, lance les 70 tests, enchaîne les sept pilotes de
`tests/recette/`, nettoie `resultats/` et les `__pycache__`, et vérifie que
`readme.txt` tient dans 80 colonnes. Elle se termine par
`Recette complète : tout est conforme.` ou liste les lignes `ECHEC`.

Pour aller plus vite pendant le développement, la suite seule suffit :

```bash
python3 tests/test_outils.py          # 70 tests, ~45 s, démarre le labo
python3 tests/test_outils.py -v       # une ligne par test
python3 tests/test_outils.py detection  # une seule classe
```

Rien ne joint que `127.0.0.1` : aucun accès réseau requis.

## 4. Conventions

- Commentaires et docstrings **en français**, avec accents, comme le reste.
- `readme.txt` : ASCII seul (pas d'accents) et **80 colonnes maximum** — à
  vérifier après toute édition (`awk 'length>80' readme.txt`).
- `MANUEL.md` peut utiliser les accents, tableaux et blocs de code.
- Pas de commentaire de code non demandé ; la logique se lit dans les noms.
- `lab_server.py` : chaque profil déclare ses chemins, champs et codes HTTP ;
  `Profil.realm` sert à l'en-tête `WWW-Authenticate` du profil Tomcat.

## 5. La VM d'atelier (IP dynamique)

**L'adresse IP est attribuée par DHCP et change : ne jamais la figer.** La VM
est identifiée par sa MAC — mais cette MAC n'est pas stable non plus, à
l'import d'un `.ova` VirtualBox en attribue une nouvelle. `adresse_vm.sh`
demande donc les MAC à VirtualBox lui-même, seule source de vérité :

```bash
VM=$(./adresse_vm.sh)     # lit la table ARP, balaye le sous-réseau si besoin
```

`adresse_vm.sh` ne renvoie **aucune adresse de repli** : VM introuvable, il
sort en erreur. Viser l'IP d'une autre machine serait pire que de ne rien
lancer. Surcharges : `MAC_VM=...` (une ou plusieurs), `PORT_SONDE=...` (8180
par défaut, sert de confirmation d'identité — un port fermé signale une VM
encore en démarrage), `VBOX=...` si le binaire n'est pas dans le `PATH`. Sonde
rapide si la table ARP est déjà remplie, ~20 ms ; ~10 s si le balayage doit
remplir la table.

La VM tourne dans VirtualBox (`metasploitable2 1`, issue de l'import du `.ova`
du 2026-10-03, MAC `0800270770B5`), réseau ponté sur `wlp0s20f3`. Réseau privé,
autorisation implicite. Ubuntu 8.04, Apache 2.2.8, MySQL 5.0.51a-3ubuntu5,
Tomcat 5.5, PHP 5.2.4. Accès SSH `msfadmin`/`msfadmin` avec
`HostKeyAlgorithms=+ssh-rsa` (OpenSSH de 2008).

| Cible | État |
|---|---|
| port 80 | Apache 2.2.8 : accueil Metasploitable2, DVWA, Mutillidae, phpMyAdmin, TikiWiki, TWiki, DAV, **WordPress 3.9.2** (`/wordpress/wp-login.php`) |
| port 8180 | Tomcat 5.5 : `/manager/html` → 401, realm `Tomcat Manager Application` ; **WebGoat 5.3** (`/WebGoat/attack`) |
| port 8009 | AJP Tomcat (non testé par l'outil) |
| port 8080 | **fermé** |

Identifiants réels validés : DVWA `admin`/`password`, Mutillidae
`admin`/`adminpass`, phpMyAdmin `root`/`toor`, Tomcat `tomcat`/`tomcat`,
WordPress `admin`/`admin`, WebGoat `webgoat`/`webgoat`.

Corrections appliquées le 2026-10-02 (sauvegarde dans `/root/sauvegarde`) :
mot de passe MySQL `root` passé de vide à `toor`, puis reconfigurés DVWA
(`config/config.inc.php`), Mutillidae (`config.inc`), TikiWiki et TikiWiki-old
(`db/local.php`, qui utilisaient `root`/`root`). La base de Mutillidae a été
recréée : son `config.inc` pointait sur `metasploit` (vide) au lieu de
`owasp10`, table `accounts` comprise. Alias Apache ajouté pour servir
`/phpmyadmin/` à côté du canonique `/phpMyAdmin/`.

Toujours sonder les ports avant une démo :

```bash
VM=$(./adresse_vm.sh) || exit 1
for p in 80 8080 8180; do
    timeout 2 bash -c "echo > /dev/tcp/$VM/$p" 2>/dev/null \
        && echo "$p ouvert" || echo "$p fermé"
done
```

Ne pas se fier à ce test pour le port 8180 : il a renvoyé « fermé » alors que
Tomcat répondait. Vérifier plutôt par une vraie requête
(`requests.get(f"http://{VM}:8180/", timeout=10)`).

## 6. Pièges déjà payés — ne pas les réintroduire

1. **Tomcat n'a pas de formulaire.** `--profil tomcat` active `--basic-auth`
   (`GET` + en-tête `Authorization`), port 8180 sur cette VM, pas 8080.
2. **WebGoat n'a pas de formulaire non plus**, contrairement à tous les cours :
   son `web.xml` ne déclare qu'un `login-config BASIC` et son code ne contient
   ni Acegi ni filtre de formulaire. Il s'attaque donc comme le Manager, avec
   `--profil tomcat -U webgoat`, en visant `/WebGoat/attack`. La racine
   `/WebGoat/` répond `401` tant qu'on n'est pas authentifié (la contrainte de
   sécurité couvre tout `/WebGoat/*`), puis `404` une fois authentifié : ne pas
   confondre les deux, l'outil les compte tous deux comme échec. Le profil
   `webgoat` du laboratoire reste lui un formulaire (`username`/`password`/`csrf`)
   : c'est la version que décrit l'OWASP Testing Guide, et les tests en dépendent.
3. **phpMyAdmin ne renvoie plus de 302 à corps vide** (constaté le 2026-10-03,
   ce que contredit le diagnostic d'origine). `GET /phpMyAdmin/` répond `200`
   avec le formulaire, et le `POST` de connexion donne `2390 o` sur succès
   contre `3379 o` avec `#1045 - Access denied` : les empreintes se
   distinguent sans suivre la redirection. Le chemin reste `/phpMyAdmin/` sur le
   port **80**, casse significantielle. `conf.d/alias-phpmyadmin` ajoute
   l'alias `/phpmyadmin/`. Si le 302 vide réapparaît un jour, c'est que la
   session phpMyAdmin s'appuie de nouveau sur une redirection : le profil
   garde `--follow-redirects`, inoffensif dans les deux cas.
4. **DVWA n'expose aucun `user_token`** sur sa page de connexion : c'est le
   bouton `Login=Login` qui exécute le handler. Sans lui, refus **muet**.
   D'où `collect_submit_fields()` qui envoie les boutons détectés, et
   `--inspect` qui les exclut des champs d'identifiant proposés.
5. **Mutillidae se connecte** (`admin`/`adminpass`) **et** renvoie l'identifiant
   et le mot de passe dans sa page d'erreur (`SELECT ... WHERE
   password='...'`). Sans masquage, chaque essai change la longueur de la page
   et l'outil annonce un **faux succès à l'essai 1**.
   Parade : `masque_les_valeurs()` remplace la valeur par `<ESSAI>` uniquement
   devant un nom de champ d'identifiant (`INDICES_ECHEC`), **jamais** dans le
   balisage — `type="password"` et `name="password"` doivent rester intacts.
   Les tests de `TestCibleReelle` verrouillent ce comportement.
6. **Seuils de masquage** : secrets de moins de 3 caractères non masqués
   (volatile par construction), donc `SUSPECT` possible, jamais faux succès.
7. **Longueurs comparées par tranches de 256** (`Fingerprint.cluster`) : deux
   pages d'échec qui diffèrent de quelques octets restent dans le même
   cluster, sinon le mot de passe renvoyé par Mutillidae ferait crier
   « réussite ». Un test qui fabrique des corps trop courts (43 contre 46
   octets) tombe donc dans `SUSPECT` : c'est un artefact du harnais, pas un
   défaut de l'outil.
8. **Corps POST lu une seule fois** (`lire_corps()`) : le relire vidait la
   requête et provoquait `501 Unsupported method` en keep-alive.
9. **Casse** : une faute `Couple`/`couple` coûtait un `NameError` silencieux.

## 7. Ce qui est fait

- Modes GET/POST, JSON, multi-utilisateurs, `--dry-run`, `--inspect`,
  rapport JSON + texte, détection à trois niveaux (motifs, calibration,
  statistiques) avec verdicts `ECHEC` / `SUCCES` / `SUSPECT` / verrouillage.
- 7 profils de laboratoire (`interne`, `dvwa`, `wordpress`, `mutillidae`,
  `phpmyadmin`, `webgoat`, `tomcat`) et 6 presets applicatifs côté outil.
- Utilitaires annexes : `test.py` (vérification manuelle d'un couple),
  `bruteforcessh.py` (scanner SSH, hors périmètre HTTP).
- `--follow-redirects` / `--no-follow-redirects` : comparer la page atteinte
  après un 302 au corps vide (phpMyAdmin).
- Dictionnaires : `dico.txt` (10 000), `dico_labo.txt` (20, dont `Lab2024!` en
  6ᵉ position), `dico_metasploitable.txt` (6 mots des applis).
- 70 tests + sept pilotes de recette dans `tests/recette/`, lancés par
  `./tests/recette/lancer_recette.sh` ; documentation à jour (§6.3.1,
  §8.8, §12.3.1 du manuel).
- La racine du laboratoire redirige vers le chemin du profil, pour les six
  profils à formulaire comme pour Tomcat en Basic : viser `http://host:port/`
  suffit maintenant.

## 8. Reste à faire (au choix, selon l'envie)

- **Chantier clos le 2026-10-02** : WordPress 3.9.2 et WebGoat 5.3 ont été
  installés sur la vraie VM (procédé détaillé en §8.9 du manuel). WordPress est
  dans `/var/www/wordpress`, sa base `wordpress` utilise le compte MySQL
  `root`/`toor`. Le WAR WebGoat est dans
  `/var/lib/tomcat5.5/webapps/WebGoat.war`.
  Trois obstacles ont dû être levés côté VM, à ne pas refaire à l'aveugle :
  `openjdk-6-jre-headless` (204 Mo) à la place de `gij`, les rôles exacts
  `webgoat_user`/`webgoat_admin`/`webgoat_challenge` dans `tomcat-users.xml`
  (sans eux : 403), et `TOMCAT5_SECURITY=no` dans `/etc/init.d/tomcat5.5`
  (le `SecurityManager` rendait toutes les pages en 500 ;
  `/etc/default/tomcat5.5` est ignoré à ce sujet). Original sauvegardé dans
  `/root/sauvegarde/init.d-tomcat5.5-avant-webgoat`.
- **Deux pièges révélés par la réimportation du 2026-10-03**, à refaire après
  chaque import d'un `.ova` neuf, parce que l'IP change (nouvelle MAC, nouveau
  bail DHCP) alors que la VM garde l'ancienne en mémoire :
  1. **WordPress casse entièrement.** Sa table `wp_options` porte `siteurl` et
     `home` pointant sur l'IP de l'ancienne VM, et le formulaire de connexion
     publie cette valeur dans son `action` : l'outil suit donc le formulaire
     et poste vers une IP morte, sans jamais voir la page. Message
     trompeur, `No route to host` sur l'hôte de la calibration alors que la
     cible est bonne. Remède :
     `mysql -uroot -ptoor wordpress -e "update wp_options set
     option_value='http://<IP>/wordpress' where option_name in ('siteurl','home');"`
     — le suffixe `/wordpress` est obligatoire, l'oublier donne un WordPress
     qui répond mais refuse toute connexion. Aucune autre application (DVWA,
     Mutillidae, phpMyAdmin, TikiWiki, TWiki) ne fige d'IP : vérifié sur les
     six pages.
  2. **Apache ne démarre pas au premier boot**, port 80 muet alors que MySQL,
     Tomcat et VNC répondent. `apache2ctl configtest` dit `Syntax OK` et le
     symlink `S91apache2` est bien en place. Vérifié le 2026-10-03 : **un
     simple reboot suffit**, le boot suivant démarre Apache normalement
     (`/etc/init.d/apache2 start` au pire, mais inutile). Tous les scénarios
     du chapitre 8 (port 80) échouent tant que ce n'est pas fait.
- **Écart assumé, décidé le 2026-10-02** : `PROFILS["webgoat"]` de
  `bruteforce.py` reste orienté formulaire, comme `lab_server.py` et les cinq
  tests qui en dépendent ; le laboratoire sert la version que décrit l'OWASP
  Testing Guide. Le WebGoat 5.3 de la vraie VM n'ayant pas de formulaire, la
  commande documentée pour cette VM est `--profil tomcat -U webgoat`. Décision
  explicite de l'utilisateur : ne pas réécrire le profil du labo et ses tests
  pour coller au déployé. Ne pas rouvrir sans qu'il le demande.
- Rien d'autre : les deux chantiers ouverts en début de session (redirection
  de la racine du labo, déplacement des harnais hors de `/tmp`) sont clos.
- Clos le 2026-10-03 : l'IP de la VM est désormais résolue par
  `adresse_vm.sh`, qui lit les MAC des VMs en marche auprès de VirtualBox —
  l'import d'un `.ova` en changeant. Plus aucune adresse en dur dans
  `AGENTS.md` ni `MANUEL.md`.

## 9. Recette express pour une démo

```bash
# laboratoire : aucune VM requise
python3 lab_server.py --port 8080 --profil dvwa &
python3 bruteforce.py --profil dvwa -U admin \
    -u http://127.0.0.1:8080/dvwa/login.php -w dico_metasploitable.txt

# vraie VM
VM=$(./adresse_vm.sh) || exit 1
python3 bruteforce.py --profil dvwa -U admin -k 20 -d 0.5 \
    -u http://$VM/dvwa/login.php -w dico_metasploitable.txt
python3 bruteforce.py --profil tomcat -U tomcat -k 10 \
    -u http://$VM:8180/manager/html -w dico_metasploitable.txt
python3 bruteforce.py --profil phpmyadmin -U root -k 6 \
    -u http://$VM/phpMyAdmin/index.php -w dico_metasploitable.txt
python3 bruteforce.py --profil mutillidae -U admin -k 9 \
    -u http://$VM/mutillidae/index.php?page=login.php \
    -w dico_metasploitable.txt
python3 bruteforce.py --profil wordpress -U admin -k 4 -d 0.5 \
    -u http://$VM/wordpress/wp-login.php \
    -w dico_metasploitable.txt
python3 bruteforce.py --profil tomcat -U webgoat -k 8 -d 0.4 \
    -u http://$VM:8180/WebGoat/attack \
    -w dico_metasploitable.txt
```

Toujours montrer `--inspect` et `--dry-run` avant l'attaque réelle.

## 10. Fichiers de recette

| Fichier | Rôle |
|---|---|
| `tests/test_outils.py` | 70 tests unitaires et d'intégration (démarre le labo). |
| `tests/recette/lancer_recette.sh` | recette complète en une commande. |
| `tests/recette/verif_profils.py` | 6 cas : profils + options de détection. |
| `tests/recette/verif_profils2.py` | 7 cas : les 6 applications + non-régression. |
| `tests/recette/test_bruteforce.py` | 15 vérifications de bout en bout. |
| `tests/recette/test_gaps.py` | 15 cas d'options (`-H`, `-c`, `-T json`…). |
| `tests/recette/test_get.py` | mode GET et `--success-on-redirect`. |
| `tests/recette/test_interactive.py` | mode interactif, jeton conservé. |
| `tests/recette/test_docs.py` | les exemples du manuel, exécutés tels quels. |
