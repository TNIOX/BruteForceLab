# BruteForceLab

Outil pédagogique d'essai de mots de passe sur formulaire de connexion web, avec
un laboratoire multi-profils qui imite des applications volontairement
vulnérables.

**Usage réservé aux cibles autorisées.** L'outil refuse une adresse publique et
demande une confirmation explicite sinon.

## Documentation

| Fichier | Contenu |
|---|---|
| [`readme.txt`](readme.txt) | Résumé de référence, installation, profils, image VM |
| [`MANUEL.md`](MANUEL.md) | Manuel complet, 12 chapitres |
| [`AGENTS.md`](AGENTS.md) | Notes de reprise, pièges connus de la VM d'atelier |

## Démarrage rapide

```bash
pip install -r requirements.txt

python3 lab_server.py --port 8080 --profil dvwa &
python3 bruteforce.py --profil dvwa -U admin \
    -u http://127.0.0.1:8080/dvwa/login.php -w dico_metasploitable.txt
```

Sur une cible réelle, lire d'abord le chapitre 8 du manuel : `--i-have-authorization`
est demandé, et `--inspect` puis `--dry-run` permettent de voir ce qui sera envoyé
avant toute attaque réelle.

## Laboratory

`lab_server.py` reproduit six applications en local, sans VM et sans réseau :
`interne`, `dvwa`, `wordpress`, `mutillidae`, `phpmyadmin`, `webgoat` et `tomcat`.
Rien ne joint que `127.0.0.1`.

## Tests

```bash
./tests/recette/lancer_recette.sh
```

Compile les modules, lance les 70 tests, enchaîne les sept pilotes de recette et
nettoie les artefacts.

## Licence et mentions

Outil pédagogique. Les cibles d'atelier sont reproductibles par le laboratoire
`lab_server.py` ; l'image Metasploitable2 modifiée est une image du Metasploitable
Project (Rapid7), distribuée séparément et non incluse dans ce dépôt.