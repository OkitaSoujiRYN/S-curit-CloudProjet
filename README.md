# Sécurité Cloud Projet
Ce projet a pour objectif de mettre en place un environnement AWS intégrant les meilleures pratiques en matière de
sécurité, de disponibilité et de gestion des risques. L’application débutera avec une base de 1 000
utilisateurs, avec la capacité d’évoluer pour prendre en charge jusqu’à 100 000 utilisateurs
simultanés..
## Document du projet
Le sujet complet du projet est disponible en cliquant sur le lien suivant :
[Projet Sécurité dans le cloud](./Projet%20Sécurité%20dans%20le%20cloud.pdf)

## Contenu du projet
- `main.tf` : Fichier principal Terraform.
- `lambda_function.py` : Code pour la fonction Lambda.
- `lambda_function.zip` : Fichier compressé pour la fonction Lambda.
- [Projet Sécurité dans le cloud.pdf](./Projet%20Sécurité%20dans%20le%20cloud.pdf) : Sujet du projet.

## Instructions d'utilisation
1. Clonez ce dépôt :
   ```bash
   git clone https://github.com/OkitaSoujiRYN/S-curit-CloudProjet.git
   cd S-curit-CloudProjet
2. Initialisez Terraform
terraform init

3. Appliquez la Configuration Terraform
   terraform apply
