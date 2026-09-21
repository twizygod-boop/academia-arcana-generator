# Academia Arcana — générateur personnalisé Shopify

Ce service complète le thème Shopify. Il transforme les informations saisies sur la fiche produit en documents PDF personnalisés après le paiement.

## Flux
1. Le visiteur fait le test des maisons.
2. Le résultat est mémorisé dans le navigateur.
3. Sur un produit marqué `arcana-personnalise`, le thème pré-remplit prénom/nom/maison.
4. Shopify ajoute ces données comme `line item properties`.
5. Shopify appelle le webhook `orders/paid` de ce service.
6. Le service génère le ou les PDF, crée un ZIP et envoie un lien sécurisé par e-mail.

## Installation
- `npm install`
- copier `.env.example` vers `.env` et renseigner les valeurs.
- `npm start`
- exposer le serveur en HTTPS.
- créer dans Shopify Admin un webhook `orders/paid` vers `https://VOTRE-DOMAINE/webhooks/orders-paid` et utiliser le secret de signature dans `SHOPIFY_WEBHOOK_SECRET`.

## Produits Shopify
Ajoute le tag `arcana-personnalise` aux produits personnalisés. Sur ces produits, le thème affiche le formulaire de personnalisation et transmet :
- `Prénom`
- `Nom`
- `Maison`
- `_arcana_personalized=true`

Les titres contenant `Lettre`, `Passeport`, `Certificat` ou `Profil` déterminent le document généré. Un titre contenant autre chose produit un passeport par défaut.

## E-mail
Configure un SMTP dans `.env`. Sans SMTP, le fichier est quand même généré et reste accessible par son lien sécurisé, mais aucun e-mail ne sera envoyé.

## Production
Utiliser HTTPS, un vrai stockage persistant pour `storage/`, un SMTP transactionnel et un secret long et aléatoire. Ne pas mettre les secrets dans le thème Shopify.
