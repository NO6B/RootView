#!/bin/bash

CIBLE="ip"

echo "Début des tests de détection pour RootView sur l'hôte $CIBLE..."


echo "[1/5] Lancement du test SSH Brute Force..."
for i in {1..30}; do 
    ssh -o ConnectTimeout=2 -o BatchMode=yes -o StrictHostKeyChecking=no ubuntu@$CIBLE 2>/dev/null
done


echo "[1.bis] Lancement du test SSH Utilisateur Invalide..."
ssh -o ConnectTimeout=5 -o BatchMode=yes user_fantome_test@$CIBLE 2>/dev/null


echo "[2/5] Lancement du test de volume HTTP (requiert apache2-utils)..."
ab -n 150 -c 10 http://$CIBLE/ > /dev/null 2>&1


echo "[3/5] Lancement du test SQLi..."
curl -s "http://$CIBLE/login?id=1'%20OR%201=1" > /dev/null


echo "[4/5] Lancement du test Path Traversal..."
curl -s "http://$CIBLE/../../etc/passwd" > /dev/null

# HTTP Brute Force (Web)
echo "[5/5] Lancement du test HTTP Brute Force..."
for i in {1..25}; do 
    curl -s -X POST "http://$CIBLE/login" -d "user=admin&pass=123" > /dev/null
done

echo "Tests terminés"
