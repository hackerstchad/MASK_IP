# MASK_IP — Calculateur Avancé de Masques de Sous-Réseau

<img width="1248" height="832" alt="OIG3 AbZqg1c" src="https://github.com/user-attachments/assets/bfefb797-e794-48df-a4d2-4d0b93b06eaf" />

NET -TOOLS LINK https://www.majorgeeks.com/mg/sortdate/networking.html

> **Créé par HackersTchad**  
> Version 3.0.0 | Python 3.8+

MASK_IP est un calculateur de sous-réseaux IPv4 et IPv6 très avancé, Il permet d'analyser une adresse IP, de convertir masque/CIDR, de découper un réseau en sous-réseaux (VLSM), et d'agréger des routes (supernet).

## Caractéristiques

- Analyse IPv4 complète : masque, wildcard, network, broadcast, plage utilisable, nombre d'hôtes, classe IP
- Analyse IPv6 compressée/éclatée
- Conversion masque ↔ CIDR
- Découpage VLSM d'un réseau parent
- Agrégation de routes (supernet)
- Affichage binaire et hexadécimal
- Interface interactive

## Installation

```bash
pip install -r requirements_MASK_IP.txt
```

## Utilisation

[![Démonstration Asciinema](https://asciinema.org/a/1264812.svg)](https://asciinema.org/a/1264812)



### Mode interactif

```bash
python MASK_IP.py
```

### Ligne de commande

```bash
# Analyse IPv4
python MASK_IP.py -i 192.168.1.10/24

# Analyse IPv6
python MASK_IP.py -i 2001:db8::1/64

# Convertir CIDR en masque
python MASK_IP.py -c /24

# Convertir masque en CIDR
python MASK_IP.py -c 255.255.255.0

# Découper un réseau
python MASK_IP.py -s 192.168.0.0/24 -p 26

# Agréger des réseaux
python MASK_IP.py -a 192.168.0.0/24,192.168.1.0/24
```

## Exemple de sortie

```
┌─────────────────────────────────────────────────────────┐
│ Propriété               │ Valeur                        │
├─────────────────────────┼───────────────────────────────┤
│ Adresse IP              │ 192.168.1.10                  │
│ CIDR                    │ /24                           │
│ Masque                  │ 255.255.255.0                 │
│ Wildcard                │ 0.0.0.255                     │
│ Adresse réseau          │ 192.168.1.0                   │
│ Broadcast               │ 192.168.1.255                 │
│ Première IP utilisable  │ 192.168.1.1                   │
│ Dernière IP utilisable  │ 192.168.1.254                 │
│ Nombre total d'hôtes    │ 254                           │
│ Classe IP               │ C                             │
└─────────────────────────────────────────────────────────┘
```

## Licence

Projet éducatif — usage libre et responsable.
