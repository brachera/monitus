#!/usr/bin/env python3

#Import required libraries
import json
import os
import re

techniques = []
scores = []
for _, _, files in os.walk('.'):
    # match files which begin with  the letter t, i.e. the profiles
    files = [file for file in files if re.match(r'^t', file)]
    for file in files:
        technique_id = file.strip('.pp')
        entry = {
            # Upper case T ID required for ATT&CK Navigator
            "techniqueID": technique_id.upper(),
            "score": 100,
        }
        scores.append(entry)
        
# Json template for creation        
layer = {
    "domain": "mitre-enterprise",
    "name": "Puppet coverage",
    "gradient": {
        "colors": [
            "#ffffff",
            "#ff6666"
        ],
        "maxValue": 100,
        "minValue": 0
    },
    "filters": {
		"stages": [
			"act"
		],
		"platforms": [
			"Linux"
		]
	},
    "version": "2.2", 
    "techniques": scores,
}

with open('layer.json', 'w') as f:
    f.write(json.dumps(layer))
        