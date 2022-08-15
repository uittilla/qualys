### Qualys vulnerability parser

``` 
pip3 install -r requirements.txt

python3 qualys.py --help
usage: qualys.py [-h] [-p] [-f] [-v]

Qualys Vulnerability Tracking. 
Combines data sources into individual vulnerabilities.

optional arguments:
  -h, --help     Show this help message and exit
  -p, --publish  Fetch qualys data and prepare it for consumption
  -f, --fullrun  Enact a full qualys kb run
  -v, --verbose  Increase output verbosity
  
Your first run should be [python3 qualys.py -p -f -v]
```

