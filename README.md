# Privbox Reimplementation
CMPT783 Spring 2026 Project Group Byte4Byte

# Skeleton

We can use this inital skeleton to implement the API and core functionality for the Privbox reimplementation. 

```
privbox/
├── api/
│   ├── __init__.py
│   ├── rg_api.py          # Rule Generator endpoints
│   ├── mb_api.py          # Middlebox endpoints
│   ├── endpoint_api.py    # Sender/Receiver endpoints
│   └── models.py          # Pydantic models
├── core/
│   ├── crypto.py          # Charm-Crypto based EC operations
│   ├── protocols.py       # PrivBox protocols (Figs 2,3,5)
│   ├── tokenization.py    # Token encryption (Fig 6)
│   ├── inspection.py      # Traffic inspection (Fig 7)
│   └── storage.py         # State management
├── tests/
├── requirements.txt
└── main.py
```