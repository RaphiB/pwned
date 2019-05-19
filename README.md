# pwned

pwned is a Python tool to check for personal data leaks. It takes emails and passwords as input and queries Troy Hunt's haveibeenpwned.com. 

## Security  

Passwords aren't stored or sent in plaintext. The passwords you enter in this tool are hashed and only a fraction of the hash is sent to the API. 

More information on that topic: [Privacy of your passwords](https://www.troyhunt.com/ive-just-launched-pwned-passwords-version-2#cloudflareprivacyandkanonymity)

## Installation

Use the package manager [pip](https://pip.pypa.io/en/stable/):

```bash
pip install -r requirements.txt
```

## Usage
Just execute the tool with Python3.

```python
python ./pwned.py
```

## License
This software is released under the GNU General Public License v3.0. See LICENSE.md for details.
