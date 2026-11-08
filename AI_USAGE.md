## Tools

I used Claude (Anthropic) to draft triage/core.py and triage/**main**.py and to write my own tests in tests/test_triage.py. I read the code, ran `python -m pytest -q` myself and compared every rule with the task text.

## What AI got wrong

I checked the spots where assistants usually slip: a security-severity that is a string versus a number (and 0, 11, "abc", True), Bandit's confidence downgrade applying after the severity mapping, taking the Bandit code line by exact line number (9 vs 10 vs 100) instead of a prefix match, fingerprints that must ignore line numbers and whitespace, a suppression expiring today still applying, and exit code 2 for missing or non-JSON input. (Edit this section with anything you personally saw go wrong while testing.)

## In my own words

**Bandit rates the MD5 in etag() HIGH and DB_PASSWORD LOW. Which would you fix first in Diwan's code, and why?**
I would fix DB_PASSWORD first: a hard-coded credential gives direct access to the database to anyone who can read the repo or the build, while MD5 used for an ETag is a cache check, not something an attacker gains from. Bandit rates how risky the pattern looks, not what it means in our code, so I check the context before trusting its rating.

**Why does a suppression need an expiry date?**
Without one a suppression silently becomes permanent: the code, the exposure or the owner can change and nobody looks again. An expiry forces someone to re-confirm the risk, so accepted risks do not turn into forgotten ones.
