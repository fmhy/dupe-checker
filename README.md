# FMHY Dupe Checker

A simple, *fast* tool to compare links against the FMHY wiki, and display their redirect chains.

![screenshot](https://i.imgur.com/B0yZPq4.png)

<hr width=100>

## Getting started

### Clone the repo

```bash
git clone https://gitlab.com/cevoj/fmhy-dupe-checker.git
cd fmhy-dupe-checker\
```

### Install requirements

[Python](https://www.python.org/downloads/) is required. 

```bash
pip install -r requirements.txt
```

Run `FmhyChecker.pyw`

<hr width=100>

## Usage

### Comparing links to wiki

This tool takes links inputted into the field on the left, and checks if they are not already present in the wiki.

**Links** ***already*** **in the wiki** will be indicated with a ❌, and **links** ***NOT*** **in the wiki** will have a ✅.

Links will be automatically pulled using regex. The regex is designed to ignore trailing `/`, `http`/`https`, and `www`/`ww1`...`2`...etc to be as flexible as possible.

### Copying links

The UI provides 3 buttons to copy links to your clipboard.

| Button | What it copies |
|-|-|
| `Copy ❌` | Copies *duped* (❌) links |
| `Copy ✅` | Copies *unique* (✅) links |
| `Copy 🔍` | Only links that are *unique* (✅) **AND** *tested* with a *successful* response code (🟢)

### Broken link tester

**Usage video**

https://github.com/fmhy/dupe-checker/assets/125338382/e144e529-db6b-4989-a90e-e27f6881efb6

Selecting links and clicking `Test` will the fetch the URL's redirect chain. View more information by *hovering* over a status code.

| Status code | Indication |
|-|-|
| 🟢 `200`-`204` | Successful |
| 🔵 `301`-`307` | Redirect |
| 🟠 `400`-`410` | Client error |
| 🔴 `500`-`504` | Server error |

Read more about status codes [here](https://httpstatus.io/http-status-codes).


### CSV Exports

The download button will export the data to a CSV file.

![csv](https://i.imgur.com/KzxzNIb.png)

*Note: Status codes are hyperlinked.*

---