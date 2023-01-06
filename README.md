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
pip install requests PyQt5 pyperclip fake-headers
```

Run `FmhyChecker.pyw`

<hr width=100>

## Usage

### Comparing and copying links

This tool takes links inputted into the field on the left, and checks if they are not already present in the wiki. Links will be automatically pulled using regex.

*Note that the ReGex is designed to ignore trailing `/`, `http`/`https`, and `www`/`ww<n>`*

*Dupes* will be indicated with a ❌, and *unique* links will have a ✅. Once the scan is complete, the `Copy ❌` and `Copy ✅` buttons will be ungreyed, allowing you to copy all *dupe* or *unique* flagged links separated by a newline (`\n`).


### Checking URL validity 

![video here](https://i.imgur.com/9BhHsaY.mp4)

Selecting links and clicking `Test` will the URL's redirect chain. View a URL by hovering over its status code.

The `Copy 🔍` button will copy all links that are *unique* (✅) **and** *tested* to have successful responses (read more about status codes [here](https://httpstatus.io/http-status-codes)).


### CSV Exports

The download button will export the data to a CSV file.

![csv](https://i.imgur.com/KzxzNIb.png)

*Note: Status codes are hyperlinked.*

---