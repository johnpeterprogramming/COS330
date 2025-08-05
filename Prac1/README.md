# View Repository: https://github.com/johnpeterprogramming/COS330/tree/master/Prac1
# How to setup:

## Install dependencies
```
sudo apt install -y sqlite3 john git build-essential libssl-dev zlib1g-dev yasm ocl-icd-opencl-dev opencl-headers clinfo
```

## Compile John the Ripper from source (jumbo version), to be able to use gpu
```
git clone https://github.com/openwall/john john-jumbo
cd john-jumbo/src
git checkout bleeding-jumbo
./configure --enable-opencl
make -s clean
make -sj$(nproc)
```

## Setup python environment
```
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
```


## Examples
### Run with mask using gpu and specifying a pot
```
./john-jumbo/run/john sha256_hashes.txt --verbosity=5 --mask='[a-zA-Z][a-zA-Z][a-zA-Z][a-zA-Z][a-zA-Z][a-zA-Z]' --pot=sha256pot -format=raw-SHA256-opencl
```
### Display available formats for opencl
```
./john-jumbo/run/john --list=formats | grep opencl
```
