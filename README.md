# Sub-Algo-Frq-Analysis

## About
This is a cryptography project about the substitution algorithm and the frequency analysis technique utilized to crack its ciphers.


## Requirements
- Python3
- Install the necessary packages by executing the following command line: `pip3 install -r requirements.txt`


## How to run these scripts?
- In a terminal, check the available run options for the substitution algorithm script by executing the following command line: `python3 sub.py -h`

![suboptions](https://user-images.githubusercontent.com/86275885/122942009-e1d47980-d343-11eb-989d-27e86fa01ce1.png)


- You can create a cipher text from a plain text (e.g., the provided example file is data/harrypotter.txt) by using the substitution algorithm script by executing the following command line: `python3 sub.py -e -f data/harrypotter.txt`

![sub](https://user-images.githubusercontent.com/86275885/122940933-e8aebc80-d342-11eb-8973-00ec5d944696.png)

- Copy the generated cipher text and save it as *log/cipher.txt*

- In a terminal, check the available run options for the frequency analysis script by executing the following command line: `python3 frq.py -h`

![frqoptions](https://user-images.githubusercontent.com/86275885/122942031-e5680080-d343-11eb-9da8-e3d0010262fe.png)


- You can attempt to crack the previously generated cipher text by using the frequency analysis algorithm script by executing the following command line: `python3 frq.py -f log/cipher.txt`

![frq1](https://user-images.githubusercontent.com/86275885/122941184-27447700-d343-11eb-871f-53439815d888.png)

![frq2](https://user-images.githubusercontent.com/86275885/122941187-27dd0d80-d343-11eb-9d89-f166c0f7d543.png)
