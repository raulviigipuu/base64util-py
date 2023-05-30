# base64util-py

Base64 encoder/decoder in python using tkinter gui.

User can choose file or directory and encode it to one base64 text file and later restore the file/directory. Also the result can be encrypted using password.

## install

  python -m venv venv
  . venv/bin/activate
  pip install -r requirements.txt

Maybe tkinter should be installed separately, for example in Ubuntu:

  sudo apt-get install python3-tk

## run

  python main.py

## screenshot

![Screenshot (Ubuntu)](./screenshot.png "Screenshot (Ubuntu)")

## bugs

  \- directory structure not created correctly when encoded in windows and decoded in linux

## todo

  \- nice error and success messages

  \- console prints out or behind --debug flag
