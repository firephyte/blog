# HTB Challenge Writeup: Ancient Encodings
### By: gnos1s


Upon downloading the file, we get a file and a python script:

```python
from Crypto.Util.number import bytes_to_long
from base64 import b64encode
from secret import FLAG


def encode(message):
    return hex(bytes_to_long(b64encode(message)))


def main():
    encoded_flag = encode(FLAG)
    with open("output.txt", "w") as f:
        f.write(encoded_flag)


if __name__ == "__main__":
    main()
    ```

```
$ cat output.txt
0x53465243657a51784d56383361444e664d32356a4d475178626a6c664e44497a5832677a4d6a4e664e7a42664e5463306558303d%
```

As we can see from the python script, the flag is base64 encoded, then hexed. We can reverse these operations one by one.

The decrypted text is: ```SFRCezQxMV83aDNfM25jMGQxbjlfNDIzX2gzMjNfNzBfNTc0eX0=```

Now we just have to base64 decode:

```
$ echo "SFRCezQxMV83aDNfM25jMGQxbjlfNDIzX2gzMjNfNzBfNTc0eX0=" | base64 -d
HTB{411_7h3_3nc0d1n9_423_h323_70_574y}
```

FLAG: HTB{411_7h3_3nc0d1n9_423_h323_70_574y}