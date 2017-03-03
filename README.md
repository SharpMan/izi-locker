## Synopsis

This is a simple variation of crypto-locker such as TeslaCrypt and Cryptor which aims to target data-file (amv,mp3,pdf,etc..).
The process begins by :

* Recursive directory scan
* List of sensitive files targets
* Encrypting each file content with **AES256** or **RSA-2048** using a unique key
* Renaming the file
* Sending the path, oldname, new_name, and encrypting key to the malware server

######Note 1:
I didn't use **PKCS#5** padding since it's a lose of time.
I just ignore the last block of file which is not dividable by 16.

######Note 2:
The encryption process and manipulation of data are done in the CPU register instead of ~~RAM~~.
This will accelerate and smooth data access.

## Plain-text resources
[Remove “Your personal files are encrypted” ransomware](https://malwaretips.com/blogs/remove-your-personal-files-are-encrypted-virus/)
[KillDisk Ransomware Targets Linux; Demands $250,000 Ransom, But Won't Decrypt Files](http://thehackernews.com/2017/01/linux-ransomware-malware.html)
[Los Angeles College Pays Hackers $28,000 Ransom To Get Its Files Back](http://thehackernews.com/2017/01/ransomware-malware-attack.html)

## Acknowledgments

* Hal Finney's AES256 implementation
