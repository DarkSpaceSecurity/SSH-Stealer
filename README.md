# RunAs-Stealer
Smart keylogging capability to steal SSH Credentials including password & Private Key   

## Usage

The stolen credentials are written to `C:\Users\<Username>\Desktop\desktop.ini` ADS `log` stream.   

To get the credentials type the cmd command:
```shell
more < "C:\Users\<Username>\Desktop\desktop.ini:log"
```
To remove the stored credentials type the powershell command:
```powershell
Remove-Item -Path "C:\Users\d1rk\Desktop\desktop.ini" -Stream "log"
```

***N.B: Refer to the Demo down below for each use case*** 



#### Demo
https://github.com/user-attachments/assets/b6558b62-08ad-4efe-9757-1e1113808a0a
