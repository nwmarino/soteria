# soteria

Soteria provides a way to centralize encrypted data on any drive. By containerizing
data, large amounts of personal data can be compiled into one place for ease
of access across most file systems.

Creates a new container `MyContainer` in the current working directory:
```sh
soteria -mk MyContainer -pw <password>
```

Deletes a container `MyContainer` in the current working directory:
```sh
soteria -rm MyContainer -pw <password>
```

Write and encrypt one or more files to the container `MyContainer`:
```sh
soteria -c MyContainer -pw <password> -op store passwords.txt presentation.mp4
```

Decrypt and read one or more files from the container `MyContainer`:
```sh
soteria -c MyContainer -pw <password> -op load github_password.txt
```
