# soteria

Soteria provides a way to centralize encrypted data on any drive. By containerizing
data, large amounts of personal data can be compiled into one place for ease
of access across most file systems.

Creates a new container `MyContainer.enc` in the current working directory:
```sh
soteria mk MyContainer
```

Deletes a container `MyContainer.enc` in the current working directory:
```sh
soteria del MyContainer
```

Write and encrypt one or more files to the container `MyContainer`:
```sh
soteria MyContainer store passwords.txt presentation.mp4
```

Decrypt and read one or more files from the container `MyContainer`:
```sh
soteria MyContainer load github_password.txt
```
