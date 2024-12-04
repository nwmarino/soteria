# soteria

Soteria provides a way to centralize encrypted data on any drive. By containerizing
files, encrypted data can be moved in one contained place.

Creates a new container `MyContainer` in the current working directory:
```sh
soteria --mk MyContainer --pw <password>
```

Deletes a container `MyContainer` in the current working directory:
```sh
soteria --rm MyContainer --pw <password>
```

Write and encrypt one or more files to the container `MyContainer`:
```sh
soteria MyContainer --pw <password> --store passwords.txt presentation.mp4
```

Decrypt and read one or more files from the container `MyContainer`:
```sh
soteria MyContainer --pw <password> --load github_password.txt
```
