just a tiny http server that uses `push-token` to generate sifas push
notification tokens. this is a temporary solution until I implement
firebase in kotlin

# usage

```
npm i
npm run
```

now you can generate tokens by just sending a GET request to localhost:6969

the entire response body (plain text) is your token

```
curl 127.0.0.1:6969
```
