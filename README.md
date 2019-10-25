work-in-progress headless client for love live! school idol festival
all stars

follow along with my [notes](https://github.com/Francesco149/reversing-sifas)
to see how I reverse engineer it

this project is at a very early stage. right now it's meant to be used by
me and other developers to reverse engineer the api further and test it.
eventually i want this to be a module you can use to automatically manage
and create your sifas accounts

# progress
- [x] `/login/startup`: creates a new account
- [x] `/login/login`: log into existing account
- [x] properly generating `asset_state` instead of hardcoding it
- [x] `/dataLink/fetchGameServiceDataBeforeLogin` gets existing accounts
  associated with a `service_id`, also used to get MasterVersion on
  startup
- [x] `/terms/agreement` used for checking the currently accepted ToS
  version and what the latest version to accept is
- [x] `/userProfile/setProfile` sets name, nickname, message and push
  notification token
- [x] `/userProfile/setProfileBirthday` sets birth month and day
- [x] `/story/finishUserStoryMain` completes a main story chapter

# build and run (linux)
temporarily, you need nodejs to run an additional local service that
generates push notification tokens. this will run on port 6969

```
cd token-generator
npm i
npm start
```

once that's running, you can build and run the client

you need the kotlin compiler (kotlinc) which on void linux is package
`kotlin-bin`

my build script will automatically download and set up dependencies

```
# build and run
./build.sh | tee -a output.log
```

it's recommended to save output to a log as some responses are very large
to read with just terminal scrollback

# rationale
why kotlin? it just so happens that the http library used by the game is
java and I decided to use it for better accuracy. I'm not a big fan of
kotlin, it suffers from the same slow compilation as java, which is
incredibly slow compared to something like C

I will not put this on maven - the directory structure and packaging
process is too ugly and I don't want to tab 10 levels of subdirectories
every time I edit a file. I will leave it as a simple single file.
if you want to use this in a project feel free to just straight up
embed the source file in it
