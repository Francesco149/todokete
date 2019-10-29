work-in-progress headless client for love live! school idol festival
all stars

follow along with my [notes](https://github.com/Francesco149/reversing-sifas)
to see how I reverse engineer it

this project is at a very early stage. right now it's meant to be used by
me and other developers to reverse engineer the api further and test it.
eventually i want this to be a module you can use to automatically manage
and create your sifas accounts

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

# build and run (windows/cygwin)
install nodejs, I don't think the additional tools for native extensions
are necessary, not sure

download java for windows x64 https://jdk.java.net/java-se-ri/9 and extract
somewhere

the java cacerts file will be broken. replace it with [this](https://mega.nz/#!hBZxHSwA!d248h7O3OVs22NSESCNelhfiXPcWh131mGRNZIJqaY0)
. you should copy it to `path\to\java\lib\security` replacing the cacerts
file

from the cygwin installer select curl, sqlite, sqlite-devel, zip, git.
other packages might be necessary that I missed, if you run into any
issue re-run cygwin installer to install more pkgs

run (replace paths as appropriate for your installs)

```
echo 'export PATH="$PATH:/cygdrive/c/path/to/java-9/bin"' >> .bashrc
echo 'export PATH="$PATH:/cygdrive/c/Program Files/nodejs"' >> .bashrc
curl -s https://get.sdkman.io | bash
sdk install kotlin
```

last command will prompt you to run some init command. run it

then run

```
source ~/.bashrc
```

now you can

```
git clone https://github.com/Francesco149/todokete ~/todokete
cd ~/todokete/token-generator
npm i
npm start
```

and in another cygwin window:

```
cd ~/todokete
./build.sh
```

# client progress
- [x] store accounts in a database. this is very early and might change
  significantly as the client takes shape
- [x] keep track of account tutorial status in case of failed requests,
  crashes, disconnects, etc
- [x] resume accounts with incomplete tutorial (not extensively tested)
- [x] log in existing accounts
- [ ] configurable endpoint and other version/region tied things
- [x] multithread support (theoretically works but not tested)
- [ ] store full request logs for each account
- [ ] a way to view and filter all logs combined
- [ ] proxy support

# api progress
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
- [x] `/live/start` starts a live, receives note data for the chosen song
- [x] `/ruleDescription/saveRuleDescription` not sure, I think it has
  something to do with either gifts or storyline progress status
- [x] `/live/finish` completes a live. sends precise note-by-note scoring.
  accurate simulation of the game's scoring system is required to submit
  real scores, however for the tutorial lives it's possible to skip by
  submitting all the notes with zero values as demonstrated in my
  `skipLive` function. this is equivalent to pausing and clicking ok to
  skip the live
- [x] `/communicationMember/setFavoriteMember` sets favorite member, the
  character who appears in your main screen
- [x] `/bootstrap/fetchBootstrap` fetches all kinds of info based on the
  list of id's provided. things that can be fetched include login bonuses,
  expired items, new badges, banners, notices, billing info
- [x] `/navi/tapLovePoint` sent when you touch your waifu in the main
  screen
- [x] `/navi/saveUserNaviVoice` not 100% sure, I think it has to do with
  unlocking menu options
- [x] `/trainingTree/fetchTrainingTree` supposed to get training locations
  or something like that but during the tutorial the response is empty
- [x] `/trainingTree/levelUpCard`
- [x] `/trainingTree/activateTrainingTreeCell` probably sent when you
  start training. not sure where the cell id's come from
- [x] `/communicationMember/finishUserStorySide` complete a character
  side story
- [x] `/card/updateCardNewFlag` used to refresh cards info
- [x] `/liveDeck/saveDeckAll` saves live team/s. not sure what cardWithSuit
  means yet. maybe related to the outfit they're wearing?
- [x] `/liveDeck/saveSuit` not sure, but I think it saves the outfit for
  a particular character
- [x] `/livePartners/fetch` fetches a list of live partners. empty request
- [x] `/gacha/fetchGachaMenu` gets the list of scouting pools, empty req
- [x] `/gacha/draw` scout from a pool
- [x] `/tutorial/phaseEnd` ends the tutorial. empty request
- [x] `/dataLink/fetchGameServiceData` gets existing accounts
  associated with a `service_id`
- [x] `/dataLink/linkOnStartUpGameService` associates the currently logged
  account to a service id so it can be later retrieved with
  fetchGameServiceData or fetchGameServiceDataBeforeLogin
- [x] `/loginBonus/readLoginBonus` marks login bonus splashscreens as read.
  empty response
- [x] `/notice/fetchNoticeDetail` gets contents of a specific note. a list
  of notes can be obtained from `fetch_bootstrap_notice_response` when
  calling fetchBootstrap
- [x] `/notice/fetchNotice` gets various notices, empty request
- [x] `/present/fetch` gets a list of pending presents. empty request
- [x] `/present/receive` opens presents, takes a list of present id's from
  `/present/fetch`

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
