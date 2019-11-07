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
./build.sh daemon | tee -a output.log
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
./build.sh daemon
```

# client progress
- [x] store accounts in a database
- [x] log in existing accounts
- [ ] configurable endpoint and other version/region tied things
- [x] multithread support
- [ ] store full request logs for each account
- [ ] a way to view and filter all logs combined
- [ ] proxy support
- [x] link sifid.net account
- [x] automatically download apk and parse strings and hashes

# backend progress
this is very rough at the moment, I just needed a quick hack to visualize
accounts and items from the temporary front-end I'm developing. it
literally just dumps all the accounts and items at once as json when you
request `/accounts` and lets you get decrypted textures by pak name and
offset.  this requires having an "assets" folder that contains a texture
folder with the decrypted folder as well as the decrypted game databases
(`masterdata.db`, `asset_a_ja_0.db` and all the dictionary db's)

# protocol overview
the body of each request is a json array that contains two elements

- a json object
- a hex string representation of the request hash

`[{"my_data": "blahblah"},"123456789abcdef123456789abcdef123456789a"]`

request headers are the default okhttp3 headers, plus
`content-type: application/json` . make sure this header doesn't have
the charset part or the server will refuse

the hash obtained by running hmac-sha1 on a string that contains the
request path (including the query string) and the json object, separated
by a space

example:
`/some/endpoint?u=123 {"my_data": "blahblah"}`

the key for this hmac-sha1 hash is the sessionKey, which is initially
set to startupKey. this startupKey changes for every version of the game,
but you can easily extract it by using Il2CppDumper with unity version
`2018.4` on `libil2cpp.so` and looking for the endpoint string in the
generated `script.py`, the startup key will be nearby, it's a 16-character
string. if you can't find it, you're gonna have to load the binary into
ghidra or ida, and load the strings from `script.py` (it's an ida script),
then look at `ServerConfig$$.cctor` and all the strings it references

you can even just straight up open the game's global-metadata.dat in a
hex editor and search for the strings there

the base path of the endpoint (currently `/ep1015`) will also change every
version

reponses will also be a json array that contains

- a timestamp
- a master version hash, we will need this later
- unknown integer that is always zero
- response json object
- hash

example:

`[1572439123123,"abcdef012345689a",0,{"some_data":"blah"},"abcdef0123456789abcdef0123456789abcdef01"]`

the query string for requests can contain a number of parameters, in this
order:

- p: platform (a for android). this is always present
- mv: the master version hash. can be obtained from the first response.
  omitted for the first request
- id: request id. this is a sequential number that starts at 1 and
  increments for each successful request
- t: unix timestamp in milliseconds. omitted for the first request
- u: user id. omitted if not logged in. obtained from creating an account
  or recovering account data associated with a service id

order of parameters is important. the server cannot handle them out of
order

there's a number of api's that return your password through an
`authorization_key` field, which is base64-encoded. each one of them will
require you to send a "mask" field in your request. this mask field is
an array of 32 random bytes, encrypted with the game's public key and
encoded as base64. the server then xors your password with these bytes
before sending it to you. to get your actual password, you have to xor this
back with the random bytes you sent. this password is used as your
sessionKey. your password appears to be determined on account creation and
doesn't seem to change, but it can be recovered through fetchGameService
calls provided that you linked a service id to your accout

the public key can be obtained by searching for a string that
starts with `<RSAKeyValue>` in the Il2CppDumper output as with the
startup key. this is a .net xml key string. most other languages will
want it converted to pem format. just take the pem formatted key from
my code, it's probably never gonna change

apis that return your password:

- `/login/startup` . this is where you create your account
- `/dataLink/fetchGameServiceDataBeforeLogin` gets your account data from
  the linked service id
- `/dataLink/fetchGameServiceData` same as above but it's an authenticated
  request signed with your password
- `/dataLink/fetchSchoolIdolFestivalIdDataAfterLogin`
  get accounts associated with this sifid. it returns link data like
  fetchGameServiceData

as soon as you obtain your password, you should change your sessionKey from
the startup key to the password and sign all authenticated requests with it

once you call `/login/login` with your password, you will get yet another
xored `authorization_key` which is temporary for that particular session

the startup key is only used for fetchGameServiceDataBeforeLogin and
startup as far as I know

some api calls have a `device_token` field. this is a firecloud messaging
push notification token, which can be obtained by calling firebase api
with the project number from
`base.apk/assets/google-services-desktop.json`

some api calls have a `asset_state` field. this is an obfuscated string
of bytes generated by libjackpot-core. you can check my code to see how
it's computed. it's not checked at the moment, but it's best to generate
it correctly. the value depends on the first 3 bytes of your random byte
string used in mask, the md5, sha1, sha256 hashes of the package signature,
as well as the md5, sha1, sha256 hashes of libil2cpp.so and
libjackpot-core.so

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
- [x] `/bootstrap/getClearedPlatformAchievement` gets a list of
  achievement id's (probably linked to stuff like the android game hub
  or whatever it's called). empty request
- [x] `/schoolIdolFestivalIdReward/fetch` gets a list of sif id rewards.
  empty request
- [x] `/dataLink/fetchDataLinks` checks whether you have a sifid linked
  as well as whatever gaming platform your phone uses. empty request
- [x] `/dataLink/fetchSchoolIdolFestivalIdDataAfterLogin`
  get accounts associated with this sifid. it returns link data like
  fetchGameServiceData
- [x] `/dataLink/linkSchoolIdolFestivalId` link your sifid. empty request,
  sent after fetchSchoolIdolFestivalIdDataAfterLogin which is probably
  how the server knows what sifid to link

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
