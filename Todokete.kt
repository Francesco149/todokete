// This is free and unencumbered software released into the public domain.
//
// Anyone is free to copy, modify, publish, use, compile, sell, or
// distribute this software, either in source code form or as a compiled
// binary, for any purpose, commercial or non-commercial, and by any
// means.
//
// For more information, please refer to <http://unlicense.org/>

import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.core.subcommands
import com.github.ajalt.clikt.parameters.options.default
import com.github.ajalt.clikt.parameters.options.flag
import com.github.ajalt.clikt.parameters.options.option
import com.github.ajalt.clikt.parameters.options.prompt
import com.github.ajalt.clikt.parameters.types.int
import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.google.gson.JsonParser
import com.google.gson.JsonSyntaxException
import com.google.gson.TypeAdapter
import com.google.gson.TypeAdapterFactory
import com.google.gson.reflect.TypeToken
import com.google.gson.stream.JsonReader
import com.google.gson.stream.JsonToken
import com.google.gson.stream.JsonWriter
import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer
import com.tylerthrailkill.helpers.prettyprint.pp
import java.io.BufferedInputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.FileReader
import java.io.IOException
import java.io.InputStream
import java.io.PrintWriter
import java.io.StringWriter
import java.lang.RuntimeException
import java.lang.Thread
import java.lang.reflect.ParameterizedType
import java.math.BigInteger
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.spec.X509EncodedKeySpec
import java.sql.DriverManager
import java.sql.ResultSet
import java.sql.SQLException
import java.sql.Statement
import java.util.Base64
import java.util.GregorianCalendar
import java.util.UUID
import java.util.concurrent.LinkedBlockingQueue
import java.util.zip.ZipFile
import java.util.zip.ZipInputStream
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.concurrent.thread
import kotlin.random.Random
import kotlin.text.Charsets
import okhttp3.HttpUrl
import okhttp3.MediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.Response
import org.sqlite.SQLiteConfig

// internal globals
// no thread-unsafe stuff here

// "Instances of Base64.Encoder class are safe for use by multiple
// concurrent threads"
// "Instances of Base64.Decoder class are safe for use by multiple
// concurrent threads"
// https://docs.oracle.com/javase/8/docs/api/java/util/Base64.Encoder.html
// https://docs.oracle.com/javase/8/docs/api/java/util/Base64.Decoder.html

val base64Encoder = Base64.getEncoder()
val base64Decoder = Base64.getDecoder()

// as far as I know, OkHttpClient is thread safe
val httpClient = OkHttpClient()

// gson instances are thread safe as far as I know. should be fine to keep
// this global
val gson = GsonBuilder()
  .registerTypeAdapterFactory(JsonMapAdapterFactory())
  .create()

// ------------------------------------------------------------------------
// misc stateless utils and classes

fun randomDelay(ms: Int) =
  Thread.sleep((ms + (-ms / 5..ms / 5).random()).toLong())

fun String.fromBase64() = base64Decoder.decode(this)
fun ByteArray.toBase64() = base64Encoder.encodeToString(this)
fun ByteArray.toHexString() = joinToString("") { "%02x".format(it) }

// xors two ByteArrays together. result is truncated to shortest array
fun ByteArray.xor(other: ByteArray) =
  (zip(other) { a, b -> (a.toInt() xor b.toInt()).toByte() }).toByteArray()

// "aabbccdd" -> arrayOf(0xaa, 0xbb, 0xcc, 0xdd)
fun String.hexStringToByteArray() =
  chunked(2).map { it.toInt(16).toByte() }.toByteArray()

// pretty print json from json string
fun prettyPrint(result: String) {
  val pp = GsonBuilder().setPrettyPrinting().create()
  val array = JsonParser.parseString(result).getAsJsonArray()
  println(pp.toJson(array))
}

private fun <T> sqlTry(f: () -> T): T {
  while (true) {
    try { return f() } catch (e: SQLException) {
      printException(e)
      println("retrying sql...")
      Thread.sleep(1000)
    }
  }
}

fun readOnlyDB(db: String): Statement {
  val config = SQLiteConfig()
  config.setReadOnly(true)
  val conn = DriverManager
    .getConnection("jdbc:sqlite:$db", config.toProperties())
  conn.setAutoCommit(false)
  return conn.createStatement()
}

// generics are a mistake that cause people to come up with useless
// 200iq solutions to problems that don't exist

// sifas json maps are laid out like so: [ key, value, key, value, ... ]
// so we need to override the built in map type adapter
class JsonMapAdapterFactory : TypeAdapterFactory {
  override fun <T> create(gson: Gson, t: TypeToken<T>): TypeAdapter<T>? {
    if (!Map::class.java.isAssignableFrom(t.getRawType())) { return null }
    if (t.getType() !is ParameterizedType) { return null }
    val tk = (t.getType() as ParameterizedType).getActualTypeArguments()[0]
    val tv = (t.getType() as ParameterizedType).getActualTypeArguments()[1]
    val keyAdapter = gson.getAdapter(TypeToken.get(tk))
    val valueAdapter = gson.getAdapter(TypeToken.get(tv))
    @Suppress("UNCHECKED_CAST")
    return Adapter(keyAdapter, valueAdapter) as TypeAdapter<T>
  }

  class Adapter<Tk, Tv>(
    keyAdapter: TypeAdapter<Tk>,
    valueAdapter: TypeAdapter<Tv>
  ) : TypeAdapter<Map<Tk, Tv>>() {
    val keyAdapter = keyAdapter
    val valueAdapter = valueAdapter

    @Throws(IOException::class)
    override fun read(reader: JsonReader): Map<Tk, Tv>? {
      when (reader.peek()) {
        JsonToken.NULL -> {
          reader.nextNull()
          return null
        }
        JsonToken.BEGIN_ARRAY -> {
          val res = HashMap<Tk, Tv>()
          reader.beginArray()
          while (reader.hasNext()) {
            val key = keyAdapter.read(reader)
            val value = valueAdapter.read(reader)
            if (res.put(key, value) != null) {
              throw JsonSyntaxException("duplicate key: $key")
            }
          }
          reader.endArray()
          return res
        }
        else -> throw JsonSyntaxException("expected array for json map")
      }
    }

    @Throws(IOException::class)
    override fun write(writer: JsonWriter, value: Map<Tk, Tv>?) {
      if (value == null) {
        writer.nullValue()
        return
      }
      writer.beginArray()
      value.map {
        keyAdapter.write(writer, it.key)
        valueAdapter.write(writer, it.value)
      }
      writer.endArray()
    }
  }
}

// ------------------------------------------------------------------------

data class AllStarsConfig(
  // used by the autoupdater to check the config against the apk
  var apkHash: String = "",

  // first StringLiteral in  ServerConfig$$.cctor
  var ServerEndpoint: String =
  "https://jp-real-prod-v4tadlicuqeeumke.api.game25.klabgames.net/ep1016",

  // second StringLiteral in  ServerConfig$$.cctor
  var StartupKey: String = "I6ow2cY1c2wWXJP7",

  // found in DMCryptography$$CreateRSAProvider . must be converted from
  // xml to pem using a tool like
  // https://gist.github.com/Francesco149/8c6288a853dd010a638892be2a2c48af
  var RSAPublicKey: String = """-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC/ZUSWq8LCuF2JclEp6uuW9+yddLQvb2420+F8
rxIF8+W53BiF8g9m6nCETdRw7RVnzNABevMndCCTD6oQ6a2w0QpoKeT26578UCWtGp74NGg2Q2fH
YFMAhTytVk48qO4ViCN3snFs0AURU06niM98MIcEUnj9vj6kOBlOGv4JWQIDAQAB
-----END PUBLIC KEY-----""",

  var PackageName: String = "com.klab.lovelive.allstars",

  // md5, sha1, sha256 of the package's certificate in hexstring form
  // obtained by running https://github.com/warren-bank/print-apk-signature
  // on the split apk
  var PackageSignatures: List<String> = listOf(
    "3f45f90cbcc718e4b63462baeae90c86",
    "1be2103a6929b38798a29d89044892f3b3934184",
    "1d32dbcf91697d46594ad689d49bb137f65d4bb8f56a26724ae7008648131b82"
  ),

  // md5, sha1, sha256 of libjackpot-core.so in binary form
  var JackpotSignatures: List<ByteArray> = arrayOf(
    "567617087e0ea8f7bffbc6b48f494438",
    "d307fabb4a1020e15793f928b67f0ef0a3543c67",
    "e7ebed91664a9d86ca57a26ea249f9413cca5d4c832bf4d3c6d5f500fd686ea6"
  ).map { it.hexStringToByteArray() },

  // md5, sha1, sha256 of libil2cpp.so in binary form
  var Il2CppSignatures: List<ByteArray> = arrayOf(
    "4fc6bb13ee3655fcdbda08dd0114bafe",
    "b8c29a7b82065a8efaff2a6c669055e4728abefe",
    "9056823687cd2d2046ff7ae7100f31ae3db0f76ca895113feccb220290085346"
  ).map { it.hexStringToByteArray() }
)

class AllStarsClient(
  val config: AllStarsConfig = AllStarsConfig(),
  // these only need to be set if you're making a new account
  var deviceName: String = "To be filled by O.E.M. To be filled by O.E.M.",
  val nickname: String = "",
  val name: String = "",
  var deviceToken: String = "", // fcm push notification token
  var serviceId: String = "" // ideally unique for each account
) {

// ------------------------------------------------------------------------
// crypto and other internal utils

val kf = KeyFactory.getInstance("RSA")
val keyBytes = Base64.getDecoder().decode(
  config.RSAPublicKey
    .replace("-----BEGIN PUBLIC KEY-----", "")
    .replace("-----END PUBLIC KEY-----", "")
    .replace("\\s+".toRegex(), "")
)
val keySpecX509 = X509EncodedKeySpec(keyBytes)
val pubKey = kf.generatePublic(keySpecX509)

fun md5(str: String): String {
  val digest = MessageDigest.getInstance("MD5")
  digest.reset()
  digest.update(str.toByteArray())
  val hash = digest.digest()
  return BigInteger(1, hash).toString(16).padStart(32, '0')
}

fun publicEncrypt(data: ByteArray): ByteArray {
  val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding")
  cipher.init(Cipher.ENCRYPT_MODE, pubKey)
  return cipher.doFinal(data)
}

fun hmacSha1(key: ByteArray, data: ByteArray): String {
  val hmacKey = SecretKeySpec(key, "HmacSHA1")
  val hmac = Mac.getInstance("HmacSHA1")
  hmac.init(hmacKey)
  return hmac.doFinal(data).toHexString()
}

// ------------------------------------------------------------------------
// state

var userId: Int = 0 // obtained after startup, or known before login
var requestId = 0 // incremented after every successful request
var temporarySessionKey: ByteArray? = null
var sessionKey = config.StartupKey.toByteArray()
var randomBytes = Random.nextBytes(32) // regenerated on login/startup
var flags = 0 // used in call()
var masterVersion: String? = null // obtained after the first request
var lastRequestTime: Long = 0
var userModel: UserModel? = null // TODO: keep this properly updated
var authCount: Int = 0
var sifidMail: String? = null
var sifidPassword: String? = null

// ------------------------------------------------------------------------
// http client

// used in flags
val WithMasterVersion = 1 shl 1
val WithTime = 1 shl 2
val PrintHeaders = 1 shl 3

fun call(path: String, payload: String, retries: Int = 20): String {
  repeat(retries) {
    try {
      return callNoRetry(path, payload)
    } catch (e: Exception) {
      printException(e)
      println("retrying http...")
      Thread.sleep(2000)
    }
  }
  return callNoRetry(path, payload)
}

fun callNoRetry(path: String, payload: String): String {
  lastRequestTime = System.currentTimeMillis()
  val nextRequestId = requestId + 1
  var pathWithQuery = path + "?p=a"
  if ((flags and WithMasterVersion) != 0) {
    pathWithQuery += "&mv=" + masterVersion!!
  }
  pathWithQuery += "&id=$nextRequestId"
  if (userId != 0) {
    pathWithQuery += "&u=$userId"
  }
  if ((flags and WithTime) != 0) {
    pathWithQuery += "&t=$lastRequestTime"
  }
  println("-> POST $pathWithQuery")
  val hashData = pathWithQuery + " " + payload
  val key =
    if (temporarySessionKey != null) temporarySessionKey
    else sessionKey
  val hash = hmacSha1(key!!, hashData.toByteArray())
  val json = """[$payload,"$hash"]"""
  println("-> $json")
  val JSON = MediaType.parse("application/json")
  val request = Request.Builder()
    .url("${config.ServerEndpoint}$pathWithQuery")
    .post(RequestBody.create(JSON, json.toByteArray()))
    .build()
  val response = httpClient.newCall(request).execute()
  if (!response.isSuccessful) {
    throw RuntimeException("unexpected code $response")
  }
  if ((flags and PrintHeaders) != 0) {
    val headers = response.headers()
    for (i in 0..headers.size() - 1) {
      val name = headers.name(i)
      val value = headers.value(i)
      println("$name: $value")
    }
  }
  val s = response.body()!!.string()
  prettyPrint(s)
  requestId += 1
  return s
}

// TODO: handle mainteinance
// example maint response
// code = 503 service unavailable
// json = {"message_ja":"「ラブライブ！スクールアイドルフェスティバル ALL
// STARS」は\n現在メンテナンス中です。\nメンテナンス中はゲームをプレイする
// ことはできません。\n\n【メンテナンス時間】\n<color value=\"#ffa800\">20
// 19年10月29日 0:00 ~ 2019年10月29日 8:00予定</color>\n\n<color value=\"
// #ffa800\">特訓のマスの調整と、その補填について準備を進めております。\n状
// 況によってメンテナンス終了が前後する可能性もあります\n予めご了承ください
// 。</color>\n\nお客様にはご不便をお掛けし誠に申し訳ありませんが、\n何卒
// ご協力をお願いいたします。","url_ja":"https://lovelive-as.bushimo.jp/"}
//
// seems like it can also give 410 Gone where body is just "Gone". I think
// this happens when klab moves to a new /epxxxx version

inline fun <reified T> parseResponse(result: String): T? {
  // TODO: consider moving everything except gson call to call() for
  // smaller code output
  val array = JsonParser.parseString(result).getAsJsonArray()
  array[0].getAsInt().let { flags = flags or WithTime }
  array[1].getAsString()?.let {
    masterVersion = it
    flags = flags or WithMasterVersion
  }
  ?: run { throw JsonSyntaxException("couldn't parse MasterVersion") }
  array[3].getAsJsonObject()?.let {
    return gson.fromJson(it, T::class.java).pp()
  }
  return null
}

// ------------------------------------------------------------------------
// api

fun generateMask(): String {
  randomBytes = Random.nextBytes(32)
  return publicEncrypt(randomBytes).toBase64()
}

data class FetchGameServiceDataBeforeLoginRequest(
  val user_id: Int,
  val service_id: String,
  val mask: String
)

data class UserLinkData(
  val user_id: Int,
  val authorization_key: String,
  val name: LocalizedText,
  val last_login_at: Long,
  val sns_coin: Int,
  val terms_of_use_version: Int,
  var service_user_common_key: ByteArray
)

data class CurrentUserData(
  val user_id: Int,
  val name: LocalizedText,
  val last_login_at: Long,
  val sns_coin: Int
)

data class UserLinkDataBeforeLogin(
  val linked_data: UserLinkData,
  val current_data: CurrentUserData
)

data class FetchGameServiceDataBeforeLoginResponse(
  val data: UserLinkDataBeforeLogin?
)

fun fetchGameServiceDataBeforeLogin(
  user_id: Int = -1
): FetchGameServiceDataBeforeLoginResponse? {
  val result = call(
    path = "/dataLink/fetchGameServiceDataBeforeLogin",
    payload = gson.toJson(FetchGameServiceDataBeforeLoginRequest(
      user_id = user_id,
      service_id = serviceId,
      mask = generateMask()
    ))
  )
  val res: FetchGameServiceDataBeforeLoginResponse? = parseResponse(result)
  res?.data?.linked_data?.let {
    it.service_user_common_key =
      it.authorization_key.fromBase64().xor(randomBytes)
  }
  return res
}

data class StartupRequest(
  val mask: String,
  val resemara_detection_identifier: String,
  val time_difference: Int
)

data class StartupResponse(
  val user_id: Int,
  val authorization_key: String
)

fun startup(): StartupResponse? {
  val advertisingId = UUID.randomUUID().toString()
  val resemara = md5(advertisingId + config.PackageName)
  val timeZone = GregorianCalendar().getTimeZone()
  val offset = timeZone.getRawOffset() / 1000
  val result = call(
    path = "/login/startup",
    payload = gson.toJson(StartupRequest(
      mask = generateMask(),
      resemara_detection_identifier = resemara,
      time_difference = offset
    ))
  )
  val resp: StartupResponse? = parseResponse(result)
  resp?.let { userId = it.user_id }
  return resp
}

data class LoginRequest(
  val user_id: Int,
  val auth_count: Int,
  val mask: String,
  val asset_state: String
)

data class LocalizedText(val dot_under_text: String) {
  override fun toString(): String = dot_under_text
}

data class UserStatus(
  val name: LocalizedText,
  val nickname: LocalizedText,
  val last_login_at: Long,
  val rank: Int,
  val exp: Int,
  val message: LocalizedText,
  val recommend_card_master_id: Int,
  val max_friend_num: Int,
  val live_point_full_at: Long,
  val live_point_broken: Int,
  val activity_point_count: Int,
  val activity_point_reset_at: Long,
  val activity_point_payment_recovery_daily_count: Int,
  val activity_point_payment_recovery_daily_reset_at: Long,
  val game_money: Int,
  val card_exp: Int,
  val free_sns_coin: Int,
  val apple_sns_coin: Int,
  val google_sns_coin: Int,
  val birth_date: Int?,
  val birth_month: Int?,
  val birth_day: Int?,
  val latest_live_deck_id: Int,
  val main_lesson_deck_id: Int,
  val favorite_member_id: Int,
  val last_live_difficulty_id: Int,
  val lp_magnification: Int,
  val emblem_id: Int,
  val device_token: String,
  val tutorial_phase: Int,
  val tutorial_end_at: Long,
  val login_days: Int,
  val navi_tap_count: Int,
  val navi_tap_recover_at: Long,
  val is_auto_mode: Boolean,
  val max_score_live_difficulty_master_id: Int?,
  val live_max_score: Int,
  val max_combo_live_difficulty_master_id: Int?,
  val live_max_combo: Int,
  val lesson_resume_status: Int,
  val accessory_box_additional: Int,
  val terms_of_use_version: Int,
  val bootstrap_sifid_check_at: Long
)

data class UserMember(
  val member_master_id: Int,
  val custom_background_master_id: Int,
  val suit_master_id: Int,
  val love_point: Int,
  val love_point_limit: Int,
  val love_level: Int,
  val view_status: Int,
  val is_new: Boolean
)

data class UserCard(
  val card_master_id: Int,
  val level: Int,
  val exp: Int,
  val love_point: Int,
  val is_favorite: Boolean,
  val is_awakening: Boolean,
  val is_awakening_image: Boolean,
  val is_all_training_activated: Boolean,
  val max_free_passive_skill: Int,
  val grade: Int,
  val training_life: Int,
  val training_attack: Int,
  val training_dexterity: Int,
  val active_skill_level: Int,
  val passive_skill_a_level: Int,
  val passive_skill_b_level: Int,
  val passive_skill_c_level: Int,
  val additional_passive_skill_1_id: Int,
  val additional_passive_skill_2_id: Int,
  val additional_passive_skill_3_id: Int,
  val additional_passive_skill_4_id: Int,
  val acquired_at: Long,
  val is_new: Boolean
)

data class UserSuit(
  val suit_master_id: Int,
  val is_new: Boolean
)

data class UserLiveDeck(
  val user_live_deck_id: Int,
  val name: LocalizedText,
  val card_master_id_1: Int?,
  val card_master_id_2: Int?,
  val card_master_id_3: Int?,
  val card_master_id_4: Int?,
  val card_master_id_5: Int?,
  val card_master_id_6: Int?,
  val card_master_id_7: Int?,
  val card_master_id_8: Int?,
  val card_master_id_9: Int?,
  val suit_master_id_1: Int?,
  val suit_master_id_2: Int?,
  val suit_master_id_3: Int?,
  val suit_master_id_4: Int?,
  val suit_master_id_5: Int?,
  val suit_master_id_6: Int?,
  val suit_master_id_7: Int?,
  val suit_master_id_8: Int?,
  val suit_master_id_9: Int?
)

data class UserLiveParty(
  val party_id: Int,
  val user_live_deck_id: Int,
  val name: LocalizedText,
  val icon_master_id: Int,
  val card_master_id_1: Int?,
  val card_master_id_2: Int?,
  val card_master_id_3: Int?
)

data class UserLessonDeck(
  val user_lesson_deck_id: Int,
  val name: String,
  val card_master_id_1: Int?,
  val card_master_id_2: Int?,
  val card_master_id_3: Int?,
  val card_master_id_4: Int?,
  val card_master_id_5: Int?,
  val card_master_id_6: Int?,
  val card_master_id_7: Int?,
  val card_master_id_8: Int?,
  val card_master_id_9: Int?
)

data class UserLiveMvDeck(
  val live_master_id: Int,
  val member_master_id_1: Int?,
  val member_master_id_2: Int?,
  val member_master_id_3: Int?,
  val member_master_id_4: Int?,
  val member_master_id_5: Int?,
  val member_master_id_6: Int?,
  val member_master_id_7: Int?,
  val member_master_id_8: Int?,
  val member_master_id_9: Int?,
  val suit_master_id_1: Int?,
  val suit_master_id_2: Int?,
  val suit_master_id_3: Int?,
  val suit_master_id_4: Int?,
  val suit_master_id_5: Int?,
  val suit_master_id_6: Int?,
  val suit_master_id_7: Int?,
  val suit_master_id_8: Int?,
  val suit_master_id_9: Int?
)

data class UserLiveDifficulty(
  val live_difficulty_id: Int,
  val max_score: Int,
  val max_combo: Int,
  val play_count: Int,
  val clear_count: Int,
  val cancel_count: Int,
  val not_cleared_count: Int,
  val is_full_combo: Boolean,
  val cleared_difficulty_achievement_1: Int?,
  val cleared_difficulty_achievement_2: Int?,
  val cleared_difficulty_achievement_3: Int?,
  val enable_autoplay: Boolean,
  val is_autoplay: Boolean,
  val is_new: Boolean
)

data class UserStoryMain(val story_main_master_id: Int)

data class UserStoryMainSelected(
  val story_main_cell_id: Int,
  val selected_id: Int
)

data class UserVoice(
  val navi_voice_master_id: String,
  val is_new: Boolean
)

data class UserEmblem(
  val emblem_m_id: String,
  val is_new: Boolean,
  val emblem_param: String,
  val acquired_at: Long
)

data class UserGachaTicket(
  val ticket_master_id: Int,
  val normal_amount: Int,
  val apple_amount: Int,
  val google_amount: Int
)

data class UserGachaPoint(
  val point_master_id: Int,
  val amount: Int
)

data class UserLessonEnhancingItem(
  val enhancing_item_id: Int,
  val amount: Int
)

data class UserTrainingMaterial(
  val training_material_master_id: Int,
  val amount: Int
)

data class UserGradeUpItem(
  val item_master_id: Int,
  val amount: Int
)

data class UserCustomBackground(
  val custom_background_master_id: Int,
  val is_new: Boolean
)

data class UserStorySide(
  val story_side_master_id: Int,
  val is_new: Boolean,
  val acquired_at: Long
)

data class UserStoryMember(
  val story_member_master_id: Int,
  val is_new: Boolean,
  val acquired_at: Long
)

data class UserRecoveryLp(
  val recovery_lp_master_id: Int,
  val amount: Int
)

data class UserRecoveryAp(
  val recovery_ap_master_id: Int,
  val amount: Int
)

data class UserMission(
  val mission_m_id: Int,
  val is_new: Boolean,
  val mission_count: Int,
  val is_cleared: Boolean,
  val is_received_reward: Boolean,
  val new_expired_at: Long
)

data class UserDailyMission(
  val mission_m_id: Int,
  val is_new: Boolean,
  val mission_start_count: Int,
  val mission_count: Int,
  val is_cleared: Boolean,
  val is_received_reward: Boolean,
  val cleared_expired_at: Long
)

data class UserWeeklyMission(
  val mission_m_id: Int,
  val is_new: Boolean,
  val mission_start_count: Int,
  val mission_count: Int,
  val is_cleared: Boolean,
  val is_received_reward: Boolean,
  val cleared_expired_at: Long,
  val new_expired_at: Long
)

data class UserInfoTriggerBasic(
  val trigger_id: Int,
  val info_trigger_type: Int,
  val limit_at: Long,
  val description: String,
  val param_int: Int?
)

data class UserInfoTriggerCardGradeUp(
  val trigger_id: Int,
  val card_master_id: Int,
  val before_love_level_limit: Int,
  val after_love_level_limit: Int
)

data class UserInfoTriggerMemberLoveLevelUp(
  val trigger_id: Int,
  val member_master_id: Int,
  val before_love_level: Int
)

data class UserAccessory(
  val user_accessory_id: Int,
  val accessory_master_id: Int,
  val level: Int,
  val exp: Int,
  val grade: Int,
  val attribute: Int,
  val passive_skill_1_id: Int?,
  val passive_skill_1_level: Int?,
  val passive_skill_2_id: Int?,
  val passive_skill_2_level: Int?,
  val is_lock: Boolean,
  val is_new: Boolean,
  val acquired_at: Long
)

data class UserAccessoryLevelUpItem(
  val accessory_level_up_item_master_id: Int,
  val amount: Int
)

data class UserAccessoryRarityUpItem(
  val accessory_rarity_up_item_master_id: Int,
  val amount: Int
)

data class UserUnlockScene(
  val unlock_scene_type: Int,
  val status: Int
)

data class UserSceneTips(val scene_tips_type: Int)
data class UserRuleDescription(val display_status: Int)
data class UserExchangeEventPoint(val amount: Int)

data class UserSchoolIdolFestivalIdRewardMission(
  val school_idol_festival_id_reward_mission_master_id: Int,
  val is_cleared: Boolean,
  val is_new: Boolean,
  val count: Int
)

data class UserGpsPresentReceived(val campaign_id: Int)
data class UserEventMarathon(
  val event_master_id: Int,
  val event_point: Int,
  val opened_story_number: Int,
  val read_story_number: Int
)

data class UserLiveSkipTicket(
  val ticket_master_id: Int,
  val amount: Int
)

data class UserEventMarathonBooster(
  val event_item_id: Int,
  val amount: Int
)

data class UserReferenceBook(val reference_book_id: Int)

data class UserReviewRequestProcessFlow(
  val review_request_trigger_type: Int,
  val review_request_status_type: Int
)

data class UserModel(
  val user_status: UserStatus,
  val user_member_by_member_id: Map<Int, UserMember>,
  val user_card_by_card_id: Map<Int, UserCard>,
  val user_suit_by_suit_id: Map<Int, UserSuit>,
  var user_live_deck_by_id: Map<Int, UserLiveDeck>,
  var user_live_party_by_id: Map<Int, UserLiveParty>,
  val user_lesson_deck_by_id: Map<Int, UserLessonDeck>,
  val user_live_mv_deck_by_id: Map<Int, UserLiveMvDeck>,
  val user_live_difficulty_by_difficulty_id: Map<Int, UserLiveDifficulty>,
  val user_story_main_by_story_main_id: Map<Int, UserStoryMain>,
  val user_story_main_selected_by_story_main_cell_id:
    Map<Int, UserStoryMainSelected>,
  val user_voice_by_voice_id: Map<Int, UserVoice>,
  val user_emblem_by_emblem_id: Map<Int, UserEmblem>,
  val user_gacha_ticket_by_ticket_id: Map<Int, UserGachaTicket>,
  val user_gacha_point_by_point_id: Map<Int, UserGachaPoint>,
  val user_lesson_enhancing_item_by_item_id:
    Map<Int, UserLessonEnhancingItem>,
  val user_training_material_by_item_id: Map<Int, UserTrainingMaterial>,
  val user_grade_up_item_by_item_id: Map<Int, UserGradeUpItem>,
  val user_custom_background_by_id: Map<Int, UserCustomBackground>,
  val user_story_side_by_id: Map<Int, UserStorySide>,
  val user_story_member_by_id: Map<Int, UserStoryMember>,
  val user_recovery_lp_by_id: Map<Int, UserRecoveryLp>,
  val user_recovery_ap_by_id: Map<Int, UserRecoveryAp>,
  val user_mission_by_mission_id: Map<Int, UserMission>,
  val user_daily_mission_by_mission_id: Map<Int, UserDailyMission>,
  val user_weekly_mission_by_mission_id: Map<Int, UserWeeklyMission>,
  val user_info_trigger_basic_by_trigger_id:
    Map<Int, UserInfoTriggerBasic>,
  val user_info_trigger_card_grade_up_by_trigger_id:
    Map<Int, UserInfoTriggerCardGradeUp>,
  val user_info_trigger_member_love_level_up_by_trigger_id:
    Map<Int, UserInfoTriggerMemberLoveLevelUp>,
  val user_accessory_by_user_accessory_id: Map<Int, UserAccessory>,
  val user_accessory_level_up_item_by_id:
    Map<Int, UserAccessoryLevelUpItem>,
  val user_accessory_rarity_up_item_by_id:
    Map<Int, UserAccessoryRarityUpItem>,
  val user_unlock_scenes_by_enum: Map<Int, UserUnlockScene>,
  val user_scene_tips_by_enum: Map<Int, UserSceneTips>,
  val user_rule_description_by_id: Map<Int, UserRuleDescription>,
  val user_exchange_event_point_by_id: Map<Int, UserExchangeEventPoint>,
  val user_school_idol_festival_id_reward_mission_by_id:
    Map<Int, UserSchoolIdolFestivalIdRewardMission>,
  val user_gps_present_received_by_id: Map<Int, UserGpsPresentReceived>,
  val user_event_marathon_by_event_master_id: Map<Int, UserEventMarathon>,
  val user_live_skip_ticket_by_id: Map<Int, UserLiveSkipTicket>,
  val user_event_marathon_booster_by_id:
    Map<Int, UserEventMarathonBooster>,
  val user_reference_book_by_id: Map<Int, UserReferenceBook>,
  val user_review_request_process_flow_by_id:
    Map<Int, UserReviewRequestProcessFlow>
)

data class LiveResume(
  val live_difficulty_id: Int,
  val deck_id: Int
)

data class LoginResponse(
  // this field is actually for InvalidAuthCountResponse
  // but theres no easy way to fall back to a different type so i just make
  // fields for both optional and check for null
  val authorization_count: Int?,
  val session_key: String,
  val user_model: UserModel?,
  val is_platform_service_linked: Boolean,
  val last_timestamp: Int,
  val cautions: List<Int>, // TODO: not sure
  val show_home_caution: Boolean,
  val live_resume: Map<String, LiveResume> // TODO; not sure
)

fun assetStateLogGenerateV2(): String {
  val randomBytes64 = randomBytes.toBase64()
  val libHashChar = (randomBytes64[0].toInt() and 1) + 1
  val libHashType = randomBytes64[libHashChar].toInt().rem(3)
  val pkgHashChar = 2 - (randomBytes64[0].toInt() and 1)
  val pkgHashType = randomBytes64[pkgHashChar].toInt().rem(3)
  val xoredHashes =
    config.JackpotSignatures[libHashType]
    .xor(config.Il2CppSignatures[libHashType])
    .toHexString()
  val packageSignature = config.PackageSignatures[pkgHashType]
  val signatures = when (randomBytes64[0].toInt() and 1) {
    0 -> "$xoredHashes-$packageSignature"
    1 -> "$packageSignature-$xoredHashes"
    else -> "$xoredHashes-$packageSignature"
  }
  var xorkey =
    (randomBytes64[0].toByte().toUInt() or
    (randomBytes64[1].toByte().toUInt() shl 8) or
    (randomBytes64[2].toByte().toUInt() shl 16) or
    (randomBytes64[3].toByte().toUInt() shl 24)) xor 0x12d8af36u
  var a = 0u
  var b = 0u
  var c = 0x2bd57287u
  var d = 0u
  var e = 0x202c9ea2u
  var f = 0u
  var g = 0x139da385u
  var h = 0u
  var i = 0u
  var j = 0u
  var k = 0u
  repeat(10) {
    h = g
    i = f
    j = e
    k = d
    g = c
    f = b
    a = ((a shl 11) or (xorkey shr 21)) xor a
    xorkey = (xorkey shl 11) xor xorkey
    c = ((g shr 19) or (k shl 13)) xor xorkey xor g
    c = c xor ((xorkey shr 8) or (a shl 24))
    d = (k shr 19) xor a xor k xor (a shr 8)
    xorkey = j
    a = i
    b = k
    e = h
  }
  val xorBytes = ByteArray(signatures.length)
  for (index in 0..signatures.length - 1) {
    a = g
    xorkey = f
    b = ((i shl 11) or (j shr 21)) xor i
    j = (j shl 11) xor j
    e = ((c shr 19) or (d shl 13)) xor j
    e = e xor c xor ((j shr 8) or (b shl 24))
    xorBytes[index] = e.toByte()
    f = k
    g = c
    k = d
    j = h
    i = xorkey
    c = e
    d = (d shr 19) xor b xor d xor (b shr 8)
    h = a
  }
  return signatures.toByteArray().xor(xorBytes).toBase64()
}

fun login(retries: Int = 20): LoginResponse? {
  val result = call(
    retries = retries,
    path = "/login/login",
    payload = gson.toJson(LoginRequest(
      user_id = userId,
      auth_count = authCount + 1,
      mask = generateMask(),
      asset_state = assetStateLogGenerateV2()
    ))
  )
  return parseResponse(result)
}

data class TermsAgreementRequest(val terms_version: Int)
data class UserModelResponse(val user_model: UserModel)

fun termsAgreement(termsVersion: Int): UserModelResponse? {
  val result = call(
    path = "/terms/agreement",
    payload = gson.toJson(TermsAgreementRequest(
      terms_version = termsVersion
    ))
  )
  return parseResponse(result)
}

data class SetUserProfileRequest(
  val name: String?,
  val nickname: String?,
  val message: String?,
  val device_token: String? // firebase push notification token
)

fun setUserProfile(
  name: String? = null,
  nickname: String? = null,
  message: String? = null
): UserModelResponse? {
  val result = call(
    path = "/userProfile/setProfile",
    payload = gson.toJson(SetUserProfileRequest(
      name = name,
      nickname = nickname,
      message = message,
      device_token = deviceToken
    ))
  )
  return parseResponse(result)
}

data class SetUserProfileBirthDayRequest(
  val month: Int,
  val day: Int
)

fun setUserProfileBirthDay(
  month: Int = Random.nextInt(1, 13),
  day: Int = Random.nextInt(1, 29)
): UserModelResponse? {
  var result = call(
    path = "/userProfile/setProfileBirthday",
    payload = gson.toJson(SetUserProfileBirthDayRequest(
      month = month,
      day = day
    ))
  )
  return parseResponse(result)
}

data class StoryMainRequest(
  val cell_id: Int,
  val is_auto_mode: Boolean,
  val member_id: Int?
)

data class Content(
  val content_type: Int,
  val content_id: Int,
  val content_amount: Int
)

data class StoryMainResponse(
  val user_model_diff: UserModel,
  val first_clear_reward: List<Content>
)

fun finishUserStoryMain(
  cellId: Int,
  isAutoMode: Boolean = false,
  memberId: Int? = null
): StoryMainResponse? {
  var result = call(
    path = "/story/finishUserStoryMain",
    payload = gson.toJson(
      StoryMainRequest(
        cell_id = cellId,
        is_auto_mode = isAutoMode,
        member_id = memberId
    ))
  )
  return parseResponse(result)
}

data class LiveEventMarathonStatus(
  val event_id: Int,
  val is_use_event_marathon_booster: Boolean
)

data class StartLiveRequest(
  val live_difficulty_id: Int,
  val deck_id: Int,
  val cell_id: Int?,
  val partner_user_id: Int,
  val partner_card_master_id: Int,
  val lp_magnification: Int,
  val is_auto_play: Boolean,
  val live_event_marathon_status: LiveEventMarathonStatus?
)

data class LiveNoteSetting(
  val id: Int,
  val call_time: Int,
  val note_type: Int,
  val note_position: Int,
  val gimmick_id: Int,
  val note_action: Int,
  val wave_id: Int,
  val note_random_drop_color: Int,
  val auto_judge_type: Int
)

data class LiveWaveSetting(
  val id: Int,
  val wave_damage: Int,
  val mission_type: Int,
  val arg_1: Int,
  val arg_2: Int,
  val reward_voltage: Int
)

data class NoteGimmick(
  val uniq_id: Int,
  val id: Int,
  val note_gimmick_type: Int,
  val arg_1: Int,
  val arg_2: Int,
  val effect_m_id: Int,
  val icon_type: Int
)

data class LiveStageGimmick(
  val gimmick_master_id: Int,
  val condition_master_id_1: Int,
  val condition_master_id_2: Int?,
  val skill_master_id: Int,
  val uniq_id: Int
)

data class LiveStage(
  val live_difficulty_id: Int,
  val live_notes: List<LiveNoteSetting>,
  val live_wave_settings: List<LiveWaveSetting>,
  val note_gimmicks: List<NoteGimmick>,
  val stage_gimmick_dict: Map<Int, List<LiveStageGimmick>>
)

data class OtherUserCard(
  val card_master_id: Int,
  val level: Int,
  val grade: Int,
  val love_level: Int,
  val is_awakening: Boolean,
  val is_awakening_image: Boolean,
  val is_all_training_activated: Boolean,
  val active_skill_level: Int,
  val passive_skill_levels: List<Int>,
  val additional_passive_skill_ids: List<Int>,
  val max_free_passive_skill: Int,
  val training_stamina: Int,
  val training_appeal: Int,
  val training_technique: Int
)

data class Live(
  val live_id: Long,
  val live_type: Int,
  val deck_id: Int,
  val live_stage: LiveStage,
  val live_partner_card: OtherUserCard,
  val is_partner_friend: Boolean,
  val cell_id: Int
)

data class StartLiveResponse(
  val live: Live,
  val user_model_diff: UserModel
)

fun startLive(
  liveDifficultyId: Int,
  deckId: Int,
  cellId: Int,
  partnerUserId: Int = 0,
  partnerCardMasterId: Int = 0,
  lpMagnification: Int = 1,
  isAutoPlay: Boolean = false,
  liveEventMarathonStatus: LiveEventMarathonStatus? = null
): StartLiveResponse? {
  val response = call(
    path = "/live/start",
    payload = gson.toJson(StartLiveRequest(
      live_difficulty_id = liveDifficultyId,
      deck_id = deckId,
      cell_id = cellId,
      partner_user_id = partnerUserId,
      partner_card_master_id = partnerCardMasterId,
      lp_magnification = lpMagnification,
      is_auto_play = isAutoPlay,
      live_event_marathon_status = liveEventMarathonStatus
    ))
  )
  return parseResponse(response)
}

data class SaveRuleDescriptionRequest(
  val rule_description_master_ids: List<Int>
)

fun saveRuleDescription(ids: List<Int>): UserModelResponse? {
  val response = call(
    path = "/ruleDescription/saveRuleDescription",
    payload = gson.toJson(SaveRuleDescriptionRequest(
      rule_description_master_ids = ids
    ))
  )
  return parseResponse(response)
}

data class LiveNoteScore(
  val judge_type: Int = 1,
  val voltage: Int = 0,
  val card_master_id: Int = 0
)

data class LiveTurnStat(
  val note_id: Int = 0,
  val current_life: Int = 0,
  val current_voltage: Int = 0,
  val appended_shield: Int = 0,
  val healed_life: Int = 0,
  val healed_life_percent: Int = 0,
  val stamina_damage: Int = 0
)

data class LiveCardStat(
  val got_voltage: Int = 0,
  val skill_triggered_count: Int = 0,
  val appeal_count: Int = 0,
  val recast_squad_effect_count: Int = 0,
  val card_master_id: Int
)

data class LiveScore(
  val result_dict: Map<Int, LiveNoteScore>,
  val wave_stat: Map<Int, Boolean>,
  val turn_stat_dict: Map<Int, LiveTurnStat>, // by note id
  val card_stat_dict: Map<Int, LiveCardStat>, // by card_master_id
  val target_score: Int,
  val current_score: Int = 0,
  val combo_count: Int = 0,
  val change_squad_count: Int = 0,
  val highest_combo_count: Int = 0,
  val remaining_stamina: Int,
  val is_perfect_live: Boolean = true,
  val is_perfect_full_combo: Boolean = true,
  val use_voltage_active_skill_count: Int = 0,
  val use_heal_active_skill_count: Int = 0,
  val use_debuf_active_skill_count: Int = 0,
  val use_buf_active_skill_count: Int = 0,
  val use_sp_skill_count: Int = 0,
  val live_power: Int
)

data class ResumeFinishInfo(
  val cached_judge_result: List<Int> = emptyList() // TODO: unsure
)

data class FinishLiveRequest(
  val live_id: Long,
  val live_finish_status: Int = 1,
  val live_score: LiveScore,
  val resume_finish_info: ResumeFinishInfo = ResumeFinishInfo()
)

data class LiveDropContent(
  val drop_color: Int,
  val content: Content,
  val is_rare: Boolean
)

data class LiveResultMemberLoveStatus(val reward_love_point: Int)

data class LiveResultAchievement(
  val position: Int,
  val is_already_achieved: Boolean,
  val is_currently_achieved: Boolean
)

data class LiveResultMvp(
  val card_master_id: Int,
  val get_voltage: Int,
  val skill_triggered_count: Int,
  val appeal_count: Int
)

data class OtherUser(
  val user_id: Int,
  val name: LocalizedText,
  val rank: Int,
  val last_played_at: Int,
  val recommend_card_master_id: Int,
  val recommend_card_level: Int,
  val is_recommend_card_image_awaken: Boolean,
  val is_recommend_card_all_training_activated: Boolean,
  val emblem_id: Int,
  val is_new: Boolean,
  val introduction_message: LocalizedText,
  val friend_approved_at: Long,
  val request_status: Int,
  val is_request_pending: Boolean
)

data class LiveResult(
  val live_difficulty_master_id: Long,
  val live_deck_id: Int,
  val standard_drops: List<LiveDropContent>,
  val additional_drops: List<LiveDropContent>,
  val gimmick_drops: List<LiveDropContent>,
  val member_love_statuses: Map<Int, LiveResultMemberLoveStatus>,
  val mvp: LiveResultMvp,
  val partner: OtherUser,
  val live_result_achievements: Map<Int, LiveResultAchievement>
)

data class FinishLiveResponse(
  val live_result: LiveResult,
  val user_model_diff: UserModel
)

fun skipLive(
  live: Live,
  power: Int,
  stamina: Int,
  targetScore: Int
): FinishLiveResponse? {
  val notes = live.live_stage.live_notes
  val liveWaveSetting = live.live_stage.live_wave_settings
  var turnStatDict = notes.map({ it.id to LiveTurnStat() })
    .toMap().toMutableMap()
  turnStatDict[1] = LiveTurnStat(current_life = stamina)
  turnStatDict[0] = LiveTurnStat(current_life = stamina)
  turnStatDict[notes.size + 1] = LiveTurnStat()
  val deck = userModel!!.user_live_deck_by_id[live.deck_id]!!
  val response = call(
    path = "/live/finish",
    payload = gson.toJson(FinishLiveRequest(
      live_id = live.live_id,
      live_score = LiveScore(
        result_dict = notes.map({ it.id to LiveNoteScore() }).toMap(),
        wave_stat = liveWaveSetting.map({ it.id to false }).toMap(),
        turn_stat_dict = turnStatDict,
        card_stat_dict = mapOf(
          deck.suit_master_id_1 to deck.card_master_id_1,
          deck.suit_master_id_2 to deck.card_master_id_2,
          deck.suit_master_id_3 to deck.card_master_id_3,
          deck.suit_master_id_4 to deck.card_master_id_4,
          deck.suit_master_id_5 to deck.card_master_id_5,
          deck.suit_master_id_6 to deck.card_master_id_6,
          deck.suit_master_id_7 to deck.card_master_id_7,
          deck.suit_master_id_8 to deck.card_master_id_8,
          deck.suit_master_id_9 to deck.card_master_id_9
        ).map({ it.key!! to LiveCardStat(card_master_id = it.value!!) })
        .toMap(),
        target_score = targetScore,
        remaining_stamina = stamina,
        live_power = power
      )
    ))
  )
  return parseResponse(response)
}

data class SetFavoriteMemberRequest(val member_master_id: Int)

fun setFavoriteMember(id: Int): UserModelResponse? {
  val response = call(
    path = "/communicationMember/setFavoriteMember",
    payload = gson.toJson(SetFavoriteMemberRequest(member_master_id = id))
  )
  return parseResponse(response)
}

data class FetchBootstrapRequest(
  val bootstrap_fetch_types: List<Int>,
  val device_token: String,
  val device_name: String
)

data class UserInfoTriggerGachaPointExchangeRow(
  val trigger_id: Int,
  val gacha_master_id: Int,
  val gacha_title: LocalizedText,
  val point_1_master_id: Int,
  val point_1_before_amount: Int,
  val point_1_after_amount: Int,
  val point_2_master_id: Int,
  val point_2_before_amount: Int,
  val point_2_after_amount: Int
)

data class ShopBillingProductContent(
  val amount: Int,
  val content_type: Int,
  val content_master_id: Int,
  val is_paid_content: Boolean
)

data class ShopBillingPlatformProduct(
  val platform_product_id: String // TODO: not sure
)

data class ShopBillingLimitedProductDetail(
  val beginner_term: Int,
  val sale_end_at: Long,
  val limit_amount: Int?,
  val limited_remaining_amount: Int?,
  val parent_shop_billing_platform_product: ShopBillingPlatformProduct,
  val parent_shop_billing_product_content: List<ShopBillingProductContent>
)

data class GiftBoxContent(
  val amount: Int,
  val content_type: Int,
  val content_master_id: Int,
  val day: Int
)

data class GiftBox(
  val is_in_period_gift_box: Boolean,
  val gift_box_content: List<GiftBoxContent>
)

data class ShopBillingProduct(
  val shop_product_master_id: Int,
  val billing_product_type: Int,
  val price: Int,
  val shop_billing_product_content: List<ShopBillingProductContent>,
  val shop_billing_platform_product: ShopBillingPlatformProduct,
  val shop_billing_limited_product_detail: ShopBillingLimitedProductDetail,
  val gift_box: GiftBox
)

data class UserInfoTriggerExpiredGiftBox(
  val total_days: Int,
  val shop_billing_product: ShopBillingProduct,
  val is_repurchase: Boolean
)

data class UserInfoTriggerEventMarathonShowResultRow(
  val trigger_id: Int,
  val event_marathon_id: Int,
  val result_at: Long,
  val end_at: Long
)

data class UserInfoTrigger(
  val user_info_trigger_gacha_point_exchange_rows:
    List<UserInfoTriggerGachaPointExchangeRow>,
  val user_info_trigger_expired_gift_box_rows:
    List<UserInfoTriggerExpiredGiftBox>,
  val user_info_trigger_event_marathon_show_result_rows:
    List<UserInfoTriggerEventMarathonShowResultRow>
)

data class BillingStateInfo(
  val age: Int?,
  val current_month_purchase_price: Int
)

data class TextureStruktur(val v: String)

data class Banner(
  val banner_master_id: Int,
  val banner_image_asset_path: TextureStruktur,
  val banner_type: Int,
  val expire_at: Long,
  val transition_id: Int,
  val transition_parameter: Int?
)

data class BootstrapBanner(val banners: List<Banner>)

data class BootstrapNewBadge(
  val is_new_main_story: Boolean,
  val unreceived_present_box: Int,
  val notice_new_arrivals_ids: List<Int>,
  val is_update_friend: Boolean,
  val unreceived_mission: Int
)

data class BootstrapPickupEventMarathonInfo(
  val event_id: Int,
  val closed_at: Long,
  val end_at: Long
)

data class BootstrapLiveCampaignInfo(
  val live_campaign_end_at: Long,
  val live_daily_campaign_end_at: Long
)

data class BootstrapPickupInfo(
  val active_event: BootstrapPickupEventMarathonInfo,
  val live_campaign_info: BootstrapLiveCampaignInfo,
  val is_lesson_campaign: Boolean,
  val appeal_gachas: List<TextureStruktur>,
  val is_shop_sale: Boolean
)

data class BootstrapExpiredItem(val expired_items: List<Content>)
data class MovieStruktur(val v: String)

data class BootstrapSuperNotice(
  val notice_id: Int,
  val movie_path: MovieStruktur,
  val last_updated_at: Long
)

data class BootstrapNotice(
  val super_notices: List<BootstrapSuperNotice>,
  val fetched_at: Long,
  val review_super_notice_at: Long,
  val force_view_notice_id: Int
)

data class LoginBonusContents(
  val content_type: Int,
  val content_id: Int,
  val content_amount: Int
)

data class LoginBonusRewards(
  val day: Int,
  val status: Int,
  val content_grade: Int?,
  val login_bonus_contents: List<LoginBonusContents>
)

data class IllustLoginBonus(
  val login_bonus_id: Int,
  val login_bonus_rewards: List<LoginBonusRewards>,
  val background_id: Int,
  val start_at: Long,
  val end_at: Long
)

data class NaviLoginBonus(
  val login_bonus_id: Int,
  val login_bonus_rewards: List<LoginBonusRewards>,
  val background_id: Int,
  val whiteboard_texture_asset: TextureStruktur,
  val member_master_id: Int?,
  val suit_master_id: Int?,
  val start_at: Long,
  val end_at: Long,
  val max_page: Int,
  val current_page: Int
)

data class BootstrapLoginBonus(
  val event_2d_login_bonuses: List<IllustLoginBonus>,
  val login_bonuses: List<NaviLoginBonus>,
  val event_3d_login_bonuses: List<NaviLoginBonus>,
  val beginner_login_bonuses: List<NaviLoginBonus>,
  val comeback_login_bonuses: List<IllustLoginBonus>,
  val birthday_login_bonuses: List<NaviLoginBonus>,
  val next_login_bons_receive_at: Long
)

data class FetchBootstrapResponse(
  val user_model_diff: UserModel,
  val user_info_trigger: UserInfoTrigger,
  val billing_state_info: BillingStateInfo,
  val fetch_bootstrap_banner_response: BootstrapBanner?,
  val fetch_bootstrap_new_badge_response: BootstrapNewBadge?,
  val fetch_bootstrap_pickup_info_response: BootstrapPickupInfo?,
  val fetch_bootstrap_expired_item_response: BootstrapExpiredItem?,
  val fetch_bootstrap_login_bonus_response: BootstrapLoginBonus?,
  val fetch_bootstrap_notice_response: BootstrapNotice?,
  val mission_beginner_master_id: Int?
)

fun fetchBootstrap(types: List<Int>): FetchBootstrapResponse? {
  val response = call(
    path = "/bootstrap/fetchBootstrap",
    payload = gson.toJson(FetchBootstrapRequest(
      bootstrap_fetch_types = types,
      device_name = deviceName,
      device_token = deviceToken
    ))
  )
  return parseResponse(response)
}

data class TapLovePointRequest(val member_master_id: Int)

fun tapLovePoint(memberMasterId: Int): UserModelResponse? {
  val response = call(
    path = "/navi/tapLovePoint",
    payload = gson.toJson(TapLovePointRequest(
      member_master_id = memberMasterId
    ))
  )
  return parseResponse(response)
}

data class SaveUserNaviVoiceRequest(val navi_voice_master_ids: List<Int>)

fun saveUserNaviVoice(ids: List<Int>): UserModelResponse? {
  val response = call(
    path = "/navi/saveUserNaviVoice",
    payload = gson.toJson(SaveUserNaviVoiceRequest(
      navi_voice_master_ids = ids
    ))
  )
  return parseResponse(response)
}

data class FetchTrainingTreeRequest(val card_master_id: Int)

data class UserCardTrainingTreeCell(
  val cell_id: Int,
  val activated_at: Long
)

data class FetchTrainingTreeResponse(
  val user_card_training_tree_cell_list: List<UserCardTrainingTreeCell>
)

fun fetchTrainingTree(cardMasterId: Int): FetchTrainingTreeResponse? {
  val response = call(
    path = "/trainingTree/fetchTrainingTree",
    payload = gson.toJson(FetchTrainingTreeRequest(
      card_master_id = cardMasterId
    ))
  )
  return parseResponse(response)
}

data class LevelUpCardRequest(
  val additional_level: Int,
  val card_master_id: Int
)

data class LevelUpCardResponse(val user_model_diff: UserModel)

fun levelUpCard(
  cardMasterId: Int,
  additionalLevel: Int = 1
): LevelUpCardResponse? {
  val response = call(
    path = "/trainingTree/levelUpCard",
    payload = gson.toJson(LevelUpCardRequest(
      card_master_id = cardMasterId,
      additional_level = additionalLevel
    ))
  )
  return parseResponse(response)
}

data class ActivateTrainingTreeCellRequest(
  val card_master_id: Int,
  val cell_master_ids: List<Int>,
  val pay_type: Int
)

data class ActivateTrainingTreeCellResponse(
  val user_card_training_tree_cell_list: List<UserCardTrainingTreeCell>,
  val user_model_diff: UserModel
)

fun activateTrainingTreeCell(
  cardMasterId: Int,
  cellMasterIds: List<Int>,
  payType: Int = 1
): ActivateTrainingTreeCellResponse? {
  val response = call(
    path = "/trainingTree/activateTrainingTreeCell",
    payload = gson.toJson(ActivateTrainingTreeCellRequest(
      card_master_id = cardMasterId,
      cell_master_ids = cellMasterIds,
      pay_type = payType
    ))
  )
  return parseResponse(response)
}

data class FinishUserStorySideRequest(
  val story_side_master_id: Int,
  val is_auto_mode: Boolean?
)

fun finishUserStorySide(
  masterId: Int,
  isAutoMode: Boolean? = false
): UserModelResponse? {
  val response = call(
    path = "/communicationMember/finishUserStorySide",
    payload = gson.toJson(FinishUserStorySideRequest(
      story_side_master_id = masterId,
      is_auto_mode = isAutoMode
    ))
  )
  return parseResponse(response)
}

data class UpdateCardNewFlagRequest(val card_master_ids: List<Int>)
data class UpdateCardNewFlagResponse(val user_model_diff: UserModel)

fun updateCardNewFlag(masterIds: List<Int>): UpdateCardNewFlagResponse? {
  val response = call(
    path = "/card/updateCardNewFlag",
    payload = gson.toJson(UpdateCardNewFlagRequest(
      card_master_ids = masterIds
    ))
  )
  return parseResponse(response)
}

data class LiveSquad(
  val card_master_ids: List<Int>,
  val user_accessory_ids: List<Int?> = listOf(null, null, null)
)

data class SaveLiveDeckAllRequest(
  val deck_id: Int,
  val card_with_suit: Map<Int, Int?>,
  val squad_dict: Map<Int, LiveSquad>
)

fun saveLiveDeckAll(
  deckId: Int,
  cardWithSuit: Map<Int, Int?>,
  squad: Map<Int, LiveSquad>
): UserModelResponse? {
  val response = call(
    path = "/liveDeck/saveDeckAll",
    payload = gson.toJson(SaveLiveDeckAllRequest(
      deck_id = deckId,
      card_with_suit = cardWithSuit,
      squad_dict = squad
    ))
  )
  return parseResponse(response)
}

data class SaveLiveDeckMemberSuitRequest(
  val deck_id: Int,
  val card_index: Int,
  val suit_master_id: Int
)

fun saveSuit(
  deckId: Int,
  cardIndex: Int,
  suitMasterId: Int
): UserModelResponse? {
  val response = call(
    path = "/liveDeck/saveSuit",
    payload = gson.toJson(SaveLiveDeckMemberSuitRequest(
      deck_id = deckId,
      card_index = cardIndex,
      suit_master_id = suitMasterId
    ))
  )
  return parseResponse(response)
}

data class LivePartner(
  val user_id: Int,
  val name: LocalizedText,
  val rank: Int,
  val last_login_at: Long,
  val card_by_category: Map<Int, OtherUserCard>,
  val emblem_id: Int,
  val is_friend: Boolean,
  val introduction_message: LocalizedText
)

data class PartnerSelectState(
  val live_partners: List<LivePartner>,
  val friend_count: Int
)

// klab can't type partner
data class FetchLiveParntersResponse(
  val partner_select_state: PartnerSelectState
)

fun fetchLivePartners(): FetchLiveParntersResponse? {
  val response = call(
    path = "/livePartners/fetch",
    payload = gson.toJson(null)
  )
  return parseResponse(response)
}

data class GachaAppeal(
  val card_master_id: Int?,
  val appearance_type: Int?,
  val main_image_asset: TextureStruktur,
  val sub_image_asset: TextureStruktur,
  val text_image_asset: TextureStruktur
)

data class GachaDraw(
  val gacha_draw_master_id: Int,
  val recover_type: Int,
  val recover_at: Long,
  val draw_count: Int,
  val gacha_payment_master_id: Int,
  val gacha_payment_amount: Int,
  val gacha_point_amount: Int?,
  val description: LocalizedText,
  val is_bonus: Boolean,
  val bonus_appeal_text: LocalizedText,
  val retry_count: Int?,
  val daily_limit: Int?,
  val term_limit: Int?,
  val remain_day_count: Int?,
  val remain_term_count: Int?,
  val performance_id: Int
)

data class Gacha(
  val gacha_master_id: Int,
  val gacha_type: Int,
  val gacha_draw_type: Int,
  val gacha_payment_type: Int,
  val title: LocalizedText,
  val banner_image_asset: TextureStruktur,
  val is_time_limited: Boolean,
  val end_at: Long,
  val point_master_id: Int?,
  val point_exchange_expire_at: Long,
  val appeal_at: Long,
  val notice_id: Int,
  val appeal_view: Int,
  val gacha_appeals: List<GachaAppeal>,
  val gacha_draws: List<GachaDraw>
)

data class RetryGacha(
  val gacha_draw_master_id: Int,
  val remain_retry_count: Int,
  val expire_at: Long
)

data class AddedGachaCardResult(
  val gacha_lot_type: Int,
  val card_master_id: Int,
  val level: Int,
  val before_grade: Int,
  val after_grade: Int,
  val content: Content,
  val limit_exceeded: Boolean,
  val before_love_level_limit: Int,
  val after_love_level_limit: Int
)

data class GachaUnconfirmed(
  val gacha: Gacha,
  val retry_gacha: RetryGacha,
  val result_cards: List<AddedGachaCardResult>
)

data class FetchGachaMenuResponse(
  val gacha_list: List<Gacha>,
  val gacha_unconfirmed: GachaUnconfirmed
)

fun fetchGachaMenu(): FetchGachaMenuResponse? {
  val response = call(
    path = "/gacha/fetchGachaMenu",
    payload = gson.toJson(null)
  )
  return parseResponse(response)
}

data class DrawGachaRequest(val gacha_draw_master_id: Int)

data class DrawGachaResponse(
  val gacha: Gacha,
  val result_cards: List<AddedGachaCardResult>,
  val result_bonuses: List<Content>,
  val retry_gacha: RetryGacha,
  val user_model_diff: UserModel
)

fun drawGacha(id: Int): DrawGachaResponse? {
  val response = call(
    path = "/gacha/draw",
    payload = gson.toJson(DrawGachaRequest(gacha_draw_master_id = id))
  )
  return parseResponse(response)
}

fun tutorialPhaseEnd(): UserModelResponse? {
  val response = call(
    path = "/tutorial/phaseEnd",
    payload = gson.toJson(null)
  )
  return parseResponse(response)
}

data class FetchGameServiceDataRequest(
  val service_id: String,
  val mask: String
)

data class FetchGameServiceDataResponse(val data: UserLinkData)

fun fetchGameServiceData(): FetchGameServiceDataResponse? {
  val response = call(
    path = "/dataLink/fetchGameServiceData",
    payload = gson.toJson(FetchGameServiceDataRequest(
      service_id = serviceId,
      mask = generateMask()
    ))
  )
  val res: FetchGameServiceDataResponse? = parseResponse(response)
  res?.data?.let {
    it.service_user_common_key =
      it.authorization_key.fromBase64().xor(randomBytes)
  }
  return res
}

data class LinkGameServiceRequest(val service_id: String)
data class LinkGameServiceResponse(val empty: Int?) // empty object

fun linkGameService(): LinkGameServiceResponse? {
  val response = call(
    path = "/dataLink/linkOnStartUpGameService",
    payload = gson.toJson(LinkGameServiceRequest(service_id = serviceId))
  )
  return parseResponse(response)
}

data class ReadLoginBonusRequest(
  val login_bonus_type: Int,
  val login_bonus_id: Int
)

data class EmptyResponse(val empty: Int?)

fun readLoginBonus(type: Int, id: Int): EmptyResponse? {
  val response = call(
    path = "/loginBonus/readLoginBonus",
    payload = gson.toJson(ReadLoginBonusRequest(
      login_bonus_type = type,
      login_bonus_id = id
    ))
  )
  return parseResponse(response)
}

data class FetchNoticeDetailRequest(val notice_id: Int)

data class NoticeDetail(
  val notice_id: Int,
  val category: Int,
  val title: LocalizedText,
  val detail_text: LocalizedText,
  val date: Long
)

data class FetchNoticeDetailResponse(val notice: NoticeDetail)

fun fetchNoticeDetail(id: Int): FetchNoticeDetailResponse? {
  val response = call(
    path = "/notice/fetchNoticeDetail",
    payload = gson.toJson(FetchNoticeDetailRequest(notice_id = id))
  )
  return parseResponse(response)
}

data class NoticeSummary(
  val notice_id: Int,
  val category: Int,
  val is_new: Boolean,
  val title: LocalizedText,
  val date: Long,
  val banner_thumbnail: TextureStruktur
)

data class NoticeList(
  val category: Int,
  val new_arrival_ids: List<Int>,
  val current_page: Int,
  val max_page: Int,
  val max_index: Int,
  val notices: List<NoticeSummary>
)

data class FetchNoticeResponse(
  val notice_lists: Map<Int, NoticeList>,
  val notice_no_check_at: Long
)

fun fetchNotice(): FetchNoticeResponse? {
  val response = call(
    path = "/notice/fetchNotice",
    payload = gson.toJson(null)
  )
  return parseResponse(response)
}

data class PresentItem(
  val id: Int,
  val content: Content,
  val present_route_type: Int,
  val present_route_id: Int?,
  val param_server: LocalizedText,
  val param_client: String,
  val posted_at: Long,
  val expired_at: Long,
  val is_new: Boolean
)

data class PresentHistoryItem(
  val content: Content,
  val present_route_type: Int,
  val present_route_id: Int?,
  val param_server: LocalizedText,
  val param_client: String,
  val history_created_at: Long
)

data class FetchPresentResponse(
  val present_items: List<PresentItem>,
  val present_history_items: List<PresentHistoryItem>
)

fun fetchPresent(): FetchPresentResponse? {
  val response = call(
    path = "/present/fetch",
    payload = gson.toJson(null)
  )
  return parseResponse(response)
}

data class ReceivePresentRequest(val ids: List<Int>)

data class AddedCardResult(
  val card_master_id: Int,
  val level: Int,
  val before_grade: Int,
  val after_grade: Int,
  val content: Content,
  val limit_exceeded: Boolean,
  val before_love_level_limit: Int,
  val after_love_level_limit: Int
)

data class ReceivePresentResponse(
  val user_model_diff: UserModel,
  val present_items: List<PresentItem>,
  val present_history_items: List<PresentHistoryItem>,
  val received_present_items: List<Content>,
  val limit_exceeded_items: List<PresentItem>,
  val card_grade_up_result: List<AddedCardResult>,
  val present_count: Int
)

fun receivePresent(ids: List<Int>): ReceivePresentResponse? {
  val response = call(
    path = "/present/receive",
    payload = gson.toJson(ReceivePresentRequest(ids = ids))
  )
  return parseResponse(response)
}

data class GetClearedPlatformAchievementResponse(
  val cleared_ids: List<Int>
)

fun getClearedPlatformAchievement():
  GetClearedPlatformAchievementResponse? {
  val response = call(
    path = "/bootstrap/getClearedPlatformAchievement",
    payload = gson.toJson(null)
  )
  return parseResponse(response)
}

data class FetchSchoolIdolFestivalIdRewardResponse(
  val visible_mission_ids: List<Int>,
  val is_new_mission_ids: List<Int>,
  val ll_user_name: LocalizedText?,
  val user_model_diff: UserModel
)

fun fetchSchoolIdolFestivalIdReward():
  FetchSchoolIdolFestivalIdRewardResponse? {
  val response = call(
    path = "/schoolIdolFestivalIdReward/fetch",
    payload = gson.toJson(null)
  )
  return parseResponse(response)
}

data class LinkedInfo(
  val is_platform_linked: Boolean,
  val is_school_idol_festival_id_linked: Boolean
)

fun fetchDataLinks(): LinkedInfo? {
  val response = call(
    path = "/dataLink/fetchDataLinks",
    payload = gson.toJson(null)
  )
  return parseResponse(response)
}

data class FetchSchoolIdolFestivalIdDataRequest(
  val auth_code: String,
  val mask: String
)

data class FetchSchoolIdolFestivalIdDataResponse(val data: UserLinkData?)

fun fetchSchoolIdolFestivalIdDataAfterLogin(
  authCode: String
): FetchSchoolIdolFestivalIdDataResponse? {
  val response = call(
    path = "/dataLink/fetchSchoolIdolFestivalIdDataAfterLogin",
    payload = gson.toJson(FetchSchoolIdolFestivalIdDataRequest(
      auth_code = authCode,
      mask = generateMask()
    ))
  )
  val res: FetchSchoolIdolFestivalIdDataResponse? = parseResponse(response)
  res?.data?.let {
    it.service_user_common_key =
      it.authorization_key.fromBase64().xor(randomBytes)
  }
  return res
}

data class LinkSchoolIdolFestivalIdResponse(val user_model: UserModel)

fun linkSchoolIdolFestivalId(): LinkSchoolIdolFestivalIdResponse? {
  val response = call(
    path = "/dataLink/linkSchoolIdolFestivalId",
    payload = gson.toJson(null)
  )
  return parseResponse(response)
}

// ------------------------------------------------------------------------
// client

// creates a new account, completes tutorial, gets gifts
// - requires name, nickname, deviceName, deviceToken, serviceId to be set
// - deviceToken can be an empty string, this means that you don't have
//   google services on your device
// - name and nickname must be max 12 characters
public fun makeAccount() {
  fetchGameServiceDataBeforeLogin()!!
  randomDelay(1000)
  val startupResponse = startup()!!
  val authKey = base64Decoder.decode(startupResponse.authorization_key)
  sessionKey = authKey.xor(randomBytes)
  randomDelay(2000)
  performLogin()
  randomDelay(9000)
  var terms = userModel!!.user_status.terms_of_use_version
  if (terms == 0) terms = 1 // TODO: is this how it works?
  termsAgreement(terms)!!
  randomDelay(9000)
  setUserProfile(name = generateName())!!
  randomDelay(9000)
  setUserProfile(nickname = generateNickname())!!
  randomDelay(4000)
  setUserProfileBirthDay()!!
  randomDelay(10000)
  finishUserStoryMain(cellId = 1001)!!
  randomDelay(1000)
  var startLiveResponse = startLive(
    liveDifficultyId = 30001301,
    cellId = 1002,
    deckId = 1
  )!!
  randomDelay(4000)
  saveRuleDescription(ids = listOf(1))!!
  randomDelay(4000)
  skipLive(
    live = startLiveResponse.live,
    stamina = 6578, // TODO: calc these
    power = 1040,
    targetScore = 35000
  )!!
  randomDelay(10000)
  finishUserStoryMain(cellId = 1003)!!
  startLiveResponse = startLive(
    liveDifficultyId = 31007301,
    cellId = 1004,
    deckId = 2
  )!!
  randomDelay(4000)
  saveRuleDescription(ids = listOf(2))!!
  randomDelay(4000)
  skipLive(
    live = startLiveResponse.live,
    stamina = 5812,
    power = 1047,
    targetScore = 40000
  )!!
  randomDelay(10000)
  setFavoriteMember(id = 1)!!
  randomDelay(4000)
  fetchBootstrap(types = listOf(2, 3, 4, 5, 9, 10))!!
  randomDelay(10000)
  tapLovePoint(memberMasterId = 1)!!
  randomDelay(4000)
  saveUserNaviVoice(ids = listOf(100010004))!!
  randomDelay(8000)
  fetchTrainingTree(cardMasterId = 100012001)!!
  randomDelay(8000)
  levelUpCard(cardMasterId = 100012001)!!
  randomDelay(8000)
  activateTrainingTreeCell(
    cardMasterId = 100012001,
    cellMasterIds =
      listOf(17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1)
  )!!
  randomDelay(30000)
  finishUserStorySide(masterId = 1000120011)!!
  randomDelay(8000)
  updateCardNewFlag(masterIds = listOf(100012001))!!
  randomDelay(8000)
  // TODO: do I need to hardcode this? is there any way to generate it?
  // what does cardWithSuit mean? why do the squad id's start from 101?
  var userModelResponse = saveLiveDeckAll(
    deckId = 1,
    cardWithSuit = mapOf(
      100012001 to null,
      102071001 to null,
      102081001 to null,
      101031001 to null,
      101061001 to null,
      101051001 to null,
      100051001 to null,
      100051001 to null,
      100091001 to 100091001,
      100081001 to 100081001
    ),
    squad = mapOf(
      101 to LiveSquad(listOf(100012001, 101061001, 101051001)),
      102 to LiveSquad(listOf(102081001, 101031001, 100051001)),
      103 to LiveSquad(listOf(102071001, 100091001, 100081001))
    )
  )!!
  // TODO: smarter way to update userModel?
  var delta = userModelResponse.user_model
  userModel!!.user_live_deck_by_id = delta.user_live_deck_by_id
  userModel!!.user_live_party_by_id = delta.user_live_party_by_id
  randomDelay(8000)
  userModelResponse = saveSuit(
    deckId = 1,
    cardIndex = 1,
    suitMasterId = 100012001
  )!!
  delta = userModelResponse.user_model
  userModel!!.user_live_deck_by_id = delta.user_live_deck_by_id
  randomDelay(8000)
  fetchLivePartners()!!
  randomDelay(8000)
  startLiveResponse = startLive(
    liveDifficultyId = 31001101,
    cellId = 1005,
    deckId = 1
  )!!
  randomDelay(8000)
  skipLive(
    live = startLiveResponse.live,
    stamina = 7491,
    power = 1341,
    targetScore = 50000
  )!!
  randomDelay(10000)
  fetchGachaMenu()!!
  randomDelay(4000)
  drawGacha(id = 1)!!
  randomDelay(15000)
  fetchBootstrap(types = listOf(2, 3, 4, 5, 9, 10))!!
  randomDelay(10000)
  tutorialPhaseEnd()!!
  fetchGameServiceData()!!
  linkGameService()!!
  getGiftsAndCommitAccount()
}

fun performLogin() {
  var loginResponse: LoginResponse?
  try {
    loginResponse = login(retries = 0)
  } catch (e: Exception) {
    loginResponse = null
  }
  if (loginResponse == null) {
    // our stored key is incorrect, retrieve it
    userId = 0
    sessionKey = config.StartupKey.toByteArray()
    val fetchResponse = fetchGameServiceDataBeforeLogin()!!
    val linkedData = fetchResponse.data!!.linked_data
    sessionKey = linkedData.service_user_common_key
    userId = linkedData.user_id
    randomDelay(1000)
    loginResponse = login()!!
  }
  if (loginResponse.user_model == null) {
    // InvalidAuthCountResponse, sync with what server claims
    authCount = loginResponse.authorization_count!!
    loginResponse = login()!!
  }
  val loginSessionKey = base64Decoder.decode(loginResponse.session_key)
  temporarySessionKey = loginSessionKey.xor(randomBytes)
  userModel = loginResponse.user_model
  // TODO: better tracking of userModel changes
}

fun getGiftsAndCommitAccount() {
  randomDelay(9000)
  val fetchResponse = fetchGameServiceData()!!
  sessionKey = fetchResponse.data.service_user_common_key
  var bstrapResponse =
    fetchBootstrap(types = listOf(2, 3, 4, 5, 9, 10, 11))!!
  // TODO: figure out what type are comeback, event_3d and birthday bonuses
  bstrapResponse.fetch_bootstrap_login_bonus_response?.let {
    for (bonus in it.event_2d_login_bonuses) {
      randomDelay(5000)
      readLoginBonus(type = 3, id = bonus.login_bonus_id)!!
    }
    for (bonus in it.beginner_login_bonuses) {
      randomDelay(5000)
      readLoginBonus(type = 2, id = bonus.login_bonus_id)!!
    }
    for (bonus in it.login_bonuses) {
      randomDelay(5000)
      readLoginBonus(type = 1, id = bonus.login_bonus_id)!!
    }
  }
  // TODO: should these be removed after the first time?
  saveUserNaviVoice(ids = listOf(100010123, 100010113))!!
  bstrapResponse = fetchBootstrap(types = listOf(2, 3, 4, 5, 9, 10))!!
  bstrapResponse
    .fetch_bootstrap_notice_response?.super_notices?.lastOrNull()?.let {
      fetchNoticeDetail(id = it.notice_id)!!
    }
  fetchNotice()!!
  randomDelay(2000)
  saveUserNaviVoice(ids = listOf(100010046))!!
  val presents = fetchPresent()!!
  if (presents.present_items.size > 0) {
    randomDelay(2000)
    saveRuleDescription(ids = listOf(20))!! // TODO: necessary?
    randomDelay(5000)
    val presentResponse =
      receivePresent(ids = presents.present_items.map { it.id })!!
    userModel = presentResponse.user_model_diff
    randomDelay(9000)
    fetchBootstrap(types = listOf(2, 3, 4, 5, 9, 10))!!
  }
  commitAccount()
}

// login, complete tutorial if incomplete and get gifts
// - if deviceName is set and the account has no deviceName, it will be
//   associated to this deviceName
public fun loginAndGetGifts() {
  performLogin()
  getGiftsAndCommitAccount()
}

var sifidSession = ""

// TODO: handle errors gracefully here
fun sifidRequest(
  path: String,
  queryParams: Map<String, String> = emptyMap(),
  body: String? = null,
  mediaType: String? = null
): String? {
  var urlBuilder = HttpUrl.Builder()
    .scheme("https")
    .host("www.sifid.net")
    .addPathSegment(path)
  queryParams.map {
    urlBuilder = urlBuilder.addEncodedQueryParameter(it.key, it.value)
  }
  val url = urlBuilder.build()
  var builder = Request.Builder()
    .url(url)
    .header("User-Agent", "Mozilla/5.0 (Android 8.1.0; Tablet; rv:68.0) " +
      "Gecko/68.0 Firefox/68.0")
    .header("Accept", "text/html,application/xhtml+xml,application/xml;" +
      "q=0.9,*/*;q=0.8")
    .header("Accept-Language", "en-US,en;q=0.5")
    .header("Accept-Encoding", "gzip, deflate, br")
    .header("Connection", "keep-alive")
    .header("Cookie", "beaker.session.id=$sifidSession")
    .header("Upgrade-Insecure-Requests", "1")
  if (mediaType != null && body != null) {
    val mt = MediaType.parse(mediaType)
    builder = builder.post(RequestBody.create(mt, body.toByteArray()))
  }
  val request = builder.build()
  println(request)
  val response = httpClient.newCall(request).execute()
  if (response.code() != 302 && !response.isSuccessful) {
    println("unexpected code $response")
    return null
  }
  if ((flags and PrintHeaders) != 0) {
    val headers = response.headers()
    for (i in 0..headers.size() - 1) {
      val name = headers.name(i)
      val value = headers.value(i)
      println("$name: $value")
    }
  }
  if (response.code() == 302) {
    return response.header("Location")!!
  }
  return response.body()!!.string()
}

// login, complete tutorial, get gifts and associate a sif id with this acc
// returns success
public fun linkSifid(mail: String, password: String): Boolean {
  performLogin()
  getClearedPlatformAchievement()!!
  randomDelay(4000)
  fetchSchoolIdolFestivalIdReward()!!
  randomDelay(8000)
  val dataLinks = fetchDataLinks()!!
  if (dataLinks.is_school_idol_festival_id_linked) {
    println("this account already has a sif id linked")
    return false
  }
  sifidSession = List(32) { "abcdef0123456789".random() }.joinToString("")
  // NOTE: okhttp automatically follows redirects
  // this redirects to login
  // state = https://docs.unity3d.com/ScriptReference/Random-value.html
  // it's a simple token to prevent malware from mitming the auth
  sifidRequest(path = "auth", queryParams = mapOf(
    // OkHttp doesn't escape params as I need em, so I'm gonna manually
    // hardcode them escaped. the server is very picky about this
    // TODO: don't do this shit
    "redirect_uri" to
      "com%2eklab%2elovelive%2eallstars%3a%2f%2fklab_id%2fcallback",
    "response_type" to "code",
    "state" to "%.7f".format(Random.nextDouble()).replace(".", "%2e"),
    "client_id" to "lovelive%2eallstars",
    "scope" to "transfer_user_data+reference_user_id+reference_user_data"
  ))!!
  sifidRequest(path = "static/css/style_20191011.css")!!
  var bodyParams = HttpUrl.Builder()
    .scheme("http")
    .host("example.com")
    .addQueryParameter("email", mail)
    .addQueryParameter("password", password)
    .build()
  // this redirects to auth which redirects to home
  sifidRequest(path = "login",
    mediaType = "application/x-www-form-urlencoded",
    body = bodyParams.query()
  )!!
  // this redirects to
  // com.klab.lovelive.allstars://klab_id/callback?state=xxx&code=xxxx
  // we want the code
  val redirect = sifidRequest(path = "allow",
    mediaType = "application/x-www-form-urlencoded",
    body = "token=$sifidSession"
  )!!
  println("redirect is $redirect")
  // workaround because HttpUrl can't handle non http schemes
  val redirectUrl = HttpUrl.parse(redirect
    .replace("com.klab.lovelive.allstars://", "http://example.com"))!!
  val code = redirectUrl.queryParameter("code")!!
  println("code is $code")
  val fetchedData =
    fetchSchoolIdolFestivalIdDataAfterLogin(authCode = code)!!
  if (fetchedData.data != null) {
    println("this sif id is already linked to an account: $fetchedData")
    return false
  }
  linkSchoolIdolFestivalId()!!
  sifidMail = mail
  sifidPassword = password
  commitAccount()
  return true
}

// load account by id and set up the client to log it in. returns self
public fun getAccount(id: Int): AllStarsClient? =
  sqlLoadAccount("id = $id")

fun commitAccount() =
  sql.sqlCommitAccount(
    userId = userId,
    serviceId = serviceId,
    deviceToken = deviceToken,
    deviceName = deviceName,
    authCount = authCount + 1,
    sessionKey = sessionKey,
    sifidMail = sifidMail,
    sifidPassword = sifidPassword,
    userModel = userModel!!
  )

val sqlStatement = readOnlyDB("todokete.db")
fun sqlQuery(sql: String): ResultSet =
  sqlTry { sqlStatement.executeQuery(sql) }

fun sqlLoadAccount(wherePart: String): AllStarsClient? {
  val s = sqlQuery("""
  select id, serviceId, authCount, deviceToken, deviceName,
  sessionKey, sifidMail, sifidPassword
  from accounts where $wherePart
  """)
  if (!s.next()) {
    return null
  }
  userId = s.getInt("id")
  serviceId = s.getString("serviceId")
  authCount = s.getInt("authCount")
  deviceToken = s.getString("deviceToken")
  deviceName = s.getString("deviceName")
  sessionKey = s.getString("sessionKey").fromBase64()
  sifidMail = s.getString("sifidMail")
  sifidPassword = s.getString("sifidPassword")
  return this
}
} // AllStarsClient

// ------------------------------------------------------------------------

private val sql = object {
  fun sqlCommitAccount(
    userId: Int,
    serviceId: String,
    authCount: Int,
    deviceName: String,
    deviceToken: String,
    sessionKey: ByteArray,
    sifidMail: String?,
    sifidPassword: String?,
    userModel: AllStarsClient.UserModel
  ) = sqlQueue!!.add { sqlTry<Unit> {
    val m = userModel
    var sql = """
      insert or replace into accounts(
        id, serviceId, authCount, stars, lastLogin, deviceToken, deviceName,
        sessionKey, sifidMail, sifidPassword
      )
      values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """
    var stmt = sqlConnection.prepareStatement(sql)
    stmt.setInt(1, userId)
    stmt.setString(2, serviceId)
    stmt.setInt(3, authCount)
    stmt.setInt(4, userModel.user_status.free_sns_coin)
    stmt.setLong(5, System.currentTimeMillis())
    stmt.setString(6, deviceToken)
    stmt.setString(7, deviceName)
    stmt.setString(8, sessionKey.toBase64())
    stmt.setString(9, sifidMail)
    stmt.setString(10, sifidPassword)
    stmt.addBatch()
    stmt.execute()
    val items = (
      m.user_gacha_ticket_by_ticket_id.map {
        (k, v) -> k to v.normal_amount
      } +
      // TODO? m.user_gacha_point_by_point_id.map { (k, v) -> } +
      m.user_lesson_enhancing_item_by_item_id.map
        { (k, v) -> k to v.amount
      } +
      m.user_training_material_by_item_id.map { (k, v) -> k to v.amount } +
      m.user_grade_up_item_by_item_id.map { (k, v) -> k to v.amount } +
      m.user_recovery_lp_by_id.map { (k, v) -> k to v.amount } +
      m.user_recovery_ap_by_id.map { (k, v) -> k to v.amount } +
      m.user_accessory_level_up_item_by_id.map {
        (k, v) -> k to v.amount
      } +
      m.user_accessory_rarity_up_item_by_id.map {
        (k, v) -> k to v.amount
      } +
      m.user_live_skip_ticket_by_id.map { (k, v) -> k to v.amount } +
      m.user_event_marathon_booster_by_id.map { (k, v) -> k to v.amount }
    )
    sql = "insert or replace into items(uid, id, amount) values(?, ?, ?)"
    stmt = sqlConnection.prepareStatement(sql)
    items.map { (k, v) ->
      stmt.setInt(1, userId)
      stmt.setInt(2, k)
      stmt.setInt(3, v)
      stmt.addBatch()
    }
    stmt.executeBatch()
    sqlConnection.commit()
  } }

  fun sqlUpdate(sql: String) {
    sqlQueue!!.add {
      sqlTry<Unit> {
        sqlStatement.executeUpdate(sql)
        sqlConnection.commit()
      }
    }
  }

  fun sqlUpdateWait(sql: String) {
    val q = LinkedBlockingQueue<Unit>()
    sqlQueue!!.add {
      sqlTry<Unit> {
        sqlStatement.executeUpdate(sql)
        sqlConnection.commit()
        q.add(Unit)
      }
    }
    q.take()
  }

  // ------------------------------------------------------------------

  private val jdbcPath = "jdbc:sqlite:todokete.db" +
    "?journal_mode=WAL&synchronous=NORMAL&journal_size_limit=500"
  private val sqlQueue: LinkedBlockingQueue<() -> Unit>?
  private val sqlConnection = DriverManager.getConnection(jdbcPath)
  private val sqlStatement = sqlConnection.createStatement()

  private fun sqlUpdateSync(sql: String) =
    sqlTry { sqlStatement.executeUpdate(sql) }

  private fun sqlQuery(sql: String): ResultSet =
    sqlTry { sqlStatement.executeQuery(sql) }

  private fun tableExists(name: String): Boolean =
    sqlQuery("""
      select name
      from sqlite_master
      where type='table' and name='$name'
    """).next()

  private fun createInfoTable() {
    sqlUpdateSync("""
    create table todokete_info(
      key text primary key,
      intValue integer,
      stringValue text
    )
    """)
  }

  private fun createAccountsTable() {
    sqlUpdateSync("""
    create table if not exists accounts(
      id integer primary key,
      serviceId char[22] not null,
      authCount integer not null,
      stars integer not null,
      lastLogin integer not null,
      deviceToken char[154] not null,
      deviceName text not null,
      sessionKey char[44] not null,
      sifidMail text,
      sifidPassword text
    )
    """)
  }

  private fun createItemsTable() {
    sqlUpdateSync("""
    create table if not exists items(
      uid integer not null,
      id integer not null,
      amount integer not null,
      primary key (uid, id)
    )
    """)
  }

  private fun sqlVersion(): Int? {
    val rowSet = sqlQuery(
      "select intValue from todokete_info where key = 'version'"
    )
    if (rowSet.next()) {
      return rowSet.getInt("intValue")
    }
    return null
  }

  private fun sqlSetVersion(x: Int) =
    sqlUpdateSync("""
      update todokete_info set intValue = $x where key = 'version'
    """)

  init {
    sqlConnection.setAutoCommit(false)
    sqlStatement.setQueryTimeout(30)

    // migrating from legacy databases
    // lots of crap has piled up here, will remove eventually

    if (!tableExists("accounts")) {
      println("[db] initializing database")
      createAccountsTable()
      createInfoTable()
      createItemsTable()
      sqlSetVersion(5)
      println("[db] done")
    } else if (!tableExists("todokete_info")) {
      println("[db] migrating to db version 1")
      createInfoTable()
      sqlUpdateSync("alter table accounts add deviceName text")
      sqlUpdateSync(
        "alter table accounts add serviceUserCommonKey char[44]")
      sqlSetVersion(1)
      println("[db] done")
    }

    if (sqlVersion()!! < 2) {
      println("[db] migrating to db version 2")
      sqlUpdateSync("delete from accounts where lastLogin is null")
      sqlUpdateSync("alter table accounts rename to accounts_old")
      createAccountsTable()
      sqlUpdateSync("insert into accounts select * from accounts_old")
      sqlUpdateSync("drop table accounts_old")
      sqlSetVersion(2)
      println("[db] done")
    }

    if (sqlVersion()!! < 3) {
      println("[db] migrating to db version 3")
      sqlUpdateSync("alter table accounts add sifidMail text")
      sqlUpdateSync("alter table accounts add sifidPassword text")
      sqlSetVersion(3)
      println("[db] done")
    }

    if (sqlVersion()!! < 4) {
      println("[db] migrating to db version 4")
      createItemsTable()
      sqlSetVersion(4)
      println("[db] done")
    }

    if (sqlVersion()!! < 5) {
      println("[db] migrating to db version 5")
      sqlUpdateSync("""
        delete from accounts where
        stars is null or
        deviceToken is null or
        deviceName is null or
        serviceUserCommonKey is null
      """)
      sqlUpdateSync("alter table accounts rename to accounts_old")
      createAccountsTable()
      sqlUpdateSync("""
        insert into accounts (id, serviceId, authCount, stars, lastLogin,
          deviceToken, deviceName, sessionKey, sifidMail, sifidPassword)
          select id, serviceId, authCount, stars, lastLogin, deviceToken,
            deviceName, serviceUserCommonKey, sifidMail, sifidPassword
          from accounts_old
      """)
      sqlUpdateSync("drop table accounts_old")
      sqlSetVersion(5)
      println("[db] done")
    }

    sqlConnection.commit()

    sqlQueue = LinkedBlockingQueue<() -> Unit>()
    thread {
      while (true) {
        val f = sqlQueue.take()
        f()
      }
    }
  }
} // object sql

// ------------------------------------------------------------------------
// cli stuff

fun randomLine(file: String): String? {
  var n = 0
  File(file).forEachLine { n += 1 }
  val line = Random.nextInt(0, n)
  n = 0
  File(file).useLines { lines ->
    for (x in lines) {
      if (n == line) { return x }
      n += 1
    }
  }
  return null
}

fun String.limitLen(len: Int): String =
  if (length > len) slice(0..len - 1) else this

fun generateName(): String {
  val name = randomLine("names.txt")!!.limitLen(4).toLowerCase()
  val place = randomLine("places.txt")!!.limitLen(4).toLowerCase()
  return when (Random.nextInt(0, 2)) {
    0 -> name + place
    else -> name + place + Random.nextInt(0, 99).toString()
  }
}

fun generateNickname(): String = randomLine("names.txt")!!.limitLen(10)
fun generateDeviceName(): String = randomLine("devices.txt")!!

fun generateServiceId(): String {
  return "g" + List(20) { "0123456789".random() }.joinToString("")
  // I think this is the format for the android games hub or whatever
  // return "a_" + List(19) { "0123456789".random() }.joinToString("")
}

fun getPushNotificationToken(): String {
  // TODO: implement firebase messaging in kotlin
  println("waiting for token-generator...")
  while (true) {
    try {
      val request = Request.Builder().url("http://127.0.0.1:6969").build()
      return httpClient.newCall(request).execute().body()!!.string()
    } catch (e: java.net.SocketTimeoutException) {
      Thread.sleep(1000)
    }
  }
}

fun hashStream(fis: InputStream): List<ByteArray> {
  val md5 = MessageDigest.getInstance("MD5")
  val sha1 = MessageDigest.getInstance("SHA-1")
  val sha256 = MessageDigest.getInstance("SHA-256")
  val buf = ByteArray(8192)
  while (true) {
    val n = fis.read(buf)
    if (n < 0) break
    md5.update(buf, 0, n)
    sha1.update(buf, 0, n)
    sha256.update(buf, 0, n)
  }
  return listOf(
    md5.digest(),
    sha1.digest(),
    sha256.digest()
  )
}

fun sha1(path: String): String? {
  val fis = try { FileInputStream(path) } catch (e: Exception) { null }
  if (fis == null) return null
  val digest = MessageDigest.getInstance("SHA-1")
  val buf = ByteArray(8192)
  while (true) {
    val n = fis.read(buf)
    if (n < 0) break
    digest.update(buf, 0, n)
  }
  return digest.digest().toHexString()
}

const val apkpure = "https://apkpure.com/%E3%83%A9%E3%83%96%E3%83%A9%E3" +
  "%82%A4%E3%83%96%EF%BC%81%E3%82%B9%E3%82%AF%E3%83%BC%E3%83%AB%E3%82%A2" +
  "%E3%82%A4%E3%83%89%E3%83%AB%E3%83%95%E3%82%A7%E3%82%B9%E3%83%86%E3%82" +
  "%A3%E3%83%90%E3%83%AB-all-stars/com.klab.lovelive.allstars"

val cfduid = List(43) { "abcdef0123456789".random() }.joinToString("")

fun apkPureRequest(url: String, referer: String? = null): Response {
  var builder = Request.Builder()
    .url(url)
    .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; " +
      "rv:70.0) Gecko/20100101 Firefox/70.0")
    .header("Accept", "text/html,application/xhtml+xml,application/xml;" +
      "q=0.9,*/*;q=0.8")
    .header("Accept-Language", "en-US,en;q=0.5")
    .header("Connection", "keep-alive")
    .header("Cookie", "__cfduid=$cfduid; apkpure__lang=en")
    .header("Upgrade-Insecure-Requests", "1")
  if (referer != null) {
    builder = builder.header("Referer", referer)
  }
  return httpClient.newCall(builder.build()).execute()
}

const val globalMetadataPath =
  "assets/bin/Data/Managed/Metadata/global-metadata.dat"

fun readNum(s: InputStream, buf: ByteArray): Int {
  var total = 0
  while (total < buf.size) {
    val n = s.read(buf, total, buf.size - total)
    if (n < 0) return n
    total += n
  }
  return total
}

// automatically downloads and extracts endpoint, startup key, hashes
// from the latest game's apk
fun getConfigFromRemoteApk(download: Boolean = false): AllStarsConfig {
  if (!download) {
    while (true) {
      try {
        return gson.fromJson(FileReader("config.json"),
          AllStarsConfig::class.java)
      } catch (e: Exception) {
        println("waiting for config.json from the updater thread ...")
        Thread.sleep(10000.toLong())
      }
    }
  }
  var localHash: String? = null
  var apkHash: String? = null
  while (localHash == null || localHash != apkHash) {
    println("checking for new apk...")
    var html = apkPureRequest(url = "$apkpure/versions").body()!!.string()
    val sha1Matcher = "<strong>File SHA1: </strong>([a-f0-9]+)".toRegex()
    val hashMatch = sha1Matcher.find(html)!!
    val (hash) = hashMatch.destructured
    apkHash = hash
    localHash = sha1("sifas.xapk")
    println("remote hash: $apkHash")
    println(" local hash: $localHash")
    if (localHash != null && localHash == apkHash) {
      break
    }
    html = apkPureRequest(url = "$apkpure/download?from=versions")
      .body()!!.string()
    // sed -n 's_.*\(https://download\.apkpure\.com/[^"]*\).*_\1_p'
    val urlMatcher =
      """https://download\.apkpure\.com/b/xapk/[^"]*""".toRegex()
    val apkUrl = urlMatcher.find(html)!!.value
    println("downloading: $apkUrl")
    val resp = apkPureRequest(
      url = apkUrl,
      referer = "$apkpure/download?from=versions"
    )
    val contentLen = resp.header("Content-Length")!!.toInt()
    val input = BufferedInputStream(resp.body()!!.byteStream())
    val output = FileOutputStream("sifas.xapk")
    val buf = ByteArray(8192)
    var total = 0
    while (true) {
      val num = input.read(buf)
      if (num < 0) { break }
      total += num
      output.write(buf, 0, num)
      val percent = (total.toDouble() / contentLen.toDouble()) * 100.0
      print("$total/$contentLen " +
        "%.2f%%                   \r".format(percent))
    }
    if (total != contentLen) {
      println("incomplete download")
      Thread.sleep(30000)
      continue
    }
    localHash = sha1("sifas.xapk")
    if (localHash == null || localHash != apkHash) {
      println("hash still doesn't match, redownloading 10 minutes")
      Thread.sleep(600000)
      continue
    }
  }

  try {
    val localConfig = gson.fromJson(FileReader("config.json"),
      AllStarsConfig::class.java)
    if (localConfig.apkHash == apkHash) {
      return localConfig
    }
  } catch (e: Exception) {
    // stfu
  }

  val res = AllStarsConfig(apkHash = apkHash!!)
  println("")
  println("extracting info from apk")

  // TODO: less nesting here
  val zip = ZipFile(File("sifas.xapk"))
  for (entry in zip.entries()) {
    when (entry.getName()) {
      "com.klab.lovelive.allstars.apk" -> {
        val zis = ZipInputStream(zip.getInputStream(entry))
        var innerEntry = zis.getNextEntry()
        var foundEndpoint = false
        var foundStartupKey = false
        while (innerEntry != null && !foundEndpoint && !foundStartupKey) {
          if (innerEntry.getName() != globalMetadataPath) {
            innerEntry = zis.getNextEntry()
            continue
          }
          // header
          var buf = ByteArray(20)
          var reader = ByteBuffer.wrap(buf).order(ByteOrder.LITTLE_ENDIAN)
          var numBytes = readNum(zis, buf)
          if (numBytes != buf.size) {
            println("couldn't read metadata header")
            return res
          }
          if (reader.getInt().toUInt() != 0xFAB11BAF.toUInt()) {
            println("not a valid metadata file")
            return res
          }
          val version = reader.getInt()
          val offset = reader.getInt().toLong()
          val num = reader.getInt() / 8
          val dataOffset = reader.getInt().toLong()
          println("metadata version $version")
          println("$num strings at 0x%08x-0x%08x"
            .format(offset, offset + num * 8))
          println("string data at 0x%08x".format(dataOffset))
          zis.skip(offset - buf.size)
          // string offsets and lengths
          buf = ByteArray(num * 8)
          reader = ByteBuffer.wrap(buf).order(ByteOrder.LITTLE_ENDIAN)
          numBytes = readNum(zis, buf)
          if (numBytes != buf.size) {
            println("couldn't read string list ($numBytes/${buf.size})")
            return res
          }
          val strings = MutableList(num) {
            reader.getInt() to reader.getInt()
          }
          strings.sortBy { it.second }
          // string data
          zis.skip(dataOffset - offset - buf.size)
          var prevIndex = 0.toLong()
          var prevLength = 0.toLong()

          val re = "https://.*.klabgames.net/ep[0-9]+".toRegex()
          strings.map {
            val (length, index) = it
            zis.skip(index.toLong() - prevIndex - prevLength)
            prevIndex = index.toLong()
            prevLength = length.toLong()
            buf = ByteArray(length)
            numBytes = readNum(zis, buf)
            if (numBytes != buf.size) {
              println("couldn't read string data ($numBytes/${buf.size})")
              return res
            }
            val str = buf.toString(Charsets.UTF_8)
            if (!foundEndpoint) {
              if (re.matches(str)) {
                res.ServerEndpoint = str
                println("endpoint: $str")
                foundEndpoint = true
              }
            } else if (!foundStartupKey) {
              res.StartupKey = str
              println("startupKey: $str")
              foundStartupKey = true
            }
          }
        }
      }
      "config.arm64_v8a.apk" -> {
        val zis = ZipInputStream(zip.getInputStream(entry))
        var innerEntry = zis.getNextEntry()
        while (innerEntry != null) {
          when (innerEntry.getName()) {
            "lib/arm64-v8a/libil2cpp.so" -> {
              res.Il2CppSignatures = hashStream(zis)
              println("il2cpp hashes:")
              for (x in res.Il2CppSignatures) {
                println(x.toHexString())
              }
            }
            "lib/arm64-v8a/libjackpot-core.so" -> {
              res.JackpotSignatures = hashStream(zis)
              println("libjackpot hashes:")
              for (x in res.JackpotSignatures) {
                println(x.toHexString())
              }
            }
            else -> { }
          }
          innerEntry = zis.getNextEntry()
        }
      }
      else -> { }
    }
  }
  File("config.json").writeText(gson.toJson(res))
  return res
}

fun printException(e: Exception) {
  val sw = StringWriter()
  val pw = PrintWriter(sw)
  pw.print("\u001b[31m")
  e.printStackTrace(pw)
  pw.print("\u001b[0m\n")
  print(sw.toString())
}

fun threadLoop(f: () -> Unit, cooldown: Int) {
  while (true) {
    try { f() } catch (e: Exception) { printException(e) }
    Thread.sleep(cooldown.toLong())
  }
}

val create: () -> Unit = {
  AllStarsClient(
    config = getConfigFromRemoteApk(),
    name = generateName(),
    nickname = generateNickname(),
    deviceName = generateDeviceName(),
    deviceToken = getPushNotificationToken(),
    serviceId = generateServiceId()
  )
  .makeAccount()
}

class Create : CliktCommand(help = "Create account") {
  override fun run() = threadLoop(f = create, cooldown = 2000)
}

val gifts: (Int) -> Unit = { threads ->
  // we must query the database first and then launch our threads with
  // pre-fetched accounts. this way we don't pull the same accounts from
  // multiple threads and there's no concurrecy issues
  val old = System.currentTimeMillis() - 3600000.toLong() * 24
  val todokete = readOnlyDB("todokete.db")
  val rs = todokete.executeQuery("""
    select id from accounts where lastLogin < $old order by lastLogin asc
    limit $threads
  """)
  val handles = mutableListOf<Thread>()
  repeat(threads) {
    if (!rs.next()) {
      println("no more stale accounts, resting for a bit...")
      Thread.sleep(600000)
    }
    val id = rs.getInt("id");
    handles.add(thread {
      AllStarsClient(config = getConfigFromRemoteApk())
      .getAccount(id)?.let {
        it.loginAndGetGifts()
      } ?: run {
        println("could not load account $id")
      }
    })
  }
  handles.map { it.join() }
}

class Gifts : CliktCommand(
  help = "Log in accounts that haven't been logged in 24+h or that " +
    "haven't completed the tutorial and get gifts"
) {
  val threads: Int by
    option(help = "increase this to login multiple accounts in parallel")
    .int().default(1)
  override fun run() = threadLoop(f = { gifts(threads) }, cooldown = 2000)
}

class Link : CliktCommand(help = "Link a sifid to an account") {
  val id: Int by option(help = "User ID").int().prompt("account id")
  val mail: String by option(help = "sifid.net email")
    .prompt("sifid.net email")
  val password: String by option(help = "sifid.net password")
    .prompt("sifid.net password")
  override fun run() {
    AllStarsClient(config = getConfigFromRemoteApk())
    .getAccount(id)?.let {
      it.linkSifid(mail = mail, password = password)
    } ?: run {
      println("account $id not found")
    }
  }
}

val update: () -> Unit = { getConfigFromRemoteApk(download = true) }

class Update : CliktCommand(help = "Polls apkpure for updates") {
  override fun run() =
    threadLoop(f = update, cooldown = 60000)
}

class Daemon : CliktCommand(help = "Runs everything in parallel") {
  val createThreads: Int by
    option(help = "parallel account creation threads").int().default(4)
  val giftsThreads: Int by
    option(help = "parallel login threads").int().default(4)
  val withBackend: Boolean by
    option("--backend", "-b", help = "enable to host the backend")
      .flag("--no-backend", "-B", default = false)
  override fun run() {
    thread { threadLoop(f = update, cooldown = 60000) }
    repeat(createThreads) {
      thread { threadLoop(f = create, cooldown = 2000) }
    }
    thread {
      threadLoop(
        f = { gifts(giftsThreads) },
        cooldown = 2000
      )
    }
    while (true) {
      try {
        if (withBackend) {
          backend()
        } else {
          Thread.sleep(Long.MAX_VALUE)
        }
      } catch (e: Exception) {
        printException(e)
        Thread.sleep(2000)
      }
    }
  }
}

data class BackendItem(
  val id: Int,
  var amount: Int,
  var name: String? = null,
  var description: String? = null,
  var thumbnailAssetPath: String? = null,
  var packName: String? = null,
  var head: Int? = null
)

data class BackendAccount(
  val id: Int,
  val serviceId: String,
  val authCount: Int,
  val stars: Int,
  val lastLogin: Long,
  val deviceToken: String,
  val deviceName: String,
  val sessionKey: String,
  val sifidMail: String?,
  var items: MutableMap<Int, BackendItem>
)

fun dictionaryGet(s: String): String {
  val split = s.split(".", limit = 2)
  val dictionary = readOnlyDB("assets/dictionary_ja_${split[0]}.db")
  val message = dictionary.executeQuery("""
    select message from m_dictionary where id = '${split[1]}'
  """)
  if (message.next()) {
    return message.getString("message")
  }
  return s
}

fun backend() {
  val asset = readOnlyDB("assets/asset_a_ja_0.db")
  val masterdata = readOnlyDB("assets/masterdata.db")
  val itemCache = mutableMapOf<Int, BackendItem>()
  val defaultGson = GsonBuilder().create()

  val fetchItems: (Statement, BackendAccount) -> Unit = { stmt, account ->
    val items = stmt.executeQuery("""
      select * from items where uid=${account.id}
    """)
    while (items.next()) {
      val id = items.getInt("id")
      if (itemCache.containsKey(id)) {
        val item = itemCache[id]!!.copy()
        item.amount = items.getInt("amount")
        account.items[id] = item
        continue
      }
      var item = BackendItem(
        id = id,
        amount = items.getInt("amount")
      )
      val flds = "select name, description, thumbnail_asset_path from"
      val itemMasterdata = masterdata.executeQuery("""
        $flds m_gacha_ticket where id = $id union
        $flds m_lesson_enhancing_item where id = $id union
        $flds m_training_material where id = $id union
        $flds m_grade_upper where id = $id union
        $flds m_recovery_lp where id = $id union
        $flds m_recovery_ap where id = $id union
        $flds m_accessory_level_up_item where id = $id union
        $flds m_accessory_rarity_up_item where id = $id union
        $flds m_live_skip_ticket where id = $id union
        $flds m_event_marathon_booster_item where id = $id
      """)
      if (itemMasterdata.next()) {
        item.name = dictionaryGet(itemMasterdata.getString("name"))
        item.description =
          dictionaryGet(itemMasterdata.getString("description"))
        item.thumbnailAssetPath =
          itemMasterdata.getString("thumbnail_asset_path")
      }
      val itemAsset = asset.executeQuery("""
        select pack_name, head from texture
        where asset_path = '${item.thumbnailAssetPath}'
      """)
      if (itemAsset.next()) {
        item.packName = itemAsset.getString("pack_name")
        item.head = itemAsset.getInt("head")
      }
      account.items[item.id] = item
      itemCache[item.id] = item
    }
  }

  HttpServer.create(InetSocketAddress(6868), 0).apply {
    val context: (String, (http: HttpExchange) -> Unit) -> Unit =
    { path, f ->
      createContext(path) { http ->
        try { f(http) } catch (e: Exception) {
          printException(e)
          http.sendResponseHeaders(500, 0)
        }
        http.responseBody.close()
      }
    }
    context("/texture") { http ->
      val url = HttpUrl.parse(
        "http://" + http.getRequestHeaders().getFirst("Host") +
        http.getRequestURI()
      )
      val packName = url!!.queryParameter("packName")
      val head = url.queryParameter("head")
      http.responseHeaders.add("Access-Control-Allow-Origin", "*")
      if (packName == null || head == null) {
        http.sendResponseHeaders(404, 0)
      } else {
        http.responseHeaders.add("Content-Type", "image/png")
        http.sendResponseHeaders(200, 0)
        File("assets/texture/${packName}_$head.png")
          .inputStream().copyTo(http.responseBody)
      }
    }
    context("/accounts") { http ->
      // for some reason it doesn't refresh accounts if I don't reopen
      // the connection. might have something to do with WAL mode
      val todokete = readOnlyDB("todokete.db")
      val s = todokete.executeQuery("select * from accounts")
      val results = mutableListOf<BackendAccount>()
      while (s.next()) {
        results.add(BackendAccount(
          id = s.getInt("id"),
          serviceId = s.getString("serviceId"),
          authCount = s.getInt("authCount"),
          lastLogin = s.getLong("lastLogin"),
          deviceToken = s.getString("deviceToken"),
          deviceName = s.getString("deviceName"),
          sessionKey = s.getString("sessionKey"),
          stars = s.getInt("stars"),
          sifidMail = s.getString("sifidMail"),
          items = mutableMapOf()
        ))
      }
      for (account in results) {
        fetchItems(todokete, account)
      }
      http.responseHeaders.add("Content-Type", "application/json")
      http.responseHeaders.add("Access-Control-Allow-Origin", "*")
      http.sendResponseHeaders(200, 0)
      PrintWriter(http.responseBody, true).use {
        defaultGson.toJson(results, it)
      }
    }
    start()
  }
}

class Backend : CliktCommand(help = "Hosts the json back-end, port 6868") {
  override fun run() = backend()
}

class Todokete : CliktCommand() {
  override fun run() = Unit
}

fun main(args: Array<String>) {
  Todokete()
    .subcommands(Create(), Gifts(), Link(), Update(), Daemon(), Backend())
    .main(args)
}
