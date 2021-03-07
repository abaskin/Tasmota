/*
  xdrv_40_telegram.ino - telegram for Tasmota

  Copyright (C) 2021  Theo Arends

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifdef USE_TELEGRAM
/*********************************************************************************************\
 * Telegram bot
 *
 * Supported commands:
 * TmToken <token>    - Add your BotFather created bot token (default none)
 * TmChatId <chat_id> - Add your BotFather created bot chat id (default none)
 * TmPoll <seconds>   - Telegram receive poll time (default 10 seconds, limit 4 to 300 seconds)
 * TmState 0          - Disable telegram sending (default)
 * TmState 1          - Enable telegram sending (needs valid TmChatId)
 * TmState 2          - Disable telegram listener (default)
 * TmState 3          - Enable telegram listener
 * TmState 4          - Disable telegram response echo (default)
 * TmState 5          - Enable telegram response echo
 * TmSend <text>      - If telegram sending is enabled AND a chat id is present then send text
 * TmSendJson <json>  - If telegram sending is enabled AND a chat id is present then send json
 *                      which is added to the request json, a text key is required
 *
 * Tested with defines
 * #define USE_TELEGRAM                             // Support for Telegram protocol
 * #define USE_TELEGRAM_FINGERPRINT "\xB2\x72\x47\xA6\x69\x8C\x3C\x69\xF9\x58\x6C\xF3\x60\x02\xFB\x83\xFA\x8B\x1F\x23" // Telegram api.Telegram->org TLS public key fingerpring
\*********************************************************************************************/

#include <time.h>
#include <Ticker.h>
#include "WiFiClientSecureLightBearSSL.h"

#define XDRV_40                    40

#ifndef TELEGRAM_LOOP_WAIT
  #define TELEGRAM_LOOP_WAIT       10
#endif

namespace Xdrv40TelegramBot {
  constexpr uint32_t MinPoll {4};
  constexpr uint32_t MaxPoll {300};

  #ifdef USE_MQTT_TLS_CA_CERT
    constexpr uint32_t tls_rx_size {2048};   // since Telegram CA is bigger than 1024 bytes, we need to increase rx buffer
    constexpr uint32_t tls_tx_size {1024};
  #else
    constexpr uint32_t tls_rx_size {1024};
    constexpr uint32_t tls_tx_size {1024};
  #endif

  constexpr uint8_t Fingerprint[] PROGMEM {USE_TELEGRAM_FINGERPRINT};
  constexpr uint32_t ClientTimeout {1500};

  using  TelegramSetting = struct {
    String token;
    int32_t chatID;
    union {
      uint16_t settingState;
      struct {
        uint16_t poll : 9,          // size based on TELEGRAM_MAX_POLL
                 send_enable : 1,
                 recv_enable : 1,
                 echo_enable : 1;
      };
    };
  };

  using  TelegramData = struct {
    int32_t nextUpdateID;
    bool poll;
    Ticker* tickerPoll;
    BearSSL::WiFiClientSecure_light* client;
  };

  using TelegramMessage = struct {
    int32_t id, chatID;
    String text, event;
  };

  TelegramData* Telegram {nullptr};
  TelegramSetting* Setting {nullptr};
  std::unique_ptr<TelegramMessage> Message;

  Ticker TickerPoll;
  auto tickerPollFunction = [](){ Telegram->poll = true; };

  /*********************************************************************************************\
   * JSON Generator for Objects
  \*********************************************************************************************/
  class TelegramJsonGeneratorObject : public JsonGeneratorObject {
    public:
      template<typename T>
      void replace(const T newVal) { val = newVal; }
  };

  /*********************************************************************************************\
   * Namespace Forward Declarations
  \*********************************************************************************************/

  void InitFromSettings(void);
  void TelegramInit(void);

  size_t TelegramRequest(const __FlashStringHelper* command, const char* body);
  void TelegramResponse(char* buffer, const size_t contentLength);

  void GetUpdates(void);
  bool SendMessage(const int32_t chatID, const char* text, const char* json);

  void Poll(void);
  void Process(void);

  void CmndTmState(void);
  void CmndTmPoll(void);
  void CmndTmPollStatus(void);
  void CmndTmChatId(void);
  void CmndTmToken(void);
  void CmndTmSend(void);
  void CmndTmSendJson(void);

  void updateSettings(void);
  void doCmndSend(const char* text, const char* json);

  #ifdef TELEGRAM_EXEC_CMND
    String ExecuteCommand(void);
  #endif

/*********************************************************************************************\
 * Read Setting and Initialize
\*********************************************************************************************/

  inline void InitFromSettings(void) {
    // copy the settings buffer so we can modify it
    char json[strlen(SettingsText(SET_TELEGRAM_TOKEN)) + 1];
    strcpy(json, SettingsText(SET_TELEGRAM_TOKEN));

    JsonParser parser(json);
    auto root = parser.getRootObject();

    if (root) {
      Setting = new TelegramSetting {
        .token = root[F("t")].getStr(),
        .chatID = root[F("c")].getInt(),
      };
      Setting->settingState = root[F("s")].getUInt();

      AddLog_P(LOG_LEVEL_INFO, PSTR("TGM: Read Settings"));
    } else {
      Setting = new TelegramSetting {
        .token = SettingsText(SET_TELEGRAM_TOKEN),
        .chatID =  atoi(SettingsText(SET_TELEGRAM_CHATID)),
      };
      Setting->settingState = TELEGRAM_LOOP_WAIT;
      updateSettings();

      AddLog_P(LOG_LEVEL_INFO,
        (!Setting->token.isEmpty() || Setting->chatID != 0)
          ? PSTR("TGM: Existing setting migrated")
          : PSTR("TGM: No setting found"));
    }

    if (Setting->recv_enable ||
        Setting->echo_enable ||
        Setting->send_enable) {
      TelegramInit();
    }
  }

  void TelegramInit(void) {
    Telegram = new TelegramData {
      .nextUpdateID = 0,
      .poll = false,
      .tickerPoll = new Ticker,
      .client = new BearSSL::WiFiClientSecure_light {tls_rx_size, tls_tx_size},
    };

    Telegram->tickerPoll->attach((float)Setting->poll, tickerPollFunction);

  #ifdef USE_MQTT_TLS_CA_CERT
    Telegram->client->setTrustAnchor(&GoDaddyCAG2_TA, 1);
  #else
    Telegram->client->setPubKeyFingerprint(Fingerprint, Fingerprint, false); // check server fingerprint
  #endif
    Telegram->client->setTimeout(ClientTimeout);

    AddLog_P(LOG_LEVEL_INFO, PSTR("TGM: Started"));
  }

/*********************************************************************************************\
 * Connect to Telegram
\*********************************************************************************************/

  size_t TelegramRequest(const __FlashStringHelper* method, const char* body) {
    // AddLog_P(LOG_LEVEL_DEBUG, PSTR("TGM: Method %s"), method);
    // AddLog_P(LOG_LEVEL_DEBUG, PSTR("TGM: Body %s"), body.c_str());

    // change api.telegram.org in header as well
    if (Setting->token.isEmpty() || !Telegram->client->connect("api.telegram.org", 443)) {
      return 0;
    }

    AddLog_P(LOG_LEVEL_DEBUG, PSTR("TGM: Connected"));

    // uint32_t tls_connect_time = millis();
    // AddLog_P(LOG_LEVEL_DEBUG, PSTR("TGM: Connected in %d ms, max ThunkStack used %d"), millis() - tls_connect_time, Telegram->client->getMaxThunkStackUse());

    Telegram->client->print(F("POST /bot"));
    Telegram->client->print(Setting->token);
    Telegram->client->print(method);
    Telegram->client->println(F(" HTTP/1.1"));
    Telegram->client->println(F("Host: api.telegram.org"));
    Telegram->client->println(F("Content-Type: application/json"));
    Telegram->client->print(F("Content-Length: "));
    Telegram->client->println(strlen(body));
    Telegram->client->println();

    Telegram->client->println(body);

    size_t contentLength {0};
    String line {(char*) nullptr};
    line.reserve(100);
    while (Telegram->client->connected()) {
      line = Telegram->client->readStringUntil('\n');
      if (line == "\r") { break; }
      if (line.startsWith(F("Content-Length:"))) {
        line = line.substring(line.indexOf(F(":")) + 1);
        line.trim();
        contentLength = line.toInt();
      }
    }

    if (contentLength == 0) { Telegram->client->stop(); }

    return contentLength;
  }

  void TelegramResponse(char* buffer, const size_t contentLength) {
    if (!Telegram->client->connected()) { return; }

    uint32_t offset {0};
    while (Telegram->client->available()) {
      offset = Telegram->client->read((uint8_t*)buffer + offset, contentLength - offset);
    }

    Telegram->client->stop();
  }

/*********************************************************************************************\
 * Get Updates (received messages)
\*********************************************************************************************/

  inline void GetUpdates(void) {
    AddLog_P(LOG_LEVEL_DEBUG, PSTR("TGM: getUpdates, offset: %d"), Telegram->nextUpdateID);

    PGM_P getBody =
      PSTR(R"({"limit":1,"allowed_updates":["message","callback_query"],"offset":%d})");

    char body[strlen_P(getBody) + 12];
    sprintf_P(body, getBody, Telegram->nextUpdateID);

    auto contentLength = TelegramRequest(F("/getUpdates"), body);
    char response[contentLength + 1];
    memset(response, '\0', sizeof(response));
    TelegramResponse(response, contentLength);

    // make a copy of the response for the event to use
    String fullResponse {response};

    // AddLog_P(LOG_LEVEL_DEBUG, PSTR("TGM: response: %s"), fullResponse.c_str());

    // this will modify response
    JsonParser parser(response);
    auto root = parser.getRootObject();

    if (!root || root[PSTR("ok")].getBool() == false) {
       AddLog_P(LOG_LEVEL_DEBUG, PSTR("TGM: getUpdates Failed"));
       return;
    }

    auto result = root[PSTR("result")].getArray()[0].getObject();
    if (!result) {
      AddLog_P(LOG_LEVEL_DEBUG, PSTR("TGM: No new messages"));
      return;
    }

    Telegram->nextUpdateID = result[PSTR("update_id")].getInt() + 1;  // set the id for the next message

    if (result[PSTR("message")].isObject()) {
      Message.reset(new TelegramMessage {
        .id = result[PSTR("message")].getObject()[PSTR("message_id")].getInt(),
        .chatID = result[PSTR("message")].getObject()[PSTR("chat")].getObject()[PSTR("id")].getInt(),
        .text = result[PSTR("message")].getObject()[PSTR("text")].getStr(),
      });
    }

    if (result[PSTR("callback_query")].isObject()) {
      Message.reset(new TelegramMessage {
        .id = result[PSTR("callback_query")].getObject()[PSTR("message")].getObject()[PSTR("message_id")].getInt(),
        .chatID = result[PSTR("callback_query")].getObject()[PSTR("message")].getObject()[PSTR("chat")].getObject()[PSTR("id")].getInt(),
        .text = result[PSTR("callback_query")].getObject()[PSTR("data")].getStr(),
      });
    }

    if (!Message) { return; }   // should never happen, but to be safe

    AddLog_P(LOG_LEVEL_DEBUG_MORE, PSTR(R"(TGM: Parsed update_id: %d, chatID: %d, text: "%s")"),
             Telegram->nextUpdateID - 1, Message->chatID, Message->text.c_str());

    Message->event = F(R"({"Telegram":)");
    Message->event.concat(fullResponse.substring(fullResponse.indexOf("[") + 1, fullResponse.lastIndexOf("]")));
    Message->event.concat(F("}"));
  }

/*********************************************************************************************\
 * Send Message
\*********************************************************************************************/

  bool SendMessage(const int32_t chatID, const char* text, const char* json) {
    AddLog_P(LOG_LEVEL_DEBUG_MORE, PSTR("TGM: sendMessage"));

    TelegramJsonGeneratorObject body;

    if (json != nullptr) { body.replace(json); }
    if (text != nullptr) { body.add("text", text); }

    body.add("chat_id", chatID);

    auto contentLength = TelegramRequest(F("/sendMessage"), body.toString().c_str());
    char response[contentLength + 1];
    memset(response, '\0', sizeof(response));
    TelegramResponse(response, contentLength);

    JsonParser parser(response);
    auto root = parser.getRootObject();

    if (!root || root[PSTR("ok")].getBool() == false) {
      AddLog_P(LOG_LEVEL_DEBUG, PSTR("TGM: Message send failed"));
      return false;
    }

    AddLog_P(LOG_LEVEL_DEBUG, PSTR("TGM: Message sent"));
    return true;
  }

/*********************************************************************************************\
 * Execute Command
\*********************************************************************************************/

  #ifdef TELEGRAM_EXEC_CMND
  String ExecuteCommand(void) {
    uint32_t index {TasmotaGlobal.log_buffer_pointer};
    TasmotaGlobal.templog_level = LOG_LEVEL_INFO;

    ExecuteCommand(Message->text.c_str(), SRC_CHAT);

    char* line;
    size_t len;
    String response {F("{")};
    while (GetLog(TasmotaGlobal.templog_level, &index, &line, &len)) {
      // [14:49:36.123 MQTT: stat/wemos5/RESULT = {"POWER":"OFF"}] > [{"POWER":"OFF"}]
      char* JSON = (char*)memchr(line, '{', len);
      if (JSON) {  // Is it a JSON message (and not only [15:26:08 MQT: stat/wemos5/POWER = O])
        size_t JSONlen = min(len - (JSON - line), sizeof(TasmotaGlobal.mqtt_data));
        char stemp[JSONlen];
        strlcpy(stemp, JSON +1, JSONlen -2);
        response.concat(stemp);
        response.concat(F(","));
      }
    }
    response.concat(F("}"));
    response.replace(F(",}"), F("}"));

    TasmotaGlobal.templog_level = 0;

    return response;
  }
  #endif

/*********************************************************************************************\
 * Poll and Process
\*********************************************************************************************/

  inline void Poll(void) {
    if ((!Setting->recv_enable && !Setting->echo_enable) ||
        !Telegram->poll) { return; }

    Telegram->poll = false;

    if (TasmotaGlobal.global_state.network_down) { return; }

    GetUpdates();
  }

  inline void Process(void) {
    if (!Message) { return; }

    if (Setting->echo_enable) {
      SendMessage(Message->chatID, Message->text.c_str(), nullptr);
    }

    if (Setting->recv_enable) {
      TelegramJsonGeneratorObject body;
      body.replace(F(R"({"type":"event"})"));
      body.add("chat_id", Message->chatID);
      body.add("message_id", Message->id);
      body.add("text", Message->text);
      body.addStrRaw("serviced", (RulesProcessEvent((char*)Message->event.c_str())) ? "true" : "false");

      SendMessage(Message->chatID, body.toString().c_str(), nullptr);

    #ifdef TELEGRAM_EXEC_CMND
      SendMessage(Message->chatID, ExecuteCommand().c_str(), nullptr);
    #endif
    }

    Message.reset(nullptr);
  }

/*********************************************************************************************\
 * Commands
\*********************************************************************************************/

  #define D_CMND_TMSTATE "State"
  #define D_CMND_TMPOLL "Poll"
  #define D_CMND_TMSEND "Send"
  #define D_CMND_TMSENDJSON "SendJson"
  #define D_CMND_TMTOKEN "Token"
  #define D_CMND_TMCHATID "ChatId"

  const char kCommands[] PROGMEM = "Tm|"  // Prefix
    D_CMND_TMSTATE "|" D_CMND_TMPOLL "|" D_CMND_TMTOKEN "|" D_CMND_TMCHATID "|"
    D_CMND_TMSEND "|" D_CMND_TMSENDJSON;

  void (* const Command[])(void) PROGMEM = {
    &CmndTmState, &CmndTmPoll, &CmndTmToken, &CmndTmChatId,
    &CmndTmSend, &CmndTmSendJson
  };

  void CmndTmState(void) {
    if (XdrvMailbox.data_len > 0) {
      switch (XdrvMailbox.payload) {
        case 0: // Off
        case 1: // On
          Setting->send_enable = bitRead(XdrvMailbox.payload, 0);
          break;
        case 2: // Off
        case 3: // On
          Setting->recv_enable = bitRead(XdrvMailbox.payload, 0);
          break;
        case 4: // Off
        case 5: // On
          Setting->echo_enable = bitRead(XdrvMailbox.payload, 0);
          break;
        default:
          break;
      }
      updateSettings();
    }

    if (Telegram == nullptr &&
        (Setting->recv_enable ||
         Setting->echo_enable ||
         Setting->echo_enable)) {
      TelegramInit();
    }

    snprintf_P (TasmotaGlobal.mqtt_data, sizeof(TasmotaGlobal.mqtt_data),
                PSTR(R"({"%s":{"Send":"%s","Receive":"%s","Echo":"%s","Poll":%d}})"),
                XdrvMailbox.command,
                GetStateText(Setting->send_enable),
                GetStateText(Setting->recv_enable),
                GetStateText(Setting->echo_enable),
                Setting->poll);
  }

  void CmndTmPoll(void) {
    if (XdrvMailbox.data_len > 0) {
      Setting->poll = constrain(XdrvMailbox.payload, MinPoll, MaxPoll);
      updateSettings();

      if (Telegram != nullptr) {
        Telegram->tickerPoll->detach();
        Telegram->tickerPoll->attach((float)Setting->poll, tickerPollFunction);
      }
    }

    ResponseCmndNumber(Setting->poll);
  }

  void CmndTmChatId(void) {
    if (XdrvMailbox.data_len > 0) {
      Setting->chatID = (XdrvMailbox.data[0] == '"') ? 0 : atoi(XdrvMailbox.data);
      updateSettings();
    }

    ResponseCmndNumber(Setting->chatID);
  }

  void CmndTmToken(void) {
    if (XdrvMailbox.data_len > 0) {
      Setting->token = (XdrvMailbox.data[0] == '"') ? "" : XdrvMailbox.data;
      updateSettings();
    }

    ResponseCmndChar(Setting->token.c_str());
  }

  void updateSettings(void) {
    JsonGeneratorObject json;
    json.add("t", Setting->token);
    json.add("c", Setting->chatID);
    json.add("s", Setting->settingState);

    SettingsUpdateText(SET_TELEGRAM_TOKEN, json.toString().c_str());
  }

  void CmndTmSend(void) { doCmndSend(XdrvMailbox.data, nullptr); }
  void CmndTmSendJson(void) { doCmndSend(nullptr, XdrvMailbox.data); }

  void doCmndSend(const char* text, const char* json) {
    if (!Setting->send_enable ||
        !SendMessage(Setting->chatID, text, json)) {
      ResponseCmndChar(D_JSON_FAILED);
      return;
    }

    ResponseCmndDone();
  }
} // namespace Xdrv40TelegramBot

/*********************************************************************************************\
 * Interface
\*********************************************************************************************/

bool Xdrv40(uint8_t function)
{
  bool result {false};

  switch (function) {
    case FUNC_INIT:
      Xdrv40TelegramBot::InitFromSettings();
      break;
    case FUNC_LOOP:
      Xdrv40TelegramBot::Process();
      break;
    case FUNC_EVERY_250_MSECOND:
      Xdrv40TelegramBot::Poll();
      break;
    case FUNC_COMMAND:
      result = DecodeCommand(Xdrv40TelegramBot::kCommands, Xdrv40TelegramBot::Command);
      break;
  }
  return result;
}

/*
void TelegramSendGetMe(void) {
  AddLog_P(LOG_LEVEL_DEBUG_MORE, PSTR("TGM: getMe"));

  String command = F("/getMe");
  String response = TelegramConnectToTelegram(command);

  // {"ok":true,"result":{"id":1179906608,"is_bot":true,"first_name":"Tasmota","username":"tasmota_bot","can_join_groups":true,"can_read_all_group_messages":false,"supports_inline_queries":false}}

//  AddLog_P(LOG_LEVEL_DEBUG_MORE, PSTR("TGM: Response %s"), response.c_str());
}
*/
#endif  // USE_TELEGRAM

// Example update messages
// {"ok":true,"result":[]}
// or
// {"ok":true,"result":[
//  {"update_id":973125394,
//   "message":{"message_id":25,
//              "from":{"id":139920293,"is_bot":false,"first_name":"Theo","last_name":"Arends","username":"tjatja","language_code":"nl"},
//              "chat":{"id":139920293,"first_name":"Theo","last_name":"Arends","username":"tjatja","type":"private"},
//              "date":1591877503,
//              "text":"M1"
//             }
//  }
// ]}
// or
// {"ok":true,"result":[
//  {"update_id":973125396,
//   "message":{"message_id":29,
//              "from":{"id":139920293,"is_bot":false,"first_name":"Theo","last_name":"Arends","username":"tjatja","language_code":"nl"},
//              "chat":{"id":139920293,"first_name":"Theo","last_name":"Arends","username":"tjatja","type":"private"},
//              "date":1591879753,
//              "text":"/power toggle",
//              "entities":[{"offset":0,"length":6,"type":"bot_command"}]
//             }
//  }
// ]}
// or
// {"ok":true,"result":[
//  {"update_id":14354460,
//   "message":{"message_id":164,
//              "from":{"id":139920293,"is_bot":false,"first_name":"Theo","last_name":"Arends","username":"tjatja","language_code":"nl"},
//              "chat":{"id":139920293,"first_name":"Theo","last_name":"Arends","username":"tjatja","type":"private"},
//              "date":1602428727,
//              "text":"Status 1"
//             }
//  }
// ]}
