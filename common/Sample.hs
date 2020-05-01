{-# language OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes #-}
{-# language TypeApplications #-}

module Sample
  ( ssl_access_1
  , ssl_request_1
  , asm_1
  , asm_2
  , asm_3
  , asm_4
  ) where

import Data.Bytes (Bytes)
import Data.Word (Word8)
import Data.Char (ord)
import Data.Text.Encoding (encodeUtf8)
import NeatInterpolation (text)
import qualified Data.Bytes as Bytes
import qualified Data.Text as T
import qualified GHC.Exts as Exts

-- Sample Logs. If you add a sample log to this file, please
-- replace all information in the log that could possibly be
-- meaningful. At a bare minimum, this means:
--
-- * Replace any IP addresses with non-routable addresses 
--   from the TEST-NET-1 block (192.0.2.0/24).
-- * Replace any domain names with the reserved domain
--   name example.com.
-- * Replace any hostnames with something like MY-HOST
--   or NY-APP or SAMPLE-HOST.

pack :: String -> Bytes
pack = Bytes.fromByteArray . Exts.fromList . map (fromIntegral @Int @Word8 . ord)

ssl_access_1 :: Bytes
ssl_access_1 = pack $ concat
  [ "Dec 6 10:02:54 SAMPLE-HOST info logger: "
  , "[ssl_acc] 127.0.0.1 - - [06/Dec/2019:10:02:54 -0600] "
  , "\"/iControl/iControlPortal.cgi\" 200 626"
  ]

ssl_request_1 :: Bytes
ssl_request_1 = pack $ concat
  [ "Nov 13 10:02:54 SAMPLE-HOST info logger: "
  , "[ssl_req][06/Dec/2019:10:02:54 -0600] 127.0.0.1 TLSv1 "
  , "AES256-SHA \"/iControl/iControlPortal.cgi\" 626"
  ]

asm_1 :: Bytes
asm_1 = pack $ concat
  [ "Dec 6 13:14:50 f5.example.com ASM:\"Information Leakage\","
  , "\"2019-12-06 13:14:49\",\"192.0.2.56\",\"443\",\"US\","
  , "\"/path/to/file\",\"N/A\",\"192.0.2.51\",\"192.0.2.117%0\","
  , "\"192.0.2.57\",\"GET\",\"2016-12-31 09:35:53\",\"/path/to/another\","
  , "\"HTTPS\",\"\",\"GET /foo/bar/baz HTTP/1.1\\r\\nHost: example.com"
  , "\\r\\nConnection: keep-alive\\r\\nAccept: text/html,"
  , "application/xhtml+xml,application/xml;q=0.9,*/*;"
  , "q=0.8\\r\\nUser-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 12_3_1 "
  , "like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) "
  , "Version/12.1.1 Mobile/15E148 Safari/604.1\\r\\nAccept-Language: "
  , "en-us\\r\\nReferer: https://www.example.com/foo/bar/fizz.seam?"
  , "cid=24313\\r\\nAccept-Encoding: br, gzip, deflate\\r\\n\\r\\n\","
  , "\"blocked\",\"Only illegal requests are logged\",\"403\",\"0\","
  , "\"2a0276a17b6b7d70\",\"Informational\",\"\",\"\",\"4131\",\"\","
  , "\"15267537619763049516\",\"f5.example.com\",\"/foo/bar/baz\","
  , "\"N/A\",\"\",\"Illegal HTTP status in response\",\"N/A\",\"N/A\""
  ]

asm_2 :: Bytes
asm_2 = pack $ concat
  [ "Dec 15 06:33:48 f5.example.co.uk ASM:\"\","
  , "\"2019-12-15 06:33:48\",\"192.0.2.13\",\"443\",\"US\","
  , "\"/foo/BAR.COM\",\"N/A\",\"192.0.2.35\","
  , "\"192.0.2.67%0\",\"192.0.2.63\",\"GET\",\"2016-12-31 "
  , "09:35:53\",\"/foo/BAR.COM\",\"HTTPS\",\"\","
  , "\"GET /... HTTP/1.1\\r\\nCache-Control: no-cache\\r\\nConnection: "
  , "Keep-Alive\\r\\nPragma: no-cache\\r\\nAccept: */*\\r\\nAccept-Encoding: "
  , "gzip, deflate\\r\\nFrom: bingbot(at)microsoft.com\\r\\nHost: "
  , "www.bar.com\\r\\nUser-Agent: Mozilla/5.0 (compatible; "
  , "bingbot/2.0; +http://www.bing.com/bingbot.htm)\\r\\n\\r\\n\","
  , "\"passed\",\"Only illegal requests are logged\",\"302\",\"0\","
  , "\"50ef75c2d6161201\",\"Informational\",\"\",\"\",\"4331\",\"\","
  , "\"15267537619804775945\",\"f5.example.co.uk\","
  , "\"/...\",\"N/A\",\"\",\"\",\"N/A\",\"N/A\""
  ]

asm_3 :: Bytes
asm_3 = pack $ concat
  [ "<134>Apr 28 06:01:40 FOO-BAR-F5-Appliance.example.com "
  , "ASM:unit_hostname=\"FOO-BAR-F5-Appliance.example.com\","
  , "management_ip_address=\"192.0.2.65\","
  , "http_class_name=\"/path/to/resource\","
  , "web_application_name=\"/path/to/resource\","
  , "policy_name=\"/path/to/resource\","
  , "policy_apply_date=\"2016-12-31 09:35:53\",violations=\"\","
  , "support_id=\"14268534616787439415\",request_status=\"passed\","
  , "response_code=\"200\",ip_client=\"192.0.2.173\",route_domain=\"0\","
  , "method=\"POST\",protocol=\"HTTPS\",query_string=\"\","
  , "x_forwarded_for_header_value=\"N/A\",sig_ids=\"\",sig_names=\"\","
  , "date_time=\"2020-04-28 06:01:40\",severity=\"Informational\","
  , "attack_type=\"\",geo_location=\"US\",ip_address_intelligence=\"N/A\","
  , "username=\"N/A\",session_id=\"fb3gda4a71152d0a\",src_port=\"58030\","
  , "dest_port=\"443\",dest_ip=\"192.0.2.76\",sub_violations=\"\","
  , "virus_name=\"N/A\",uri=\"/the/path\","
  , "request=\"POST /the/path HTTP/1.1\\r\\nHost: www.example.com\\r\\n"
  , "Connection: keep-alive\\r\\nContent-Length: 235\\r\\nUser-Agent: "
  , "Mozilla/5.0 (Linux; Android 9; LM-Q720) AppleWebKit/537.36 (KHTML, "
  , "like Gecko) Chrome/81.0.4044.117 Mobile Safari/537.36\\r\\n"
  , "Content-Type: application/x-www-form-urlencoded; charset=UTF-8\\r\\n"
  , "Accept: */*\\r\\nOrigin: https://www.example.com\\r\\n"
  , "Sec-Fetch-Site: same-origin\\r\\nSec-Fetch-Mode: cors\\r\\n"
  , "Sec-Fetch-Dest: empty\\r\\nReferer: "
  , "https://www.example.com/other/resource/page?foo=bar&baz=1"
  , "\\r\\nAccept-Encoding: gzip, deflate, br\\r\\nAccept-Language: "
  , "en-US,en;q=0.9\\r\\n\\r\\n\""
  , "\r\n" -- Tests that we can handle spurious trailing newlines
  ]

asm_4 :: Bytes
asm_4 = pack $ T.unpack $ T.replace "\n" ""
  [text|
    Oct  1 12:09:21 FOO-BAR-F5-Appliance-X.example.com ASM:unit_hostname=
    "FOO-BAR-F5-Appliance-X.example.com",management_ip_address="192.0.2.13",
    http_class_name="/Foo/Bar.COM",web_application_name=
    "/Foo/Bar.COM",policy_name="/Common/Foo-Bar.COM",
    policy_apply_date="2019-12-31 09:35:53",violations="",support_id=
    "13266532618789046730",request_status="passed",response_code="200",
    ip_client="192.0.2.65",route_domain="0",method="POST",protocol=
    "HTTPS",query_string="",x_forwarded_for_header_value="N/A",sig_ids="",
    sig_names="",date_time="2020-05-01 12:09:21",severity="Informational",
    attack_type="",geo_location="US",ip_address_intelligence="N/A",
    username="N/A",session_id="de25fe518d3c28ed",src_port="6229",
    dest_port="443",dest_ip="192.0.2.54",sub_violations="",virus_name="N/A",
    uri="/buzz",request="POST /buzz HTTP/1.1\r\n
    Accept: */*\r\nContent-Type: application/x-www-form-urlencoded; charset=
    UTF-8\r\nReferer: https://www.example.com/foobar\r\nAccept-Language: en-
    US\r\nAccept-Encoding: gzip, deflate\r\nUser-Agent: Mozilla/
    5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko\r\n
    Host: www.example.com\r\nContent-Length: 89\r\nConnection: Keep-
    Alive\r\nCache-Control: no-cache\r\nCookie: foo=1234; website#
    lang=en;\r\n\r\nmy.param=5&your.param=6\n\n" 
  |]

-- Incomplete Reference Parser
-- 
-- F5-ASM[device_type=F5]: {!alpha} {!digit} {!digit}:{!digit}:{!digit} |
-- {host.name} ASM: "{threat_name}","{!digit}-{!digit}-{!digit} {!digit}:|
-- {!digit}:{!digit}","{destination.ip}","{destination.port}","{!alpha}",|
-- "/Common/HTTP?{S}-{http.domain}","{!drop}","{source.ip}","{!drop}",|
-- "{!drop}","{http.method}","{!digit}-{!digit}-{!digit} {!digit}:{!digit}|
-- :{!digit}","/Common/HTTP?{S}-{!drop}","{http.protocol}","{!drop}",|
-- "{!alpha} {http.path} HTTP?{S}/{http.version}\r\n{!drop}" ," {action}",|
-- "{message}","{http.status_code}","{!drop}","{!drop}","{severity}",|
-- "{!drop}","{!drop}","{source.port}","{!drop}","{!digit}","{!drop}",|
-- "{!drop}","?{N/A}?{{user}}","{!drop}","{http.message}","{threat_name}",|
-- "{!drop}"#{!digit}
