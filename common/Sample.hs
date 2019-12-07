{-# language TypeApplications #-}

module Sample
  ( ssl_access_1
  , ssl_request_1
  , asm_1
  ) where

import Data.Bytes (Bytes)
import Data.Word (Word8)
import Data.Char (ord)
import qualified Data.Bytes as Bytes
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
