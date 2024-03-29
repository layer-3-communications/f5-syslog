{-# language DuplicateRecordFields #-}
{-# language LambdaCase #-}
{-# language MultiWayIf #-}
{-# language NamedFieldPuns #-}
{-# language TypeApplications #-}

import F5.Syslog (Log(..),SslAccess(..),SslRequest(..),Asm(..),Attribute(..),decode)

import Control.Exception (throwIO)
import Data.Primitive (ByteArray)
import Data.Word (Word8)
import Data.Char (ord)
import Data.Bytes.Types (Bytes(Bytes))

import qualified Data.Primitive as PM
import qualified Data.Bytes as Bytes
import qualified Data.Bytes.Text.Latin1 as Latin1
import qualified GHC.Exts as Exts
import qualified Net.IPv4 as IPv4
import qualified Sample as S

main :: IO ()
main = do
  putStrLn "Start"
  putStrLn "testSslAccess1"
  testSslAccess1
  putStrLn "testSslAccess2"
  testSslAccess2
  putStrLn "testSslRequest1"
  testSslRequest1
  putStrLn "testSslAsm1"
  testAsm1
  putStrLn "testSslAsm2"
  testAsm2
  putStrLn "testSslAsm3"
  testAsm3
  putStrLn "testSslAsm4"
  testAsm4
  putStrLn "End"

testSslAccess1 :: IO ()
testSslAccess1 = case decode S.ssl_access_1 of
  Left err -> throwIO err
  Right (LogSslAccess SslAccess{path,user,responseCode,responseBytes,client,host}) ->
    if | path /= bytes "/iControl/iControlPortal.cgi" -> fail "bad path"
       | user /= bytes "" -> fail "bad user"
       | responseCode /= 200 -> fail "bad response code"
       | responseBytes /= 626 -> fail "bad response bytes"
       | client /= IPv4.fromOctets 127 0 0 1 -> fail "bad client"
       | host /= bytes "SAMPLE-HOST" -> fail "bad host"
       | otherwise -> pure ()
  Right _ -> fail "wrong log type"

testSslAccess2 :: IO ()
testSslAccess2 = case decode S.ssl_access_2 of
  Left err -> throwIO err
  Right (LogSslAccess SslAccess{path,user,responseCode,responseBytes,client,host}) ->
    if | path /= bytes "/foo/bang" -> fail "bad path"
       | user /= bytes "admin" -> fail "bad user"
       | responseCode /= 200 -> fail "bad response code"
       | responseBytes /= 2132 -> fail "bad response bytes"
       | client /= IPv4.fromOctets 192 0 2 167 -> fail "bad client"
       | host /= bytes "EXAMPLE-NYC" -> fail "bad host"
       | otherwise -> pure ()
  Right _ -> fail "wrong log type"

testSslRequest1 :: IO ()
testSslRequest1 = case decode S.ssl_request_1 of
  Left err -> throwIO err
  Right (LogSslRequest SslRequest{path,protocol,cipherSuite}) ->
    if | path /= bytes "/iControl/iControlPortal.cgi" -> fail "bad path"
       | cipherSuite /= bytes "AES256-SHA" -> fail "bad cipher suite"
       | protocol /= bytes "TLSv1" -> fail "bad ssl protocol"
       | otherwise -> pure ()
  Right _ -> fail "wrong log type"

testAsm1 :: IO ()
testAsm1 = case decode S.asm_1 of
  Left err -> throwIO err
  Right (LogAsm Asm{destinationPort}) ->
    if | destinationPort /= 443 -> fail "bad destination port"
       | otherwise -> pure ()
  Right _ -> fail "wrong log type"

testAsm2 :: IO ()
testAsm2 = case decode S.asm_2 of
  Left err -> throwIO err
  Right (LogAsm Asm{destinationPort,responseCode}) ->
    if | destinationPort /= 443 -> fail "bad destination port"
       | responseCode /= 302 -> fail "bad response code"
       | otherwise -> pure ()
  Right _ -> fail "wrong log type"

testAsm3 :: IO ()
testAsm3 = case decode S.asm_3 of
  Left err -> throwIO err
  Right (LogAsmKeyValue pairs) ->
    if | notElem (DestinationPort 443) pairs -> fail "bad destination port"
       | notElem (ResponseCode 200) pairs -> fail "bad response code"
       | notElem (Severity (Latin1.fromString "Informational")) pairs -> fail "bad severity"
       | otherwise -> pure ()
  Right _ -> fail "wrong log type"

testAsm4 :: IO ()
testAsm4 = case decode S.asm_4 of
  Left err -> throwIO err
  Right (LogAsmKeyValue pairs) ->
    if | notElem (DestinationPort 443) pairs -> fail "bad destination port"
       | notElem (ResponseCode 200) pairs -> fail "bad response code"
       | notElem (IpClient (IPv4.fromOctets 192 0 2 65)) pairs -> fail "bad client ip"
       | notElem (Severity (Latin1.fromString "Informational")) pairs -> fail "bad severity"
       | otherwise -> pure ()
  Right _ -> fail "wrong log type"

bytes :: String -> Bytes
bytes s = let b = pack s in Bytes b 0 (PM.sizeofByteArray b)

pack :: String -> ByteArray
pack = Exts.fromList . map (fromIntegral @Int @Word8 . ord)

