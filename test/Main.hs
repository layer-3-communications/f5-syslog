{-# language DuplicateRecordFields #-}
{-# language MultiWayIf #-}
{-# language NamedFieldPuns #-}
{-# language TypeApplications #-}

import F5.Syslog (Log(..),SslAccess(..),SslRequest(..),Asm(..),decode)

import Control.Exception (throwIO)
import Data.Primitive (ByteArray)
import Data.Word (Word8)
import Data.Char (ord)
import Data.Bytes.Types (Bytes(Bytes))

import qualified Data.Primitive as PM
import qualified GHC.Exts as Exts
import qualified Net.IPv4 as IPv4
import qualified Sample as S

main :: IO ()
main = do
  putStrLn "Start"
  putStrLn "testSslAccess1"
  testSslAccess1
  putStrLn "testSslRequest1"
  testSslRequest1
  putStrLn "testSslAsm1"
  testAsm1
  putStrLn "testSslAsm2"
  testAsm2
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

bytes :: String -> Bytes
bytes s = let b = pack s in Bytes b 0 (PM.sizeofByteArray b)

pack :: String -> ByteArray
pack = Exts.fromList . map (fromIntegral @Int @Word8 . ord)

