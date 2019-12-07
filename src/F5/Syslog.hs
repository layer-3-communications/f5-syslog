{-# language BangPatterns #-}
{-# language DerivingStrategies #-}
{-# language DeriveAnyClass #-}
{-# language DuplicateRecordFields #-}
{-# language LambdaCase #-}
{-# language NamedFieldPuns #-}

module F5.Syslog
  ( Log(..)
  , Asm(..)
  , SslRequest(..)
  , SslAccess(..)
  , decode
  ) where

import Control.Exception (Exception)
import Data.Builder.ST (Builder)
import Data.Bytes.Types (Bytes(Bytes))
import Data.Bytes.Parser (Parser,Result(Success,Failure),Slice(Slice))
import Data.Chunks (Chunks)
import Data.Word (Word16,Word64)
import Net.Types (IPv4)

import qualified Net.IPv4 as IPv4
import qualified Data.Builder.ST as Builder
import qualified Data.Bytes.Parser as P
import qualified Data.Bytes.Parser.Latin as Latin
import qualified Data.Bytes.Parser.Unsafe as Unsafe

data Log
  = LogSslRequest SslRequest
  | LogSslAccess SslAccess
  | LogAsm Asm

data Asm = Asm
  { destinationIp :: {-# UNPACK #-} !IPv4
  , destinationPort :: {-# UNPACK #-} !Word16
  , sourceIp :: {-# UNPACK #-} !IPv4
  , requestMethod :: {-# UNPACK #-} !Bytes
  , scheme :: {-# UNPACK #-} !Bytes
    -- ^ Examples: @HTTP@, @HTTPS@
  , headers :: !(Chunks Header)
  , action :: {-# UNPACK #-} !Bytes
  , responseCode :: {-# UNPACK #-} !Word64
  , requestTarget :: {-# UNPACK #-} !Bytes
  }

-- | The fields of a log of the form:
--
-- > info logger: [ssl_req][06/Dec/2019:10:02:54 -0600] 127.0.0.1 TLSv1 AES256-SHA "/iControl/iControlPortal.cgi" 626
data SslRequest = SslRequest
  { protocol :: {-# UNPACK #-} !Bytes
    -- ^ Examples: @TLSv1@
  , cipherSuite :: {-# UNPACK #-} !Bytes
    -- ^ Examples: @AES256-SHA@
  , path :: {-# UNPACK #-} !Bytes
    -- ^ Examples: @/iControl/iControlPortal.cgi@
  }

-- | The fields of a log of the form:
--
-- > info logger: [ssl_acc] 127.0.0.1 - - [06/Dec/2019:10:02:54 -0600] "/iControl/iControlPortal.cgi" 200 626
data SslAccess = SslAccess
  { path :: {-# UNPACK #-} !Bytes
    -- ^ Examples: @/iControl/iControlPortal.cgi@
  , user :: {-# UNPACK #-} !Bytes
    -- ^ Examples: @admin@, a hyphen becomes the empty string
  , responseCode :: {-# UNPACK #-} !Word64
    -- ^ Examples: 200, 404
  , responseBytes :: {-# UNPACK #-} !Word64
    -- ^ Examples: 672
  , client :: {-# UNPACK #-} !IPv4
    -- ^ Examples: 127.0.0.1
  , host :: {-# UNPACK #-} !Bytes
    -- ^ Examples: @lb.example.com@, @F5-Appliance-A@
  }

data Header = Header
  { name :: {-# UNPACK #-} !Bytes
  , value :: {-# UNPACK #-} !Bytes
  }

data Error
  = AsmDatetime
  | ClientEndOfInput
  | CountryEndOfInput
  | EncounteredLeftovers
  | HostEndOfInput
  | HttpPath
  | HttpTimestamp
  | LeadingDatetimeDay
  | LeadingDatetimeHour
  | LeadingDatetimeMinute
  | LeadingDatetimeMonth
  | LeadingDatetimeSecond
  | MalformedAction
  | MalformedApplianceIp
  | MalformedClientIdentity
  | MalformedClientIp
  | MalformedDestinationIp
  | MalformedDestinationPort
  | MalformedHeaderName
  | MalformedHeaderValue
  | MalformedHttpPath
  | MalformedHttpRequestMethod
  | MalformedHttpVersion
  | MalformedMethod
  | MalformedRequestTarget
  | MalformedResponseCode
  | MalformedScheme
  | MalformedSecondarySourceIp
  | MalformedSecondaryTimestamp
  | MalformedSourceIp
  | MissingIdentifier
  | MissingNewlineAfterHeader
  | MissingNewlineAfterLastHeader
  | PathDomainEndOfInput
  | ResponseBytes
  | ResponseCode
  | SecondaryPathDomainEndOfInput
  | SslCipherSuite
  | SslProtocol
  | ThreatEndOfInput
  | UnknownFieldA
  | UnknownFieldB
  | UnknownFieldC
  | UnknownFieldD
  | UnknownFieldE
  | UnknownFieldF
  | UnknownFieldG
  | UnknownFieldH
  | UnknownFieldI
  | UnknownFieldJ
  | UnknownFieldK
  | UnknownFieldL
  | UnknownFieldM
  | UnknownFieldN
  | UnknownFieldO
  | UnknownFieldP
  | UnknownFieldQ
  | UnrecognizedIdentifier
  deriving stock (Show)
  deriving anyclass (Exception)

decode :: Bytes -> Either Error Log
decode b = case P.parseBytes parser b of
  -- TODO: switch to parseBytesEither once it is released
  P.Failure e -> Left e
  P.Success (Slice _ _ r) -> Right r

parser :: Parser Error s Log
parser = do
  skipInitialDate
  !host <- P.takeTrailedBy HostEndOfInput 0x20 -- space
  Latin.any MissingIdentifier >>= \case
    'i' -> do
      Latin.char3 UnrecognizedIdentifier 'n' 'f' 'o'
      Latin.char UnrecognizedIdentifier ' '
      Latin.char7 UnrecognizedIdentifier 'l' 'o' 'g' 'g' 'e' 'r' ':'
      Latin.char UnrecognizedIdentifier ' '
      Latin.char5 UnrecognizedIdentifier '[' 's' 's' 'l' '_'
      Latin.any MissingIdentifier >>= \case
        'r' -> do
          Latin.char3 UnrecognizedIdentifier 'e' 'q' ']'
          parserSslRequest host
        'a' -> do
          Latin.char4 UnrecognizedIdentifier 'c' 'c' ']' ' '
          parserSslAccess host
        _ -> P.fail UnrecognizedIdentifier
    'A' -> do
      Latin.char4 UnrecognizedIdentifier 'S' 'M' ':' '"'
      parserAsm host
    _ -> P.fail UnrecognizedIdentifier

parserAsm :: Bytes -> Parser Error s Log
parserAsm !host = do
  P.takeTrailedBy ThreatEndOfInput 0x22 -- double quote
  Latin.char2 ThreatEndOfInput ',' '"'
  -- Skip the datetime
  Latin.skipTrailedBy AsmDatetime '"'
  Latin.char2 AsmDatetime ',' '"'
  destinationIp <- IPv4.parserUtf8Bytes MalformedDestinationIp
  quoteCommaQuote MalformedDestinationIp
  destinationPort <- Latin.decWord16 MalformedDestinationPort
  quoteCommaQuote MalformedDestinationPort
  skipPlainField CountryEndOfInput
  skipPlainField PathDomainEndOfInput
  skipPlainField UnknownFieldA
  sourceIp <- IPv4.parserUtf8Bytes MalformedSourceIp
  quoteCommaQuote MalformedSourceIp
  skipPlainField MalformedSecondarySourceIp -- has percent zero at end, weird
  skipPlainField MalformedApplianceIp
  requestMethod <- takePlainField MalformedMethod
  skipAsmDatetime
  quoteCommaQuote MalformedSecondaryTimestamp
  skipPlainField SecondaryPathDomainEndOfInput
  scheme <- takePlainField MalformedScheme
  skipPlainField UnknownFieldB
  -- Now the big one, the HTTP request and headers.
  -- We skip the request method since it showed up earlier
  Latin.skipTrailedBy MalformedHttpRequestMethod ' '
  -- We skip the path since it shows up later
  Latin.skipTrailedBy MalformedHttpPath ' '
  -- Skip the HTTP version
  Latin.char5 MalformedHttpVersion 'H' 'T' 'T' 'P' '/'
  match isDigit MalformedHttpVersion
  Latin.char MalformedHttpVersion '.'
  match isDigit MalformedHttpVersion
  Latin.char4 MalformedHttpVersion '\\' 'r' '\\' 'n'
  -- Parse all the headers
  headers <- allHeaders =<< P.effect Builder.new
  quoteCommaQuote MalformedAction
  action <- takePlainField MalformedAction
  skipPlainField UnknownFieldC
  responseCode <- Latin.decWord64 MalformedResponseCode
  quoteCommaQuote MalformedAction
  skipPlainField UnknownFieldD
  skipPlainField UnknownFieldE
  skipPlainField UnknownFieldF
  skipPlainField UnknownFieldG
  skipPlainField UnknownFieldH
  skipPlainField UnknownFieldI
  skipPlainField UnknownFieldJ
  skipPlainField UnknownFieldK
  skipPlainField UnknownFieldL -- F5 hostname
  requestTarget <- takePlainField MalformedRequestTarget
  skipPlainField UnknownFieldM
  skipPlainField UnknownFieldN
  skipPlainField UnknownFieldO
  skipPlainField UnknownFieldP
  Latin.skipTrailedBy UnknownFieldQ '"'
  pure $ LogAsm $ Asm
    { destinationIp , destinationPort , sourceIp
    , requestMethod , scheme , headers , action
    , responseCode , requestTarget
    }

allHeaders :: Builder s Header -> Parser Error s (Chunks Header)
allHeaders !b0 = Latin.trySatisfy (== '\\') >>= \case
  True -> do
    Latin.char3 MissingNewlineAfterLastHeader 'r' '\\' 'n'
    P.effect (Builder.freeze b0)
  False -> do
    !hdr <- oneHeader
    b1 <- P.effect (Builder.push hdr b0)
    allHeaders b1

oneHeader :: Parser Error s Header
oneHeader = do
  name <- P.takeTrailedBy MalformedHeaderName 0x3A -- colon
  Latin.skipChar ' '
  value <- P.takeTrailedBy MalformedHeaderValue 0x5C -- backslash
  Latin.char3 MissingNewlineAfterHeader 'r' '\\' 'n'
  pure Header{name,value}

skipPlainField :: e -> Parser e s ()
skipPlainField e = do
  Latin.skipTrailedBy e '"'
  Latin.char2 e ',' '"'

takePlainField :: e -> Parser e s Bytes
takePlainField e = do
  r <- P.takeTrailedBy e 0x22 -- double quote
  Latin.char2 e ',' '"'
  pure r

quoteCommaQuote :: e -> Parser e s ()
quoteCommaQuote e =
  Latin.char3 e '"' ',' '"'

parserSslAccess :: Bytes -> Parser Error s Log
parserSslAccess !host = do
  client <- IPv4.parserUtf8Bytes MalformedClientIp
  Latin.char MalformedClientIp ' '
  -- Client identity from identd is never used.
  Latin.char2 MalformedClientIdentity '-' ' '
  user <- Latin.trySatisfy (== '-') >>= \case
    True -> do
      Latin.char ClientEndOfInput ' '
      emptyBytes
    False -> P.takeTrailedBy ClientEndOfInput 0x20
  Latin.char HttpTimestamp '['
  Latin.skipTrailedBy HttpTimestamp ']'
  Latin.char HttpTimestamp ' '
  Latin.char HttpPath '"'
  path <- P.takeTrailedBy HttpPath 0x22 -- double quote
  Latin.char HttpPath ' '
  responseCode <- Latin.decWord64 ResponseCode
  Latin.char ResponseCode ' '
  responseBytes <- Latin.decWord64 ResponseBytes
  P.endOfInput EncounteredLeftovers
  pure (LogSslAccess (SslAccess {path,user,responseCode,responseBytes,client,host}))

parserSslRequest :: Bytes -> Parser Error s Log
parserSslRequest !host = do
  -- Skip the datetime information
  Latin.char HttpTimestamp '['
  Latin.skipTrailedBy HttpTimestamp ']'
  Latin.char HttpTimestamp ' '
  _ <- IPv4.parserUtf8Bytes MalformedClientIp
  Latin.char MalformedClientIp ' '
  protocol <- P.takeTrailedBy SslProtocol 0x20 -- space
  cipherSuite <- P.takeTrailedBy SslCipherSuite 0x20 -- space
  Latin.char HttpPath '"'
  path <- P.takeTrailedBy HttpPath 0x22 -- double quote
  Latin.char HttpPath ' '
  _ <- Latin.decWord64 ResponseBytes
  P.endOfInput EncounteredLeftovers
  pure (LogSslRequest (SslRequest {protocol,cipherSuite,path}))

emptyBytes :: Parser e s Bytes
emptyBytes = do
  arr <- Unsafe.expose
  pure (Bytes arr 0 0)

-- The initial datetime is formatted like this: Dec 6 10:04:50.
-- It is always missing the year. This consumes a trailing space.
skipInitialDate :: Parser Error s ()
skipInitialDate = do
  match isUpper LeadingDatetimeMonth
  match isLower LeadingDatetimeMonth
  match isLower LeadingDatetimeMonth
  Latin.char LeadingDatetimeMonth ' '
  Latin.skipDigits1 LeadingDatetimeDay
  Latin.char LeadingDatetimeDay ' '
  match isDigit LeadingDatetimeHour
  match isDigit LeadingDatetimeHour
  Latin.char LeadingDatetimeHour ':'
  match isDigit LeadingDatetimeMinute
  match isDigit LeadingDatetimeMinute
  Latin.char LeadingDatetimeMinute ':'
  match isDigit LeadingDatetimeSecond
  match isDigit LeadingDatetimeSecond
  Latin.char LeadingDatetimeSecond ' '

-- The standard YYYY-MM-DD HH:mm:SS format.
skipAsmDatetime :: Parser Error s ()
skipAsmDatetime = do
  match isDigit MalformedSecondaryTimestamp
  match isDigit MalformedSecondaryTimestamp
  match isDigit MalformedSecondaryTimestamp
  match isDigit MalformedSecondaryTimestamp
  Latin.char MalformedSecondaryTimestamp '-'
  match isDigit MalformedSecondaryTimestamp
  match isDigit MalformedSecondaryTimestamp
  Latin.char MalformedSecondaryTimestamp '-'
  match isDigit MalformedSecondaryTimestamp
  match isDigit MalformedSecondaryTimestamp
  Latin.char MalformedSecondaryTimestamp ' '
  match isDigit MalformedSecondaryTimestamp
  match isDigit MalformedSecondaryTimestamp
  Latin.char MalformedSecondaryTimestamp ':'
  match isDigit MalformedSecondaryTimestamp
  match isDigit MalformedSecondaryTimestamp
  Latin.char MalformedSecondaryTimestamp ':'
  match isDigit MalformedSecondaryTimestamp
  match isDigit MalformedSecondaryTimestamp

isUpper :: Char -> Bool
isUpper c = c >= 'A' && c <= 'Z'

isLower :: Char -> Bool
isLower c = c >= 'a' && c <= 'z'

isDigit :: Char -> Bool
isDigit c = c >= '0' && c <= '9'

match :: (Char -> Bool) -> Error -> Parser Error s ()
{-# inline match #-}
match p e = do
  c <- Latin.any e
  case p c of
    True -> pure ()
    False -> P.fail e
