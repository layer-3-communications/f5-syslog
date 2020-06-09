{-# language BangPatterns #-}
{-# language DerivingStrategies #-}
{-# language DeriveAnyClass #-}
{-# language DuplicateRecordFields #-}
{-# language LambdaCase #-}
{-# language MagicHash #-}
{-# language NamedFieldPuns #-}

module F5.Syslog
  ( Log(..)
  , Asm(..)
  , SslRequest(..)
  , SslAccess(..)
  , Attribute(..)
  , Header(..)
  , decode
  ) where

import Control.Exception (Exception)
import Data.Builder.ST (Builder)
import Data.Bytes.Types (Bytes(Bytes))
import Data.Bytes.Parser (Parser,Result(Success,Failure),Slice(Slice))
import Data.Chunks (Chunks)
import Data.Word (Word16,Word64)
import GHC.Exts (Ptr(Ptr))
import Net.Types (IPv4)

import qualified Net.IPv4 as IPv4
import qualified Data.Builder.ST as Builder
import qualified Data.Bytes as Bytes
import qualified Data.Bytes.Parser as P
import qualified Data.Bytes.Parser.Latin as Latin
import qualified Data.Bytes.Parser.Unsafe as Unsafe

data Log
  = LogSslRequest SslRequest
  | LogSslAccess SslAccess
  | LogAsm Asm
  | LogAsmKeyValue (Chunks Attribute)

data Attribute
  = Action {-# UNPACK #-} !Bytes
  | AttackType {-# UNPACK #-} !Bytes
  | DestinationIp {-# UNPACK #-} !IPv4 -- ^ The F5 IP address, not the server IP address.
  | DestinationPort {-# UNPACK #-} !Word16
  | GeoLocation {-# UNPACK #-} !Bytes -- ^ Two-letter country code
  | Headers !(Chunks Header)
  | IpClient {-# UNPACK #-} !IPv4 -- ^ IP address of the client, @ip_client@.
  | ManagementIpAddress {-# UNPACK #-} !IPv4 -- ^ IP address of F5.
  | Protocol {-# UNPACK #-} !Bytes
  | RequestBody {-# UNPACK #-} !Bytes
  | RequestMethod {-# UNPACK #-} !Bytes
  | RequestStatus {-# UNPACK #-} !Bytes
  | RequestTarget {-# UNPACK #-} !Bytes
  | ResponseCode {-# UNPACK #-} !Word64
  | Scheme {-# UNPACK #-} !Bytes
  | Severity {-# UNPACK #-} !Bytes
  | SourcePort {-# UNPACK #-} !Word16
  | Uri {-# UNPACK #-} !Bytes
  deriving stock (Eq)

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
  } deriving stock (Eq)

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
  | MalformedAttackType
  | MalformedClientIdentity
  | MalformedClientIp
  | MalformedDestinationIp
  | MalformedDestinationPort
  | MalformedGeoLocation
  | MalformedHeaderName
  | MalformedHeaderValue
  | MalformedHttpPath
  | MalformedHttpRequestMethod
  | MalformedHttpVersion
  | MalformedIpClient
  | MalformedManagementIpAddress
  | MalformedMethod
  | MalformedProtocol
  | MalformedRequestStatus
  | MalformedRequestTarget
  | MalformedResponseCode
  | MalformedScheme
  | MalformedSecondarySourceIp
  | MalformedSecondaryTimestamp
  | MalformedSeverity
  | MalformedSourceIp
  | MalformedSourcePort
  | MalformedUri
  | MissingIdentifier
  | MissingNewlineAfterHeader
  | MissingNewlineAfterLastHeader
  | PathDomainEndOfInput
  | MalformedResponseBytes
  | SecondaryPathDomainEndOfInput
  | SslCipherSuite
  | SslProtocol
  | SyslogPriority
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
  | EndOfInputInKey 
  deriving stock (Show)
  deriving anyclass (Exception)

decode :: Bytes -> Either Error Log
decode b = case P.parseBytes parser b of
  -- TODO: switch to parseBytesEither once it is released
  P.Failure e -> Left e
  P.Success (Slice _ _ r) -> Right r

skipSyslogPriority :: Parser Error s ()
skipSyslogPriority = Latin.trySatisfy (== '<') >>= \case
  True -> do
    Latin.skipDigits1 SyslogPriority
    Latin.char SyslogPriority '>'
  False -> pure ()

parser :: Parser Error s Log
parser = do
  skipSyslogPriority
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
      Latin.char3 UnrecognizedIdentifier 'S' 'M' ':'
      -- Two different paths. If we see a double quote, go for the
      -- CSV-style format. On any other character, we assume named
      -- pairs.
      Latin.trySatisfy (=='"') >>= \case
        True -> parserAsm host
        False -> do
          r <- parserAsmKeyValue =<< P.effect Builder.new
          pure (LogAsmKeyValue r)
    _ -> P.fail UnrecognizedIdentifier

parserAsmKeyValue :: Builder s Attribute -> Parser Error s (Chunks Attribute)
parserAsmKeyValue !b0 = do
  key <- Latin.takeTrailedBy EndOfInputInKey '='
  b1 <- case Bytes.length key of
    21 | Bytes.equalsCString (Ptr "management_ip_address"#) key -> do
           !addr <- quotedIp MalformedManagementIpAddress
           let !x = ManagementIpAddress addr
           P.effect (Builder.push x b0)
    14 | Bytes.equalsCString (Ptr "request_status"#) key -> do
           !txt <- quotedBytes MalformedRequestStatus
           let !x = RequestStatus txt
           P.effect (Builder.push x b0)
    13 | Bytes.equalsCString (Ptr "response_code"#) key -> do
           !code <- quotedW64 MalformedResponseCode
           let !x = ResponseCode code
           P.effect (Builder.push x b0)
    12 | Bytes.equalsCString (Ptr "geo_location"#) key -> do
           !txt <- quotedBytes MalformedGeoLocation
           let !x = GeoLocation txt
           P.effect (Builder.push x b0)
    11 | Bytes.equalsCString (Ptr "source_port"#) key -> do
           !port <- quotedPort MalformedSourcePort
           let !x = SourcePort port
           P.effect (Builder.push x b0)
       | Bytes.equalsCString (Ptr "attack_type"#) key -> do
           !txt <- quotedBytes MalformedAttackType
           if Bytes.null txt
             then pure b0
             else do
               let !x = AttackType txt
               P.effect (Builder.push x b0)
    9  | Bytes.equalsCString (Ptr "dest_port"#) key -> do
           !port <- quotedPort MalformedDestinationPort
           let !x = DestinationPort port
           P.effect (Builder.push x b0)
       | Bytes.equalsCString (Ptr "ip_client"#) key -> do
           !addr <- quotedIp MalformedIpClient
           let !x = IpClient addr
           P.effect (Builder.push x b0)
    8  | Bytes.equalsCString (Ptr "severity"#) key -> do
           !sev <- quotedBytes MalformedSeverity
           let !x = Severity sev
           P.effect (Builder.push x b0)
    7  | Bytes.equalsCString (Ptr "dest_ip"#) key -> do
           !addr <- quotedIp MalformedDestinationIp
           let !x = DestinationIp addr
           P.effect (Builder.push x b0)
       | Bytes.equalsCString (Ptr "protocol"#) key -> do
           !txt <- quotedBytes MalformedProtocol
           let !x = Protocol txt
           P.effect (Builder.push x b0)
       | Bytes.equalsCString (Ptr "request"#) key -> do
           Latin.char MalformedHttpRequestMethod '"'
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
           let !x = Headers headers
           b1 <- P.effect (Builder.push x b0)
           Latin.trySatisfy (== '"') >>= \case
             True -> pure b1
             False -> do
               -- Hmmm... we could actually take advantage of the
               -- Content-Length header in here. But that is complicated.
               -- Takes until a double quote character is found.
               !body <- P.takeTrailedBy UnknownFieldG 0x22
               case escapeSequences body of
                 Nothing -> pure b1
                 Just body' -> do
                   let !y = RequestBody body'
                   P.effect (Builder.push y b1)
    6  | Bytes.equalsCString (Ptr "method"#) key -> do
           !y <- quotedBytes MalformedMethod
           let !x = RequestMethod y
           P.effect (Builder.push x b0)
    3  | Bytes.equalsCString (Ptr "uri"#) key -> do
           !y <- quotedBytes MalformedUri
           let !x = Uri y
           P.effect (Builder.push x b0)
    _ -> do
      Latin.char UnknownFieldG '"'
      Latin.skipTrailedBy UnknownFieldG '"'
      pure b0
  P.isEndOfInput >>= \case
    True -> P.effect (Builder.freeze b1)
    False -> Latin.any UnknownFieldP >>= \case
      ',' -> parserAsmKeyValue b1
      '\n' -> lineSepAndEnd UnknownFieldJ *> P.effect (Builder.freeze b1)
      '\r' -> lineSepAndEnd UnknownFieldJ *> P.effect (Builder.freeze b1)
      _ -> P.fail UnknownFieldD

lineSepAndEnd :: e -> Parser e s ()
lineSepAndEnd e = do
  P.skipWhile (\c -> c == 0x0A || c == 0x0D)
  P.endOfInput e

quotedBytes :: e -> Parser e s Bytes
quotedBytes e = Latin.char e '"' *> Latin.takeTrailedBy e '"'

quotedIp :: e -> Parser e s IPv4
quotedIp e = Latin.char e '"' *> IPv4.parserUtf8Bytes e <* Latin.char e '"'

quotedPort :: e -> Parser e s Word16
quotedPort e = Latin.char e '"' *> Latin.decWord16 e <* Latin.char e '"'

quotedW64 :: e -> Parser e s Word64
quotedW64 e = Latin.char e '"' *> Latin.decWord64 e <* Latin.char e '"'

-- TODO: Make this actually escape things. At the least, carriage
-- returns and newlines are encoded by F5 in the normal way.
escapeSequences :: Bytes -> Maybe Bytes
escapeSequences = Just

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
  responseCode <- Latin.decWord64 MalformedResponseCode
  Latin.char MalformedResponseCode ' '
  responseBytes <- Latin.decWord64 MalformedResponseBytes
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
  _ <- Latin.decWord64 MalformedResponseBytes
  P.endOfInput EncounteredLeftovers
  pure (LogSslRequest (SslRequest {protocol,cipherSuite,path}))

emptyBytes :: Parser e s Bytes
emptyBytes = do
  arr <- Unsafe.expose
  pure (Bytes arr 0 0)

-- The initial datetime is formatted like this: Dec  6 10:04:50.
-- Notice that if the day of the month is less than ten it gets
-- padded by a space. The date is always missing the year. This
-- parser consumes a trailing space.
skipInitialDate :: Parser Error s ()
skipInitialDate = do
  match isUpper LeadingDatetimeMonth
  match isLower LeadingDatetimeMonth
  match isLower LeadingDatetimeMonth
  Latin.skipChar1 LeadingDatetimeMonth ' '
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
