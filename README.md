# F5 Systems Logs

### Overview
This repository is a parser for F5 Syslogs. 

Data Log
```sh
  = LogSslRequest SslRequest
  | LogSslAccess SslAccess
  | LogAsm Asm
  | LogAsmKeyValue (Chunks Attribute)
```

Data Attributes
```sh
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
  | SupportId {-# UNPACK #-} !Word64
  | Uri {-# UNPACK #-} !Bytes
  | Username {-# UNPACK #-} !Bytes
```