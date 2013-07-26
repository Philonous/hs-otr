{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE NamedFieldPuns #-}
module Otr.Types where

import           Control.Exception
import qualified Control.Monad.CryptoRandom as CR
import           Control.Monad.Error
import qualified Crypto.PubKey.DSA as DSA
import           Crypto.Util (constTimeEq)
import qualified Data.ByteString as BS
import           Data.Typeable
import           Data.Word
import           Numeric

-- all big endian
type OtrByte = Word8
type OtrShort = Word16
type OtrInt = Word32

-- multi-precision unsigned integer
newtype MPI = MPI{unMPI :: Integer} deriving (Show, Eq)

newtype DATA = DATA {unDATA :: BS.ByteString} deriving Eq

instance Show DATA where
    show (DATA d) = "DATA{ " ++ show (BS.length d) ++ " Bytes hex:\""
                    ++ showHexData d ++ "\"}"

type CTR = Word64

showHexData :: BS.ByteString -> String
showHexData d = concatMap (\x -> let hex = showHex x "" in
                          replicate (2 - length hex) '0' ++ hex )
                        $ BS.unpack d


-- The reason for the strange design of OtrMessage is that we need to be able to
-- serialize a messageHeader independently in order to create the MAC for data
-- messages. Unfortunately the message header and message body don't seperate
-- cleanly; the message type field is not the last of the common fields and
-- therefore can't be handled by the body serialization code. Thus we have the
-- non-normalized condition where the type field of the message header and type
-- of the body are dependent and have to coincide.

data OtrMessageHeader = MH { version      :: !OtrShort
                           , messageType  :: !OtrByte
                           , senderITag   :: !OtrInt
                           , receiverITag :: !OtrInt
                           } deriving (Show, Eq)

data OtrMessage = OM { messageHeader :: !OtrMessageHeader
                     , messageBody   :: !OtrMessageBody
                     } deriving (Eq, Show)

data OtrDHCommitMessage = DHC{ gxMpiAes    :: !DATA
                             , gxMpiSha256 :: !DATA
                             } deriving (Show, Eq)

data OtrMessagePayload = MP { messagePlaintext :: !BS.ByteString
                            , tlvs :: ![TLV]
                            } deriving (Eq, Show)

data OtrRawDataMessage = RDM { flags :: OtrByte
                             , senderKeyID :: OtrInt
                             , recipientKeyID :: OtrInt
                             , nextDHy :: MPI
                             , ctrHi :: CTR
                             , messageAes128 :: DATA
                             } deriving (Eq, Show)

data OtrDataMessage = DM { rawDataMessage :: OtrRawDataMessage
                         , messageMAC :: MAC
                         , oldMACKeys  :: DATA
                         } deriving (Eq, Show)

data TLVType = Padding
             | Disconnected
             | SMPMessage1
             | SMPMessage2
             | SMPMessage3
             | SMPMessage4
             | SMPMessage1Q
             | SMPAbort
             | ExtraKey
               deriving (Eq, Show)



data TLV = TLV { tlvType  :: TLVType
               , tlvValue :: BS.ByteString
               } deriving (Show, Eq)

data OtrDHKeyMessage = DHK {gyMpi :: !MPI } deriving (Show, Eq)

data OTRSession = OTRS { instanceTag :: !Word32
                       , aesKey      :: !(Maybe BS.ByteString)
                       , dhKey       :: !Integer
                       } deriving (Show, Eq)

data KeyDerivatives = KD { kdSsid
                         , kdC
                         , kdC'
                         , kdM1
                         , kdM2
                         , kdM1'
                         , kdM2'
                           :: !BS.ByteString
                         }
                       deriving (Eq, Show)

data MessageKeys = MK { sendAES
                      , sendMAC
                      , recvAES
                      , recvMAC :: !BS.ByteString
                      } deriving Show

newtype OtrDsaPubKey = DsaP {unDsaP:: DSA.PublicKey } deriving (Eq, Show)

newtype OtrDsaSignature = DsaS DSA.Signature deriving (Eq, Show)

data OtrRevealSignatureMessage = RSM { revealedKey :: !DATA
                                     , rsmSig :: !OtrSignatureMessage
                                     } deriving (Eq, Show)

data SignatureData = SD { sdPub   :: OtrDsaPubKey
                        , sdKeyID :: OtrInt
                        , sdSig   :: OtrDsaSignature
                        } deriving (Eq, Show)


data DHKeyPair = DHKeyPair { pub  :: !Integer
                           , priv :: !Integer
                           } deriving Show

data MsgState = MsgStatePlaintext
              | MsgStateEncrypted
              | MsgStateFinished
              deriving (Eq, Show)

data OtrState = OtrState { authState        :: !AuthState
                         , msgState         :: !MsgState
                         , ourKeyID         :: !OtrInt -- KeyID of ourCurrentKey
                         , theirPublicKey   :: !(Maybe DSA.PublicKey) -- DSA
                         , ourCurrentKey    :: !DHKeyPair
                         , ourPreviousKey   :: !DHKeyPair
                         , mostRecentKey    :: !OtrInt -- KeyID of the most
                                                       -- recent key that the
                                                       -- other party
                                                       -- acknowledged receiving
                         , nextDH           :: !DHKeyPair
                         , theirKeyID       :: !OtrInt -- KeyID of the lastest
                                                       -- of their keys we have
                                                       -- on file
                         , theirCurrentKey  :: !(Maybe Integer)
                         , theirPreviousKey :: !(Maybe Integer)
                           -- Instance Tags
                         , theirIT          :: !OtrInt -- 0 is considered a
                                                       -- special value meaning
                                                       -- no instance Tag has
                                                       -- been received yet
                         , ourIT            :: !OtrInt
                         , counter          :: !Word64
                         } deriving Show

data OtrError = WrongState
              | RandomGenError CR.GenError
              | InstanceTagRange
              | NoPeerDHKey -- theirCurrentKey is Nothing
              | ProtocolError ProtocolError -- One of the checks failed
                deriving (Show, Eq, Typeable)

instance Exception OtrError

data ProtocolError = MACFailure
                   | KeyRange -- DH key outside [2, prime - 2]
                   | PubkeyMismatch -- Offered DSA pubkey doesn't match the one
                                    -- we have
                   | SignatureMismatch
                   | HashMismatch
                   | DeserializationError String -- couldn deserialize data
                                                 -- structure
                   | UnexpectedMessagetype
                   | WrongKeyID -- KeyID is not current or current + 1
                     deriving (Show, Eq)

instance Error OtrError where
    noMsg = WrongState -- TODO: Change

data AuthState = AuthStateNone
               | AuthStateAwaitingDHKey BS.ByteString
               | AuthStateAwaitingRevealsig OtrDHCommitMessage
               | AuthStateAwaitingSig
--               | AuthStateV1Setup  -- Compat with V1
                 deriving Show

newtype MAC = MAC BS.ByteString deriving (Show) -- 20 bytes of MAC data

instance Eq MAC where
    (MAC a) == (MAC b) = constTimeEq a b

data OtrSignatureMessage = SM { encryptedSignature :: !DATA
                              , macdSignature :: !MAC
                              } deriving (Eq, Show)

data OtrMessageBody = DHCommitMessage !OtrDHCommitMessage
                    | DHKeyMessage !OtrDHKeyMessage
                    | RevealSignatureMessage !OtrRevealSignatureMessage
                    | SignatureMessage !OtrSignatureMessage
                    | DataMessage OtrDataMessage
                      deriving (Eq, Show)

showMessageType :: OtrMessageBody -> [Char]
showMessageType (DHCommitMessage        _) = "DHCommitMessage"
showMessageType (DHKeyMessage           _) = "DHKeyMessage"
showMessageType (RevealSignatureMessage _) = "RevealSignatureMessage"
showMessageType (SignatureMessage       _) = "SignatureMessage"
showMessageType (DataMessage            _) = "DataMessage"
