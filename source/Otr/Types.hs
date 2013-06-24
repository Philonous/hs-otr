{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE NamedFieldPuns #-}
module Otr.Types where

import           Control.Monad.CryptoRandom
import           Control.Monad.Error
import           Control.Monad.State
import qualified Crypto.PubKey.DSA as DSA
import           Crypto.Random(GenError)
import           Data.Bits
import qualified Data.ByteString as BS
import           Data.Data
import           Data.List
import           Data.Typeable
import           Data.Word

-- all big endian
type OtrByte = Word8
type OtrShort = Word16
type OtrInt = Word32

-- multi-precision unsigned integer
newtype MPI = MPI{unMPI :: Integer} deriving (Show, Eq)

newtype DATA = DATA {unDATA :: BS.ByteString} deriving (Show, Eq)

data OtrMessageHeader = OM { version      :: !OtrShort
                           , messageType  :: !OtrByte
                           , senderITag   :: !OtrInt
                           , receiverITag :: !OtrInt
                           } deriving (Show, Eq)



data OtrDHCommitMessage = DHC{ gxMpiAes    :: !DATA
                             , gxMpiSha256 :: !DATA
                             } deriving (Show, Eq)

data OtrDHKeyMessage = DHK {gyMpi :: !BS.ByteString } deriving (Show, Eq)

data OTRSession = OTRS { instanceTag :: !Word32
                       , aesKey      :: !(Maybe BS.ByteString)
                       , dhKey       :: !Integer

                       }

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

newtype OtrDsaPubKey = DsaP {unDsaP:: DSA.PublicKey } deriving (Eq, Show)

newtype OtrDsaSignature = DsaS DSA.Signature deriving (Eq, Show)

data OtrRevealSignatureMessage = RSM { revealedKey :: !DATA
                                     , rsmSig :: !OtrSignatureMessage
                                     } deriving (Eq, Show)

data SignatureData = SD { sdPub   :: OtrDsaPubKey
                        , sdKeyId :: OtrInt
                        , sdSig   :: OtrDsaSignature
                        } deriving (Eq, Show)


data DHKeyPair = DHKeyPair { pub  :: !Integer
                           , priv :: !Integer
                           } deriving Show

data Msgstate = MsgstatePlaintext
              | MsgstateEncrypted
              | MsgstateFinished
              deriving (Eq, Show)

data OtrState = OtrState { authState        :: !Authstate
                         , msgState         :: !Msgstate
                         , ourKeyId         :: !OtrInt
                         , theirPublicKey   :: !(Maybe DSA.PublicKey) -- DSA
                         , ourCurrentKey    :: !DHKeyPair
                         , ourPreviousKey   :: !DHKeyPair
                         , theirKeyId       :: !OtrInt
                         , theirCurrentKey  :: !(Maybe Integer)
                         , theirPreviousKey :: !(Maybe Integer)
                         } deriving Show

data OtrError = WrongState
              | RandomGenError GenError
              | ProtocolError ProtocolError -- One of the checks failed
                deriving (Show, Eq)

data ProtocolError = MACFailure
                   | KeyRange -- DH key outside [2, prime - 2]
                   | PubkeyMismatch -- Offered DSA pubkey doesn't match the one
                                    -- we have
                   | SignatureMismatch
                   | HashMismatch
                   | DeserializationError -- couldn deserialize data structure
                   | UnexpectedMessagetype
                     deriving (Show, Eq)

instance Error OtrError where
    noMsg = WrongState -- TODO: Change

data Authstate = AuthstateNone
               | AuthstateAwaitingDHKey BS.ByteString
               | AuthstateAwaitingRevealsig OtrDHCommitMessage
               | AuthstateAwaitingSig
--               | AuthstateV1Setup  -- Compat with V1
                 deriving Show

data OtrSignatureMessage = SM { encryptedSignature :: !DATA
                              , macdSignature :: !DATA
                              } deriving (Eq, Show)

data OtrMessage = DHCommitMessage !OtrDHCommitMessage
                | DHKeyMessage !OtrDHKeyMessage
                | RevealSignatureMessage !OtrRevealSignatureMessage
                | SignatureMessage !OtrSignatureMessage

showMessageType (DHCommitMessage        _) = "DHCommitMessage"
showMessageType (DHKeyMessage           _) = "DHKeyMessage"
showMessageType (RevealSignatureMessage _) = "RevealSignatureMessage"
showMessageType (SignatureMessage       _) = "SignatureMessage"
