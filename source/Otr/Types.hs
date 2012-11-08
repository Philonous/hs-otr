{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE NamedFieldPuns #-}
module Otr.Types where

import           Control.Monad.CryptoRandom
import           Control.Monad.Error
import           Control.Monad.State
import qualified Crypto.Cipher.DSA as DSA
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



data OtrDHCommitMessage = DHC{ gxMpiAes    :: !BS.ByteString
                             , gxMpiSha256 :: !BS.ByteString
                             } deriving Show

data OtrDHKeyMessage = DHK {gyMpi :: !BS.ByteString }

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
                           :: BS.ByteString
                         }
                       deriving (Eq, Show)

newtype OtrDsaPubKey = DsaP {unDsaP:: DSA.PublicKey }

newtype OtrDsaSignature = DsaS DSA.Signature

data OtrRevealSignatureMessage = RSM { pubKey :: !OtrDsaPubKey
                                     , keyId  :: !OtrInt
                                     , sigB   :: !OtrDsaSignature
                                     }


data DHKeyPair = DHKeyPair { pub  :: !Integer
                           , priv :: !Integer
                           } deriving Show

data OtrState = OtrState { authState        :: !Authstate
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
              | ProtocolFailure String -- One of the checks failed
                deriving (Show, Eq)

instance Error OtrError where
    noMsg = WrongState -- TODO: Change

instance ContainsGenError OtrError where
    toGenError (RandomGenError e) = Just e
    toGenError _ = Nothing
    fromGenError = RandomGenError

data Authstate = AuthstateNone
               | AuthstateAwaitingDHKey BS.ByteString
               | AuthstateAwaitingRevealsig OtrDHCommitMessage
               | AuthstateAwaitingSig
--               | AuthstateV1Setup  -- Compat with V1
                 deriving Show
