{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE NamedFieldPuns #-}
module Otr.Types where

import           Control.Monad.Error
import           Data.Bits
import           Crypto.Random(GenError)
import qualified Data.ByteString as BS
import           Data.Data
import           Data.List
import           Data.Typeable
import           Data.Word

-- all big endian
type OtrByte = Word8
type OtrShort = Word16
type OtrInt = Word32

-- multi-precision integer
newtype MPI = MPI{unMPI :: Integer} deriving (Show, Eq)

newtype DATA = DATA {unDATA :: BS.ByteString} deriving (Show, Eq)

data OtrMessageHeader = OM { version      :: !OtrShort
                           , messageType  :: !OtrByte
                           , senderITag   :: !OtrInt
                           , receiverITag :: !OtrInt
                           } deriving (Show, Eq)
data OtrError = WrongState
              | RandomGenError GenError
              | ProtocolFailure String -- One of the checks failed
                deriving (Show, Eq)

instance Error OtrError where
    noMsg = WrongState -- TODO: Change
