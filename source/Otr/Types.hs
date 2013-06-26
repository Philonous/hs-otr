{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE NamedFieldPuns #-}
module Otr.Types where

import           Control.Applicative((<$>))
import           Control.Monad
import           Control.Monad.CryptoRandom
import           Control.Monad.Error
import qualified Crypto.PubKey.DSA as DSA
import           Data.Bits
import qualified Data.ByteString as BS
import           Data.List
import           Data.Serialize
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

showMessageType :: OtrMessage -> [Char]
showMessageType (DHCommitMessage        _) = "DHCommitMessage"
showMessageType (DHKeyMessage           _) = "DHKeyMessage"
showMessageType (RevealSignatureMessage _) = "RevealSignatureMessage"
showMessageType (SignatureMessage       _) = "SignatureMessage"


putMessageHeader :: OtrMessageHeader -> PutM ()
putMessageHeader OM{..} = do
    put version
    put messageType
    put senderITag
    put receiverITag

getMessageHeader :: Get OtrMessageHeader
getMessageHeader = do
    version <- get
    messageType <- get
    senderITag <- get
    receiverITag <- get
    return OM{..}

instance Serialize OtrMessageHeader where
    put = putMessageHeader
    get = getMessageHeader

-- | Will be [] for x <= 0
unrollInteger :: Integer -> [Word8]
unrollInteger x = reverse $ unfoldr go x
  where
    go x' | x' <= 0    = Nothing
          | otherwise = Just (fromIntegral x', x' `shiftR` 8)

rollInteger :: [Word8] -> Integer
rollInteger = foldl' (\y x -> ((y `shiftL` 8) + fromIntegral x)) 0

putMPI :: MPI -> PutM ()
putMPI (MPI i)  = do
    let bytes = unrollInteger i
    putWord32be (fromIntegral $ length bytes)
    mapM_ put bytes
    return ()

getMPI :: Get MPI
getMPI = do
  mpiLength <- getWord32be
  mpiData <- replicateM (fromIntegral mpiLength) getWord8
  return . MPI . rollInteger $ mpiData

instance Serialize MPI where
    put = putMPI
    get = getMPI

instance Serialize DATA where
    put (DATA bs) = putWord32be (fromIntegral $ BS.length bs)
                    >> putByteString bs
    get = DATA <$> (getByteString . fromIntegral =<< getWord32be)

instance Serialize OtrDsaPubKey where
    put (DsaP (DSA.PublicKey (DSA.Params p g q) y)) = putWord16be 0
                   >> mapM_ (put . MPI) [p, q, g, y]
                   >> return ()
    get = do
        guard . (== 0) =<< getWord16be
        [p, q, g, y] <- replicateM 4 $ unMPI <$> get
        return (DsaP (DSA.PublicKey (DSA.Params p g q) y))

putDsaS :: OtrDsaSignature -> PutM ()
putDsaS (DsaS (DSA.Signature r s)) = do
    let r' = unrollInteger r
    let s' = unrollInteger s
    unless (length r' == 20 && length s' == 20)
        $ fail "Signature components not 20 bytes"
    mapM_ putWord8 r'
    mapM_ putWord8 s'


getDsaS :: Get OtrDsaSignature
getDsaS = do
    r <- replicateM 20 getWord8
    s <- replicateM 20 getWord8
    return . DsaS $ DSA.Signature (rollInteger r) (rollInteger s)

instance Serialize OtrDsaSignature where
    put = putDsaS
    get = getDsaS


putRevealMessage :: OtrRevealSignatureMessage -> PutM ()
putRevealMessage (RSM r sm) = put r >> put sm

getRevealMessage :: Get OtrRevealSignatureMessage
getRevealMessage = liftM2 RSM get get

instance Serialize OtrRevealSignatureMessage where
    put = putRevealMessage
    get = getRevealMessage

instance Serialize OtrSignatureMessage where
    put (SM enc mc) = put enc >> put mc
    get = liftM2 SM get get

instance Serialize SignatureData where
    put (SD p k s) = do
        put p
        put k
        put s
    get = liftM3 SD get get get
