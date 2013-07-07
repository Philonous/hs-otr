{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE NamedFieldPuns #-}
module Otr.Types where

import           Control.Applicative((<$>), (<*>))
import           Control.Exception
import           Control.Monad
import qualified Control.Monad.CryptoRandom as CR
import           Control.Monad.Error
import qualified Crypto.PubKey.DSA as DSA
import           Data.Bits
import qualified Data.ByteString as BS
import           Data.List
import           Data.Serialize
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

showHexData :: BS.ByteString -> String
showHexData d = concatMap (\x -> let hex = showHex x "" in
                          replicate (2 - length hex) '0' ++ hex )
                        $ BS.unpack d


data OtrMessage = OM { version      :: !OtrShort
                     , senderITag   :: !OtrInt
                     , receiverITag :: !OtrInt
                     , messageBody  :: !OtrMessageBody
                     } deriving (Show, Eq)

data OtrDHCommitMessage = DHC{ gxMpiAes    :: !DATA
                             , gxMpiSha256 :: !DATA
                             } deriving (Show, Eq)

instance Serialize OtrDHCommitMessage where
    put DHC{..} = do
        put gxMpiAes
        put gxMpiSha256
    get =
        DHC <$> get <*> get


data OtrDHKeyMessage = DHK {gyMpi :: !MPI } deriving (Show, Eq)

instance Serialize OtrDHKeyMessage where
    put DHK{..} = put gyMpi
    get = DHK <$> get

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
                           -- Instance Tags
                         , theirIT          :: !OtrInt -- 0 is considered a
                                                       -- special value meaning
                                                       -- no instance Tag has
                                                       -- been received yet
                         , ourIT            :: !OtrInt
                         } deriving Show

data OtrError = WrongState
              | RandomGenError CR.GenError
              | InstanceTagRange
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
                     deriving (Show, Eq)

instance Error OtrError where
    noMsg = WrongState -- TODO: Change

data Authstate = AuthstateNone
               | AuthstateAwaitingDHKey BS.ByteString
               | AuthstateAwaitingRevealsig OtrDHCommitMessage
               | AuthstateAwaitingSig
--               | AuthstateV1Setup  -- Compat with V1
                 deriving Show

newtype MAC = MAC BS.ByteString deriving (Eq, Show) -- 20 bytes of MAC data

instance Serialize MAC where
    get = MAC <$> getBytes 20
    put (MAC bs) = putByteString bs

data OtrSignatureMessage = SM { encryptedSignature :: !DATA
                              , macdSignature :: !MAC
                              } deriving (Eq, Show)

data OtrMessageBody = DHCommitMessage !OtrDHCommitMessage
                    | DHKeyMessage !OtrDHKeyMessage
                    | RevealSignatureMessage !OtrRevealSignatureMessage
                    | SignatureMessage !OtrSignatureMessage
                    | DataMessage ()
                      deriving (Eq, Show)

showMessageType :: OtrMessageBody -> [Char]
showMessageType (DHCommitMessage        _) = "DHCommitMessage"
showMessageType (DHKeyMessage           _) = "DHKeyMessage"
showMessageType (RevealSignatureMessage _) = "RevealSignatureMessage"
showMessageType (SignatureMessage       _) = "SignatureMessage"
showMessageType (DataMessage            _) = "DataMessage"


putMessage :: OtrMessage -> PutM ()
putMessage OM{..} = do
    let (tp, putBody) = case messageBody of
            DHCommitMessage b        -> (0x02, put b)
            DHKeyMessage b           -> (0x0a, put b)
            RevealSignatureMessage b -> (0x11, put b)
            SignatureMessage b       -> (0x12, put b)
            DataMessage b            -> (0x03, put b)
    put version
    put (tp :: OtrByte)
    put senderITag
    put receiverITag
    putBody

getMessage :: Get OtrMessage
getMessage = do
    version <- get
    messageType <- get :: Get OtrByte
    senderITag <- get
    receiverITag <- get
    messageBody <- case messageType of
        0x02 -> DHCommitMessage <$> label "getDHCommitMessage" get
        0x0a -> DHKeyMessage <$> label "getDHKeyMessage" get
        0x11 -> RevealSignatureMessage <$> label "getRevealSignatureMessage" get
        0x12 -> SignatureMessage <$> label "getSignatureMessage" get
        0x03 -> DataMessage <$> label "getDataMessage" get
        _    -> fail "unknown message type"
    return OM{..}

instance Serialize OtrMessage where
    put = putMessage
    get = getMessage

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
    mapM_ putWord8 bytes
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
    get = DATA <$> (getBytes . fromIntegral =<< getWord32be)

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
    unless (length r' <= 20 && length s' <= 20)
        . fail $ "Signature components more than 20 bytes"
          ++ showHexData (BS.pack r') ++ " / " ++ showHexData (BS.pack s')
          -- TODO: fail more -- gracefully
    replicateM (20 - length r') $ putWord8 0
    mapM_ putWord8 r'
    replicateM (20 - length s') $ putWord8 0
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
