{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE OverloadedStrings #-}
module Otr.Serialize where

import           Control.Applicative((<$>), (<*>), (<|>))
import           Control.Monad
import           Control.Monad (replicateM)
import qualified Crypto.PubKey.DSA as DSA
import           Data.Bits
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BS8
import qualified Data.ByteString.Lazy as BSL
import           Data.Char (ord)
import           Data.Char (ord)
import           Data.List
import           Data.Monoid (mconcat, mappend)
import           Data.Serialize
import           Data.Word
import           Numeric
import           Otr.Types

putMP :: OtrMessagePayload -> PutM ()
putMP MP{..} = do
    putByteString messagePlaintext
    unless (null tlvs) $ do
        putWord8 0
        forM_ tlvs putTLV

getMP :: Get OtrMessagePayload
getMP = do
    messagePlaintext <- getBytesWhile (/= 0)
    hasTlvs <- (getWord8 >> return True) <|> (return False)
    tlvs <- if hasTlvs then getTLVs else return []
    return $ MP{..}
  where
    getTLVs = do
        moreData <- (ensure 1 >> return True) <|> return False
        if moreData
            then liftM2 (:) getTLV getTLVs
            else return []


putTLV :: TLV -> PutM ()
putTLV TLV{..} = do
    putWord16be $ case tlvType of
        Padding      -> 0
        Disconnected -> 1
        SMPMessage1  -> 2
        SMPMessage2  -> 3
        SMPMessage3  -> 4
        SMPMessage4  -> 5
        SMPMessage1Q -> 6
        SMPAbort     -> 7
        ExtraKey     -> 8
    putWord16be . fromIntegral $ BS.length tlvValue
    putByteString tlvValue

getTLV :: Get TLV
getTLV = do
    tp <- getWord16be >>= \x -> case x of
        0 -> return Padding
        1 -> return Disconnected
        2 -> return SMPMessage1
        3 -> return SMPMessage2
        4 -> return SMPMessage3
        5 -> return SMPMessage4
        6 -> return SMPMessage1Q
        7 -> return SMPAbort
        8 -> return ExtraKey
        _ -> fail "Unrecognized TLV type"
    tlvLen <- fromIntegral <$> getWord16be
    TLV tp <$> getBytes tlvLen

getBytesWhile :: (Word8 -> Bool) -> Get BS.ByteString
getBytesWhile p = do
    numBytes <- lookAhead $ step 0
    getBytes numBytes
  where
    step n = check (n+1) <|> return n
    check n = do
        byte <- getWord8
        guard $ p byte
        step n

getMAC :: Get MAC
getMAC = MAC <$> getBytes 20

putMAC :: MAC -> Put
putMAC (MAC bs) = putByteString bs

instance Serialize MAC where
    get = getMAC
    put = putMAC

putMessageBody :: OtrMessageBody -> Put
putMessageBody mb = case mb of
            DHCommitMessage b        -> put b
            DHKeyMessage b           -> put b
            RevealSignatureMessage b -> put b
            SignatureMessage b       -> put b
            DataMessage b            -> put b

putMessageHeader :: OtrMessageHeader -> PutM ()
putMessageHeader MH{..} = do
    putWord16be version
    putWord8 messageType
    putWord32be senderITag
    putWord32be receiverITag

getMessageHeader :: Get OtrMessageHeader
getMessageHeader = MH <$> getWord16be
                      <*> getWord8
                      <*> getWord32be
                      <*> getWord32be

putMessage :: OtrMessage -> PutM ()
putMessage OM{..} = do
    putMessageHeader messageHeader
    putMessageBody messageBody

getMessage :: Get OtrMessage
getMessage = do
    mh <- getMessageHeader
    mb <- getMessageBody (messageType mh)
    return $ OM mh mb

getMessageBody :: OtrByte -> Get OtrMessageBody
getMessageBody messageType = case messageType of
    0x02 -> DHCommitMessage <$> label "getDHCommitMessage" get
    0x0a -> DHKeyMessage <$> label "getDHKeyMessage" get
    0x11 -> RevealSignatureMessage <$> label "getRevealSignatureMessage" get
    0x12 -> SignatureMessage <$> label "getSignatureMessage" get
    0x03 -> DataMessage <$> label "getDataMessage" get
    _    -> fail "unknown message type"

instance Serialize OtrMessage where
    put = putMessage
    get = getMessage

instance Serialize OtrDHCommitMessage where
    put DHC{..} = do
        put gxMpiAes
        put gxMpiSha256
    get =
        DHC <$> get <*> get

instance Serialize OtrDHKeyMessage where
    put DHK{..} = put gyMpi
    get = DHK <$> get

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

putDATA :: DATA -> PutM ()
putDATA (DATA bs) = putWord32be (fromIntegral $ BS.length bs)
                >> putByteString bs

getDATA :: Get DATA
getDATA = DATA <$> (getBytes . fromIntegral =<< getWord32be)

instance Serialize DATA where
    put = putDATA
    get = getDATA

instance Serialize OtrDsaPubKey where
    put (DsaP (DSA.PublicKey (DSA.Params p g q) y)) = do
        putWord16be 0
        mapM_ (putMPI . MPI) [p, q, g, y]
        return ()
    get = do
        guard . (== 0) =<< getWord16be
        [p, q, g, y] <- replicateM 4 $ unMPI <$> getMPI
        return (DsaP (DSA.PublicKey (DSA.Params p g q) y))

putDsaS :: OtrDsaSignature -> PutM ()
putDsaS (DsaS (DSA.Signature r s)) = do
    let r' = unrollInteger r
    let s' = unrollInteger s
    unless (length r' <= 20 && length s' <= 20)
        . fail $ "Signature components more than 20 bytes"
          ++ showHexData (BS.pack r') ++ " / " ++ showHexData (BS.pack s')
          -- TODO: fail more -- gracefully
    replicateM_ (20 - length r') $ putWord8 0
    mapM_ putWord8 r'
    replicateM_ (20 - length s') $ putWord8 0
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

putRDM :: OtrRawDataMessage -> PutM ()
putRDM RDM{..} = do
    putWord8 flags
    putWord32be senderKeyID
    putWord32be recipientKeyID
    putMPI nextDHy
    putWord64be ctrHi
    putDATA messageAes128

getRDM :: Get OtrRawDataMessage
getRDM = RDM <$> getWord8
            <*> getWord32be
            <*> getWord32be
            <*> getMPI
            <*> getWord64be
            <*> getDATA

instance Serialize OtrRawDataMessage where
    put = putRDM
    get = getRDM

putDM :: OtrDataMessage -> PutM ()
putDM DM{..} = do
    putRDM rawDataMessage
    putMAC messageMAC
    putDATA oldMACKeys

getDM :: Get OtrDataMessage
getDM = DM <$> getRDM
           <*> getMAC
           <*> getDATA

instance Serialize OtrDataMessage where
    put = putDM
    get = getDM

data Fragment = Fragment { fragmentSenderID    :: Word32
                         , fragmentRecipientID :: Word32
                         , fragmentChunkCount  :: Word16
                         , fragmentChunkNumber :: Word16
                         , fragmentPayload     :: BS.ByteString
                         } deriving Show

fragment si ri size bs = zipWith envelope [1 :: Word16 ..] chunks
  where
    chunks = unfoldr (\x -> let s@(pre, _) = BS.splitAt size x in
                         if BS.null pre then Nothing else Just s) bs
    n = length chunks
    envelope k chunk = Fragment { fragmentSenderID = si
                                , fragmentRecipientID = ri
                                , fragmentChunkCount = fromIntegral n
                                , fragmentChunkNumber = k
                                , fragmentPayload = chunk
                                }

putFragment Fragment{..} = do
                           putByteString "?OTR|"
                           putWord32HexFixed fragmentSenderID
                           putByteString "|"
                           putWord32HexFixed fragmentRecipientID
                           putByteString ","
                           putWord16DecFixed fragmentChunkCount
                           putByteString ","
                           putWord16DecFixed fragmentChunkNumber
                           putByteString ","
                           putByteString fragmentPayload
                           putByteString ","
  where
    putWord32HexFixed x = do
        let bs = BS8.pack $ showHex x ""
        replicateM (8 - BS.length bs) $ putByteString "0"
        putByteString bs
    putWord16DecFixed w = let digits = show w
                              prefix = (replicate (5 - length digits)) '0'
                          in string prefix >> string digits
    string = mapM_ $ putWord8 . fromIntegral . ord

readFragment = runGet unEnvelope
  where
    unEnvelope = do
        string "?OTR|"
        fragmentSenderID <- word32Hex
        char '|'
        fragmentRecipientID <- word32Hex
        char ','
        fragmentChunkCount <- word16Dec
        char ','
        fragmentChunkNumber <- word16Dec
        char ','
        fragmentPayload <- getBytesWhile (/= fromIntegral (ord ','))
        char ','
        return Fragment{..}
    string s = do
        bs <- getBytes (BS.length s)
        unless (bs == s) $ fail "String does not match"
        return ()
    char c = do
        c' <- getWord8
        unless (c' == fromIntegral (ord c)) $ fail "char does not match"
        return ()

    word32Hex :: Get Word32
    word32Hex = getBytes 8 >>= \bytes -> do
        unless (BS.all isHex bytes) $ fail "not hex"
        return $ BS.foldl' step 0 bytes
      where
        isHex w =  (w >= 48 && w <= 57)
                || (w >= 97 && w <= 102)
                || (w >= 65 && w <= 70)
        step a w | w >= 48 && w <= 57  = (a `shiftL` 4) .|. fromIntegral (w - 48)
                 | w >= 97             = (a `shiftL` 4) .|. fromIntegral (w - 87)
                 | otherwise           = (a `shiftL` 4) .|. fromIntegral (w - 55)
    word16Dec :: Get Word16
    word16Dec = getBytes 5 >>= \bytes -> do
        unless (BS.all isDigit bytes) $ fail "not decimal"
        return $ BS.foldl' step 0 bytes
      where
        step a w = a * 10 + (fromIntegral w - 48)
        isDigit w = w >= fromIntegral (ord '0') && w <= fromIntegral (ord '9')
