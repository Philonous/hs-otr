{-# LANGUAGE RecordWildCards #-}
module Otr.Serialize where

import           Control.Applicative((<$>))
import           Control.Monad
import qualified Crypto.Cipher.DSA as DSA
import           Data.Bits
import qualified Data.ByteString as BS
import           Data.List
import           Data.Serialize
import           Data.Word
import           Otr.Types

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
    go x | x <= 0    = Nothing
         | otherwise = Just (fromIntegral x, x `shiftR` 8)

rollInteger :: [Word8] -> Integer
rollInteger = foldl' (\y x -> ((y `shiftL` 8) + fromIntegral x)) 0

putMPI (MPI i)  = do
    let bytes = unrollInteger i
    putWord32be (fromIntegral $ length bytes)
    mapM_ put bytes
    return ()

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
    put (DsaP (DSA.PublicKey (p,g,q) y)) = putWord16be 0
                   >> mapM_ (put . MPI) [p, q, g, y]
                   >> return ()
    get = do
        guard . (== 0) =<< getWord16be
        [p, q, g, y] <- replicateM 4 $ unMPI <$> get
        return (DsaP (DSA.PublicKey (p,g,q) y))

putDsaS (DsaS (r, s)) = do
    let r' = unrollInteger r
    let s' = unrollInteger s
    -- unless (length r' == 20 && length s' == 20)
    --     $ fail "Signature components not 20 bytes"
    mapM_ putWord8 (unrollInteger r)
    mapM_ putWord8 (unrollInteger s)


getDsaS = do
    r <- replicateM 20 getWord8
    s <- replicateM 20 getWord8
    return $ DsaS (rollInteger r, rollInteger s)

instance Serialize OtrDsaSignature where
    put = putDsaS
    get = getDsaS


putRevealMessage RSM{..} = do
    put pubKey
    put keyId
    put sigB

getRevealMessage = do
    pubKey <- get
    keyId  <- get
    sigB   <- get
    return RSM{..}

instance Serialize OtrRevealSignatureMessage where
    put = putRevealMessage
    get = getRevealMessage