{-# LANGUAGE RecordWildCards #-}
module Otr.Serialize where

import           Control.Monad
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
         | otherwise = Just (fromIntegral x, (x `shiftR` 8))

rollInteger :: [Word8] -> Integer
rollInteger xs = go 0 xs
  where
    go y [] = y
    go y (x:xs) = go ((y `shiftL` 8) + fromIntegral x) xs

putMPI (MPI i)  = do
    let bytes = unrollInteger i
    putWord32be (fromIntegral $ length bytes)
    mapM put bytes
    return ()

getMPI = do
  mpiLength <- getWord32be
  mpiData <- replicateM (fromIntegral mpiLength) getWord8
  return . MPI . rollInteger $ mpiData

instance Serialize MPI where
    put = putMPI
    get = getMPI

instance Serialize DATA where
    put (DATA bs) = putWord32be (fromIntegral $ BS.length bs) >> putByteString bs
    get = DATA `fmap` (getByteString . fromIntegral =<< getWord32be)
