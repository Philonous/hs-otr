module Otr where

import           Control.Arrow (first)
import           Control.Monad
import qualified Crypto.Cipher.AES as Crypto
import qualified Crypto.Cipher.DH as DH
import qualified Crypto.Classes as Crypto
import qualified Crypto.Hash.SHA256 as SHA256
import qualified Crypto.Modes as Crypto
import           Data.Bits
import qualified Data.ByteString as BS
import           Data.Serialize
import           Data.Word
import           Math.NumberTheory.Powers(powerMod)
import           Numeric
import           System.Random

import           Otr.Types
import           Otr.Serialize


showBits a = reverse [if testBit a i then '1' else '0' | i <- [0.. bitSize a - 1]]

prime :: Integer
prime = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF

params = (prime, 2)

-- aes k payload = case Crypto.buildKey k :: Maybe Crypto.AES128 of
--     Nothing -> Nothing
--     Just key -> Just . fst $ Crypto.ctr' Crypto.incIV key Crypto.zeroIV payload

-- | Generate a random positive Integer with exactly b bits (highest bit will
-- always be 1)
randomBits :: RandomGen t => t -> Int -> (Integer, t)
randomBits g b = first (bit (b - 1) .|.) $ randomR (0, bit $ b - 2) g

bob1 = do
    r' <- BS.pack `fmap` replicateM 16 randomIO
    let key = case Crypto.buildKey r' :: Maybe Crypto.AES128 of
            Nothing -> error "buildKey Failed"
            Just key -> key
    (x, _) <- flip randomBits 320 `fmap` newStdGen
    let y = encode . MPI $ powerMod 2 x prime
    let aes = fst $ Crypto.ctr' Crypto.incIV key Crypto.zeroIV y
    let hash = SHA256.hash y
    return (aes, hash)
