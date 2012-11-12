{-# LANGUAGE RecordWildCards #-}
module Otr where

import           Control.Applicative ((<$>))
import           Control.Monad
import           Control.Monad.Error
import           Control.Monad.Identity
import           Control.Monad.Reader
import           Control.Monad.State.Strict
import qualified Crypto.Cipher.AES as Crypto
import qualified Crypto.Cipher.DH as DH
import qualified Crypto.Cipher.DSA as DSA
import qualified Crypto.Classes as Crypto
import qualified Crypto.HMAC as HMAC
import qualified Crypto.Hash.SHA256 as SHA256
import qualified Crypto.Modes as Crypto
import qualified Crypto.Random as CRandom
import           Data.Bits
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BSL
import           Data.Maybe(fromMaybe)
import qualified Data.Serialize as Serialize
import           Data.Word
import           Math.NumberTheory.Powers(powerMod)
import           Numeric
import           Otr.RandMonad
import           System.Random

import           Otr.Types
import           Otr.Serialize


modifyState f = putState . f =<< getState

showBits a = reverse [if testBit a i then '1' else '0' | i <- [0.. bitSize a - 1]]

prime :: Integer
prime = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF

params = (prime, 2)

-- aes k payload = case Crypto.buildKey k :: Maybe Crypto.AES128 of
--     Nothing -> Nothing
--     Just key -> Just . fst $ Crypto.ctr' Crypto.incIV key Crypto.zeroIV payload

-- | Generate a129
-- random positive Integer with exactly b bits (highest bit will
-- always be 1)
-- randomBits :: RandomGen t => t -> Int -> (Integer, t)
-- randomBits g b = first (bit (b - 1) .|.) $ CRandom.randomR (0, bit $ b - 2) g

mapLeft f (Left l) = Left $ f l
mapLeft _ (Right r) = Right r

-- randomIntegerBytes :: Int ->Otr Integer
randomIntegerBytes b = rollInteger . BS.unpack <$> getBytes b

aesCtr :: BS.ByteString -> BS.ByteString -> BS.ByteString
aesCtr k x = fst $ Crypto.ctr' Crypto.incIV key Crypto.zeroIV x
  where
    key = fromMaybe (error "buildKey Failed")
                    (Crypto.buildKey k :: Maybe Crypto.AES128)

sign :: CRandom.CryptoRandomGen g => BS.ByteString -> Otr g DSA.Signature
sign x = do
   (_, privKey) <- ask
   withRandGen $ \g -> DSA.sign g id privKey x


keyDerivs :: Integer -> KeyDerivatives
keyDerivs s = KD{..}
  where
    secBytes = Serialize.encode $ MPI s
    h2 b = SHA256.hash (BS.singleton b `BS.append` secBytes)
    kdSsid = BS.take 8 $ h2 0x00
    (kdC,kdC') = BS.splitAt 16 $ h2 0x01
    kdM1  = h2 0x02
    kdM2  = h2 0x03
    kdM1' = h2 0x04
    kdM2' = h2 0x05

putAuthstate ns = modifyState $ \s -> s{authState = ns }

m ours theirs pubKey keyId messageAuthKey = Serialize.encode m''
  where
    m' = BSL.fromChunks [ Serialize.encode $ MPI ours
                        , Serialize.encode $ MPI theirs
                        , Serialize.encode $ DsaP pubKey
                        , Serialize.encode keyId
                        ]
    m'' =  HMAC.hmac (HMAC.MacKey messageAuthKey) m' :: SHA256.SHA256
    m   = Serialize.encode m''

xs pub kid sig aesKey macKey = (xEncrypted, xSha256Mac)
  where
    x = Serialize.encode RSM { pubKey = DsaP pub
                   , keyId = kid
                   , sigB = DsaS sig
                   }
    xEncrypted = Serialize.encode . DATA $ aesCtr aesKey x
    xSha256Mac'= HMAC.hmac' (HMAC.MacKey macKey) xEncrypted :: SHA256.SHA256
    xSha256Mac = BS.take 20 $ Serialize.encode xSha256Mac'

getPrevKeyMpi :: CRandom.CryptoRandomGen g => Otr g BS.ByteString
getPrevKeyMpi = Serialize.encode . MPI . pub . ourPreviousKey <$> get

newState :: (Functor m, CRandom.CryptoRandomGen g, MonadRandom g m) => m OtrState
newState = do
    x <- randomIntegerBytes 40
    let gx = powerMod 2 x prime
    x' <- randomIntegerBytes 40
    let gx' = powerMod 2 x prime
    return OtrState { ourPreviousKey = DHKeyPair x  gx
                    , ourCurrentKey  = DHKeyPair x' gx'
                    , ourKeyId = 2
                    , theirPublicKey = Nothing
                    , theirCurrentKey = Nothing
                    , theirPreviousKey = Nothing
                    , theirKeyId = 0
                    , authState = AuthstateNone
                    }

-- -- -- bob1
bob1 :: CRandom.CryptoRandomGen g => Otr g OtrDHCommitMessage
bob1 = do
    r <- getBytes 16
    let aesKey = fromMaybe (error "buildKey Failed")
                        (Crypto.buildKey r :: Maybe Crypto.AES128)

    gxMpi <- getPrevKeyMpi
    let gxMpiAes = fst $ Crypto.ctr' Crypto.incIV aesKey Crypto.zeroIV gxMpi
    let gxMpiSha256 = SHA256.hash gxMpi
    putAuthstate $ AuthstateAwaitingDHKey r
    return DHC{..}

-- -- alice1
alice1 :: CRandom.CryptoRandomGen g
          => OtrDHCommitMessage
          -> Otr g OtrDHKeyMessage
alice1 otrcm = do
    aState <- authState <$> get
    case aState of
        AuthstateNone -> return ()
        _             -> throwError WrongState
    putAuthstate $ AuthstateAwaitingRevealsig otrcm
    DHK <$> getPrevKeyMpi

-- -- -- bob2
-- bob2 :: BS.ByteString
--      -> OtrInt
--      -> Otr (BS.ByteString, BS.ByteString, BS.ByteString)
bob2 gyMpi = do
    aState <- gets authState
    r <- case aState of
        AuthstateAwaitingDHKey r -> return r
        _ -> throwError WrongState
    checkAndSaveDHKey gyMpi
    (xbEncrypted, xbSha256Mac) <- mkAuthMessage
    putAuthstate $ AuthstateAwaitingSig
    return $! (r, xbEncrypted, xbSha256Mac)

alice2 (r, xbEncrypted, xbSha256Mac) = do
    aState <- gets authState
    DHC{..} <- case aState of
        AuthstateAwaitingRevealsig dhc -> return dhc
        _ -> throwError WrongState
    let gxMpi = aesCtr r gxMpiAes -- decrypt
    guard (SHA256.hash gxMpi == gxMpiSha256)
    checkAndSaveDHKey gxMpi
    checkAndSaveAuthMessage (xbEncrypted, xbSha256Mac)
    am <- mkAuthMessage
    putAuthstate $ AuthstateNone

bob3 (r, xaEncrypted, xaSha256Mac) = do
    aState <- gets authState

    -- KD{..} <- case aState of
    --     AuthstateAwaitingSig kd -> return kd
    --     _ -> throwError $ WrongState
    case aState of
        AuthstateAwaitingSig -> return ()
        _ -> throwError $ WrongState
    checkAndSaveAuthMessage (xaEncrypted, xaSha256Mac)
    return ()

checkAndSaveDHKey keyMpi = do
    MPI key <- case Serialize.decode keyMpi of
                   Left e -> throwError $
                               ProtocolFailure "Couldn't deserialize gy"
                   Right r -> return r
    guard (2 <= key && key <= prime - 2)
    modify (\s -> s{theirCurrentKey = Just key})

checkAndSaveAuthMessage (xEncrypted, xSha256Mac) = do
    DHKeyPair gx x <- gets ourPreviousKey
    Just gy <- gets theirCurrentKey
    (ourPub, _) <- ask
--    Just gy <- gets theirCurrentKey
    let s = powerMod gy x prime
    let KD{..} = keyDerivs s
    let xSha256Mac' = HMAC.hmac' (HMAC.MacKey kdM2) xEncrypted :: SHA256.SHA256
    guard (Serialize.encode xSha256Mac' == xSha256Mac)
    let (Right (RSM (DsaP theirPub) theirKeyId (DsaS sig))) =
                Serialize.decode $ aesCtr kdC xEncrypted
    let theirM = m gy gx theirPub theirKeyId kdM1
    -- check that the public key they present is the one we have stored (if any)
    maybe (return ()) (guard . (== theirPub)) =<< gets theirPublicKey
    guard (DSA.verify sig id theirPub theirM == Right True)
    modify $ \s -> s{ theirKeyId = theirKeyId
                    , theirPublicKey = Just theirPub
                    }

mkAuthMessage :: CRandom.CryptoRandomGen g => Otr g (BS.ByteString, BS.ByteString)
mkAuthMessage = do
    DHKeyPair gx x <- gets ourPreviousKey
    Just gy <- gets theirCurrentKey
    let s = powerMod gy x prime
    let kd@KD{..} = keyDerivs s
    (ourPub, _) <- ask
    keyId <- gets ourKeyId
    let mb = m gx gy ourPub keyId kdM1
    sig <- sign mb
    let (xbEncrypted, xbSha256Mac) = xs ourPub keyId sig kdC kdM2
    return (xbEncrypted, xbSha256Mac)

-- checkX xEncrypted xSha256 pubB = do
--     let xaSha256Mac' = HMAC.hmac' (HMAC.MacKey kdM2) xbEncrypted :: SHA256.SHA256
--     guard (encode xSha256Mac' == xSha245Mac)
--     let (Right (RSM (DsaP pubB) keyIdB (DsaS sigB))) =
--                 decode $ aesCtr aesKey xEncrypted
--     let mb = m gx gy pubB keyIdB kdM1
--     guard (DSA.verify sigB id pubB mb == Right True)
--     return () :: Maybe ()