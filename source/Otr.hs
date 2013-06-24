{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE NoMonomorphismRestriction #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE BangPatterns #-}
module Otr where

import           Control.Applicative ((<$>))
import           Control.Monad
import           Control.Monad.Error
import           Control.Monad.Identity
import           Control.Monad.Reader
import           Control.Monad.State.Strict
import qualified Crypto.Cipher.AES128 as AES
import qualified Crypto.PubKey.DH as DH
import qualified Crypto.PubKey.DSA as DSA
import qualified Crypto.Classes as Crypto
import qualified Crypto.HMAC as HMAC
import qualified Crypto.Hash.SHA256 as SHA256 (hash)
import qualified Crypto.Hash.CryptoAPI as Crypto
import qualified Crypto.Modes as Crypto (zeroIV)
import qualified Crypto.Random as CRandom
import           Data.Bits
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BSL
import           Data.Maybe(fromMaybe)
import qualified Data.Serialize as Serialize
import           Data.Word
import           Math.NumberTheory.Powers(powerMod)
import           Numeric
import           Otr.Monad
import           System.Random

import           Otr.Types
import           Otr.Serialize

getState :: Monad m => OtrT g m OtrState
getState = OtrT . lift $ get

putState :: Monad m => OtrState -> OtrT g m ()
putState = OtrT . lift . put

modifyState :: Monad m => (OtrState -> OtrState) -> OtrT g m ()
modifyState f = putState . f =<< getState


showBits a = reverse [if testBit a i then '1' else '0' | i <- [0.. bitSize a - 1]]

prime :: Integer
prime = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF

params = (prime, 2)

mapLeft f (Left l) = Left $ f l
mapLeft _ (Right r) = Right r

-- randomIntegerBytes :: Int ->Otr Integer
randomIntegerBytes :: (CRandom.CryptoRandomGen g, MonadRandom g m)
                   => Int -> m Integer
randomIntegerBytes b = (rollInteger . BS.unpack) `liftM` getBytes b

aesCtr :: BS.ByteString -> BS.ByteString -> BS.ByteString
aesCtr k x = fst $ Crypto.ctr key Crypto.zeroIV x
  where
    key = case Crypto.buildKey k :: Maybe AES.AESKey of
        Nothing -> error "Could not produce key"
        Just k -> k

-- sign :: (Monad m, CRandom.CryptoRandomGen g) =>
--      BS.ByteString -> OtrT g m DSA.Signature
sign !x = do
   (_, privKey) <- OtrT ask
   r <- OtrT . withRandGen $ \g -> case DSA.sign g privKey id x of
       (r, g) -> Right (r, g)
   return r


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

putAuthstate :: Monad m => Authstate -> OtrT g m ()
putAuthstate ns = modifyState $ \s -> s{authState = ns }

putMsgstate :: Monad m => Msgstate -> OtrT g m ()
putMsgstate ns = modifyState $ \s -> s{msgState = ns }

m :: Serialize.Serialize a => Integer
     -> Integer -> DSA.PublicKey -> a -> BS.ByteString -> BS.ByteString
m ours theirs pubKey keyId messageAuthKey = Serialize.encode m''
  where
    m' = BSL.fromChunks [ Serialize.encode $ MPI ours
                        , Serialize.encode $ MPI theirs
                        , Serialize.encode $ DsaP pubKey
                        , Serialize.encode keyId
                        ]
    m'' =  HMAC.hmac (HMAC.MacKey messageAuthKey) m' :: Crypto.SHA256
    m   = Serialize.encode m''

xs :: DSA.PublicKey
     -> OtrInt
     -> DSA.Signature
     -> BS.ByteString
     -> BS.ByteString
     -> (DATA, DATA)
xs pub kid sig aesKey macKey = (DATA xEncrypted, DATA xSha256Mac)
  where
    x = Serialize.encode sd
    sd = SD{ sdPub = DsaP pub
           , sdKeyId = kid
           , sdSig = DsaS sig
           }
    xEncrypted = aesCtr aesKey x
    xEncryptedD = Serialize.encode $ DATA xEncrypted
    xSha256Mac'= HMAC.hmac' (HMAC.MacKey macKey) xEncryptedD :: Crypto.SHA256
    xSha256Mac = BS.take 20 $ Serialize.encode xSha256Mac'

getPrevKeyMpi :: Monad m => OtrT g m BS.ByteString
getPrevKeyMpi = (Serialize.encode . MPI . pub . ourPreviousKey) `liftM` OtrT get

newState :: (CRandom.CryptoRandomGen g, MonadRandom g m) => m OtrState
newState = do
    x <- randomIntegerBytes 40
    let gx = powerMod 2 x prime
    x' <- randomIntegerBytes 40
    let gx' = powerMod 2 x prime
    return OtrState { ourPreviousKey = DHKeyPair gx  x
                    , ourCurrentKey  = DHKeyPair gx' x'
                    , ourKeyId = 2
                    , theirPublicKey = Nothing
                    , theirCurrentKey = Nothing
                    , theirPreviousKey = Nothing
                    , theirKeyId = 0
                    , authState = AuthstateNone
                    , msgState = MsgstatePlaintext
                    }

protocolGuard :: MonadError OtrError m => ProtocolError -> Bool -> m ()
protocolGuard e p = unless p . throwError $ ProtocolError e

-- -- -- bob1

-- bob1 :: (Monad m, CRandom.CryptoRandomGen g) =>
--      OtrT g m OtrDHCommitMessage
bob1 = do
    r <- getBytes 16
    gx <- OtrT . gets $ pub . ourPreviousKey
    let gxMpi = Serialize.encode $ MPI gx
    let gxMpiAes = DATA $ aesCtr r gxMpi
    let gxMpiSha256 = DATA . SHA256.hash $ gxMpi
    putAuthstate $ AuthstateAwaitingDHKey r
    return DHC{..}


-- -- alice1
-- alice1 :: (Monad m, Functor m) => OtrDHCommitMessage -> OtrT g m OtrDHKeyMessage
alice1 otrcm = do
    aState <- authState <$> getState
    case aState of
        AuthstateNone -> return ()
        _             -> OtrT $ throwError WrongState
    putAuthstate $ AuthstateAwaitingRevealsig otrcm
    gy <- OtrT . gets $ pub .  ourPreviousKey
    let gyMpi = Serialize.encode $ MPI gy
    return $ DHK gyMpi

-- bob2 :: (Monad m, Functor m, CRandom.CryptoRandomGen g) =>
--      OtrDHKeyMessage -> OtrT g m OtrRevealSignatureMessage
bob2 (DHK gyMpi) = do
    aState <- authState <$> getState
    r <- case aState of
        AuthstateAwaitingDHKey r -> return r
        _ -> throwError WrongState
    checkAndSaveDHKey gyMpi
    sm <- mkAuthMessage
    putAuthstate $ AuthstateAwaitingSig
    return $! (RSM (DATA r) sm)

-- alice2 :: (Monad m, Functor m, CRandom.CryptoRandomGen g) =>
--      OtrRevealSignatureMessage -> OtrT g m OtrSignatureMessage
alice2 (RSM r sm) = do
    aState <- authState <$> getState
    DHC{..} <- case aState of
        AuthstateAwaitingRevealsig dhc -> return dhc
        _ -> throwError WrongState
    let gxMpi = aesCtr (unDATA r) (unDATA gxMpiAes) -- decrypt
    protocolGuard HashMismatch (SHA256.hash gxMpi == unDATA gxMpiSha256)
    checkAndSaveDHKey gxMpi
    checkAndSaveAuthMessage sm
    am <- mkAuthMessage
    putAuthstate $ AuthstateNone
    return am

-- bob3 :: Monad m => OtrSignatureMessage -> OtrT g m ()
bob3 (SM xaEncrypted xaSha256Mac) = do
    aState <- OtrT $ gets authState
    case aState of
        AuthstateAwaitingSig -> return ()
        _ -> throwError $ WrongState
    checkAndSaveAuthMessage (SM xaEncrypted xaSha256Mac)
    putAuthstate $ AuthstateNone
    return ()

-- checkAndSaveDHKey :: Monad m => BS.ByteString -> OtrT g m ()
checkAndSaveDHKey keyMpi = do
    MPI key <- case Serialize.decode keyMpi of
                   Left e -> OtrT . throwError $ ProtocolError DeserializationError
                   Right r -> return r
    protocolGuard KeyRange (2 <= key && key <= prime - 2)
    OtrT $ modify (\s -> s{theirCurrentKey = Just key})

-- checkAndSaveAuthMessage :: Monad m => OtrSignatureMessage -> OtrT g m ()
checkAndSaveAuthMessage (SM (DATA xEncrypted) (DATA xSha256Mac)) = do
    DHKeyPair gx x <- OtrT $ gets ourPreviousKey
    Just gy <- OtrT $ gets theirCurrentKey
    let s = powerMod gy x prime
    let KD{..} = keyDerivs s
    let xEncryptedD = Serialize.encode $ DATA xEncrypted
    let xSha256Mac' = HMAC.hmac' (HMAC.MacKey kdM2) xEncryptedD :: Crypto.SHA256
    protocolGuard MACFailure (BS.take 20 (Serialize.encode xSha256Mac') == xSha256Mac)
    let (Right (SD (DsaP theirPub) theirKeyId (DsaS sig))) =
                Serialize.decode $ aesCtr kdC xEncrypted
    let theirM = m gy gx theirPub theirKeyId kdM1
    liftIO . print $ theirM
    -- check that the public key they present is the one we have stored (if any)
    storedPubkey <- OtrT $ gets theirPublicKey
    case storedPubkey of
        Nothing -> return ()
        Just sp -> protocolGuard PubkeyMismatch (sp == theirPub)
    protocolGuard SignatureMismatch
                  (DSA.verify id  theirPub sig theirM == True)
    OtrT . modify $ \s -> s{ theirKeyId = theirKeyId
                           , theirPublicKey = Just theirPub
                           }

-- mkAuthMessage :: (Monad m, Functor m, CRandom.CryptoRandomGen g) =>
--      OtrT g m OtrSignatureMessage
mkAuthMessage = do
    DHKeyPair gx x <- ourPreviousKey <$> getState
    Just gy <- theirCurrentKey <$> getState
    let s = powerMod gy x prime
    let kd@KD{..} = keyDerivs s
    (ourPub, _) <- OtrT ask
    keyId <- OtrT $ gets ourKeyId
    let mb = m gx gy ourPub keyId kdM1
    liftIO $ putStr "mk: "
    liftIO . print $ mb
    sig <- sign mb
    let (xbEncrypted, xbSha256Mac) = xs ourPub keyId sig kdC kdM2
    return $ SM xbEncrypted xbSha256Mac

-- checkX xEncrypted xSha256 pubB = do
--     let xaSha256Mac' = HMAC.hmac' (HMAC.MacKey kdM2) xbEncrypted :: Crypto.SHA256
--     guard (encode xSha256Mac' == xSha245Mac)
--     let (Right (RSM (DsaP pubB) keyIdB (DsaS sigB))) =
--                 decode $ aesCtr aesKey xEncrypted
--     let mb = m gx gy pubB keyIdB kdM1
--     guard (DSA.verify sigB id pubB mb == Right True)
--     return () :: Maybe ()
