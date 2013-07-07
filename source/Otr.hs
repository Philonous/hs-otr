{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE NoMonomorphismRestriction #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE BangPatterns #-}
module Otr
  ( module Otr
  , module Otr.Types
  ) where
import           Control.Applicative ((<$>))
import           Control.Concurrent.MVar
import           Control.Monad
import           Control.Monad.Error
import           Control.Monad.Reader
import           Control.Monad.State.Strict
import qualified Crypto.Cipher.AES as AES
import qualified Crypto.Classes as Crypto
import qualified Crypto.HMAC as HMAC
import qualified Crypto.Hash.CryptoAPI as Crypto
import qualified Crypto.Hash.SHA256 as SHA256 (hash)
import qualified Crypto.Modes as Crypto (zeroIV)
import qualified Crypto.PubKey.DSA as DSA
import qualified Crypto.Random.API as CRandom
import           Data.Bits hiding (shift)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BSL
import qualified Data.Serialize as Serialize
import           Math.NumberTheory.Powers(powerMod)

import           Otr.Monad
import           Otr.Types

getState :: Monad m => OtrT g m OtrState
getState = OtrT . lift $ get

putState :: Monad m => OtrState -> OtrT g m ()
putState = OtrT . lift . put

modifyState :: Monad m => (OtrState -> OtrState) -> OtrT g m ()
modifyState f = putState . f =<< getState


showBits :: Bits a => a -> [Char]
showBits a = reverse [if testBit a i then '1' else '0' | i <- [0.. bitSize a - 1]]

prime :: Integer
prime = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF

params :: Num t => (Integer, t)
params = (prime, 2)

mapLeft :: (t -> a) -> Either t b -> Either a b
mapLeft f (Left l) = Left $ f l
mapLeft _ (Right r) = Right r

-- randomIntegerBytes :: Int ->Otr Integer
randomIntegerBytes :: (CRandom.CPRG g, MonadRandom g m)
                   => Int -> m Integer
randomIntegerBytes b = (rollInteger . BS.unpack) `liftM` getBytes b

aesCtr :: BS.ByteString -> BS.ByteString -> BS.ByteString
aesCtr k x = AES.decryptCTR key zeroIV x
  where
    key = AES.initKey k
    zeroIV = AES.IV . BS.pack $ replicate 16 0

sign !x = do
   (_, privKey) <- OtrT ask
   r <- OtrT . withRandGen $ \g -> DSA.sign g privKey id x
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

getPrevKeyMpi :: Monad m => OtrT g m BS.ByteString
getPrevKeyMpi = (Serialize.encode . MPI . pub . ourPreviousKey) `liftM` OtrT get

newState :: (CRandom.CPRG g, MonadRandom g m) => m OtrState
newState = do
    x <- randomIntegerBytes 40
    let gx = powerMod 2 x prime
    x' <- randomIntegerBytes 40
    let gx' = powerMod 2 x prime
    -- smallest possible instance Tag
    it <- ((0x100 .|.) . fromIntegral) `liftM` randomIntegerBytes 4
    return OtrState { ourPreviousKey = DHKeyPair gx  x
                    , ourCurrentKey  = DHKeyPair gx' x'
                    , ourKeyId = 2
                    , ourIT = it
                    , theirPublicKey = Nothing
                    , theirCurrentKey = Nothing
                    , theirPreviousKey = Nothing
                    , theirKeyId = 0
                    , theirIT = 0
                    , authState = AuthstateNone
                    , msgState = MsgstatePlaintext
                    }

protocolGuard :: MonadError OtrError m => ProtocolError -> Bool -> m ()
protocolGuard e p = unless p . throwError $ ProtocolError e

bob1
  :: (Monad m, CRandom.CPRG g) =>
     OtrT g m OtrDHCommitMessage
bob1 = do
    r <- getBytes 16
    gx <- OtrT . gets $ pub . ourPreviousKey
    let gxMpi = Serialize.encode $ MPI gx
    let gxMpiAes = DATA $ aesCtr r gxMpi
    let gxMpiSha256 = DATA . SHA256.hash $ gxMpi
    putAuthstate $ AuthstateAwaitingDHKey r
    return DHC{..}

alice1
  :: (Monad m, Functor m) =>
     OtrDHCommitMessage -> OtrT g m OtrDHKeyMessage
alice1 otrcm = do
    aState <- authState <$> getState
    case aState of
        AuthstateNone -> return ()
        _             -> OtrT $ throwError WrongState
    putAuthstate $ AuthstateAwaitingRevealsig otrcm
    gy <- OtrT . gets $ pub . ourPreviousKey
    return $ DHK (MPI gy)


bob2 (DHK gyMpi) = do
    aState <- authState <$> getState
    r <- case aState of
        AuthstateAwaitingDHKey r -> return r
        _ -> throwError WrongState
    checkAndSaveDHKey gyMpi
    sm <- mkAuthMessage KeysRSM
    putAuthstate $ AuthstateAwaitingSig
    return $! RSM (DATA r) sm

-- alice2 :: (Monad m, Functor m, CRandom.CryptoRandomGen g) =>
--      OtrRevealSignatureMessage -> OtrT g m OtrSignatureMessage
alice2 (RSM r sm) = do
    aState <- authState <$> getState
    DHC{..} <- case aState of
        AuthstateAwaitingRevealsig dhc -> return dhc
        _ -> throwError WrongState
    let gxMpi = aesCtr (unDATA r) (unDATA gxMpiAes) -- decrypt
    protocolGuard HashMismatch (SHA256.hash gxMpi == unDATA gxMpiSha256)
    gx <- case Serialize.decode gxMpi of
        Right mpi@MPI{} -> return mpi
        Left e -> throwError . ProtocolError .  DeserializationError $
          "Could not decode gx MPI: " ++ show e
    checkAndSaveDHKey gx
    checkAndSaveAuthMessage KeysRSM sm
    am <- mkAuthMessage KeysSM
    putAuthstate $ AuthstateNone
    return am

-- bob3 :: Monad m => OtrSignatureMessage -> OtrT g m ()
bob3 (SM xaEncrypted xaSha256Mac) = do
    aState <- OtrT $ gets authState
    case aState of
        AuthstateAwaitingSig -> return ()
        _ -> throwError $ WrongState
    checkAndSaveAuthMessage KeysSM (SM xaEncrypted xaSha256Mac)
    putAuthstate $ AuthstateNone
    return ()

data AuthKeys = KeysRSM -- RevealSignatureMessage
              | KeysSM  -- SignatureMessage

-- checkAndSaveDHKey :: Monad m => BS.ByteString -> OtrT g m ()
checkAndSaveDHKey :: Monad m => MPI -> OtrT g m ()
checkAndSaveDHKey (MPI key) = do
    protocolGuard KeyRange (2 <= key && key <= prime - 2)
    OtrT $ modify (\s -> s{theirCurrentKey = Just key})

-- checkAndSaveAuthMessage :: Monad m => OtrSignatureMessage -> OtrT g m ()
checkAndSaveAuthMessage keyType (SM (DATA xEncrypted) (MAC xSha256Mac)) = do
    DHKeyPair gx x <- OtrT $ gets ourPreviousKey
    Just gy <- OtrT $ gets theirCurrentKey
    let s = powerMod gy x prime
        KD{..} = keyDerivs s
        (macKey1, macKey2, aesKey)  = case keyType of
            KeysRSM -> (kdM1 , kdM2 , kdC )
            KeysSM  -> (kdM1', kdM2', kdC')
        xEncryptedD = Serialize.encode $ DATA xEncrypted
        xSha256Mac' = HMAC.hmac' (HMAC.MacKey macKey2) xEncryptedD :: Crypto.SHA256
    protocolGuard MACFailure (BS.take 20 (Serialize.encode xSha256Mac') == xSha256Mac) -- TODO: reinstate
    let (Right (SD (DsaP theirPub) theirKeyId (DsaS sig))) =
                Serialize.decode $ aesCtr aesKey xEncrypted
        theirM = m gy gx theirPub theirKeyId macKey1
    -- check that the public key they present is the one we have stored (if any)
    storedPubkey <- OtrT $ gets theirPublicKey
    case storedPubkey of
        Nothing -> return ()
        Just sp -> protocolGuard PubkeyMismatch (sp == theirPub)
    protocolGuard SignatureMismatch $ DSA.verify id theirPub sig theirM
    OtrT . modify $ \s' -> s'{ theirKeyId = theirKeyId
                             , theirPublicKey = Just theirPub
                             }

-- mkAuthMessage :: (Monad m, Functor m, CRandom.CryptoRandomGen g) =>
--      OtrT g m OtrSignatureMessage
mkAuthMessage keyType = do
    DHKeyPair gx x <- ourPreviousKey <$> getState
    Just gy <- theirCurrentKey <$> getState
    let s = powerMod gy x prime
    let KD{..} = keyDerivs s
    let (macKey1, macKey2, aesKey)  = case keyType of
            KeysRSM -> (kdM1 , kdM2 , kdC )
            KeysSM  -> (kdM1', kdM2', kdC')
    (ourPub, _) <- OtrT ask
    keyId <- OtrT $ gets ourKeyId
    let mb = m gx gy ourPub keyId macKey1
    sig <- sign mb
    let (xbEncrypted, xbSha256Mac) = xs ourPub keyId sig aesKey macKey2
    return $ SM xbEncrypted xbSha256Mac

xs :: DSA.PublicKey
     -> OtrInt
     -> DSA.Signature
     -> BS.ByteString
     -> BS.ByteString
     -> (DATA, MAC)
xs pub kid sig aesKey macKey = (DATA xEncrypted, MAC xSha256Mac)
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


bob :: CRandom.CPRG g => Otr g ()
bob = do
    sendMessage . DHCommitMessage =<< bob1
    DHKeyMessage msg1 <- recvMessage
    sendMessage . RevealSignatureMessage =<< bob2 msg1
    SignatureMessage msg2 <- recvMessage
    bob3 msg2

-- alice :: CRandom.CPRG g => Otr g ()
alice = do
    DHCommitMessage msg1 <- recvMessage
    sendMessage . DHKeyMessage =<< alice1 msg1
    RevealSignatureMessage msg2 <- recvMessage
    sendMessage . SignatureMessage =<< alice2 msg2

newSession :: (OtrMessage -> IO a)
           -> IO OtrMessage
           -> Otr CRandom.SystemRandom ()
           -> (DSA.PublicKey, DSA.PrivateKey)
           -> IO (Either OtrError (MVar (OtrState, CRandom.SystemRandom)))
newSession sm rm side keys = do
    g <- CRandom.getSystemRandomGen
    let (st, g') = runRand g newState
    res <- runMessaging sm rm $ runOtrT keys st side g
    case res of
        Left e -> return $ Left e
        Right (((), st), g) -> Right <$> newMVar (st,g)
