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
import qualified Crypto.Hash.SHA1 as SHA1 (hash)
import qualified Crypto.Modes as Crypto (zeroIV)
import qualified Crypto.PubKey.DSA as DSA
import qualified Crypto.Random.API as CRandom
import           Data.Bits hiding (shift)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BSL
import qualified Data.Serialize as Serialize
import qualified Data.Serialize.Put as Serialize
import           Math.NumberTheory.Powers(powerMod)
import qualified Control.Exception as Ex
import qualified System.IO.Unsafe as Unsafe

import           Otr.Monad
import           Otr.Types
import           Otr.Serialize

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

makeDHKeyPair :: (CRandom.CPRG g, MonadRandom g m) => m DHKeyPair
makeDHKeyPair =  do
    x <- randomIntegerBytes 40
    let gx = powerMod 2 x prime
    return $ DHKeyPair gx x

makeDHSharedSecret private public prime = powerMod public private prime

mapLeft :: (t -> a) -> Either t b -> Either a b
mapLeft f (Left l) = Left $ f l
mapLeft _ (Right r) = Right r

-- randomIntegerBytes :: Int ->Otr Integer
randomIntegerBytes :: (CRandom.CPRG g, MonadRandom g m)
                   => Int -> m Integer
randomIntegerBytes b = (rollInteger . BS.unpack) `liftM` getBytes b

aesCtr :: AES.IV -> BS.ByteString -> BS.ByteString -> BS.ByteString
aesCtr iv k x = AES.decryptCTR key iv x
  where
    key = AES.initKey k

aesCtrZero :: BS.ByteString -> BS.ByteString -> BS.ByteString
aesCtrZero = aesCtr zeroIV
  where
    zeroIV = AES.IV . BS.pack $ replicate 16 0

sign !x = do
   (_, privKey) <- OtrT ask
   r <- OtrT . withRandGen $ \g -> DSA.sign g privKey id x
   return r


keyDerivs :: Integer -> KeyDerivatives
keyDerivs s = KD{..}
  where
    secBytes = Serialize.encode $ MPI s
    h2 b = (Unsafe.unsafePerformIO $ do
                 putStr "### "
                 print secBytes) `seq`
           SHA256.hash (BS.singleton b `BS.append` secBytes)
    kdSsid = BS.take 8 $ h2 0x00
    (kdC,kdC') = BS.splitAt 16 $ h2 0x01
    kdM1  = h2 0x02
    kdM2  = h2 0x03
    kdM1' = h2 0x04
    kdM2' = h2 0x05

putAuthState :: Monad m => AuthState -> OtrT g m ()
putAuthState ns = modifyState $ \s -> s{authState = ns }

putMsgState :: Monad m => MsgState -> OtrT g m ()
putMsgState ns = modifyState $ \s -> s{msgState = ns }

m :: Serialize.Serialize a => Integer
     -> Integer -> DSA.PublicKey -> a -> BS.ByteString -> BS.ByteString
m ours theirs pubKey keyID messageAuthKey = Serialize.encode m''
  where
    m' = BSL.fromChunks [ Serialize.encode $ MPI ours
                        , Serialize.encode $ MPI theirs
                        , Serialize.encode $ DsaP pubKey
                        , Serialize.encode keyID
                        ]
    m'' =  HMAC.hmac (HMAC.MacKey messageAuthKey) m' :: Crypto.SHA256

getPrevKeyMpi :: Monad m => OtrT g m BS.ByteString
getPrevKeyMpi = (Serialize.encode . MPI . pub . ourPreviousKey) `liftM` OtrT get

newState :: (CRandom.CPRG g, MonadRandom g m) => m OtrState
newState = do
    opk <- makeDHKeyPair
    ock <- makeDHKeyPair
    ndh <- makeDHKeyPair
    -- instance Tag has to be >= 0x100
    it <- ((0x100 .|.) . fromIntegral) `liftM` randomIntegerBytes 4
    return OtrState { ourPreviousKey = opk
                    , ourCurrentKey  = ock
                    , ourKeyID = 1
                    , ourIT = it
                    , theirPublicKey = Nothing
                    , theirCurrentKey = Nothing
                    , mostRecentKey = 2
                    , nextDH = ndh
                    , theirPreviousKey = Nothing
                    , theirKeyID = 0
                    , theirIT = 0
                    , authState = AuthStateNone
                    , msgState = MsgStatePlaintext
                    , counter = 1
                    }

protocolGuard :: MonadError OtrError m => ProtocolError -> Bool -> m ()
protocolGuard e p = unless p . throwError $ ProtocolError e

bob1
  :: (Monad m, CRandom.CPRG g) =>
     OtrT g m OtrDHCommitMessage
bob1 = do
    r <- getBytes 16
    gx <- OtrT . gets $ pub . ourCurrentKey
    let gxMpi = Serialize.encode $ MPI gx
    let gxMpiAes = DATA $ aesCtrZero r gxMpi
    let gxMpiSha256 = DATA . SHA256.hash $ gxMpi
    putAuthState $ AuthStateAwaitingDHKey r
    return DHC{..}

alice1
  :: (Monad m, Functor m) =>
     OtrDHCommitMessage -> OtrT g m OtrDHKeyMessage
alice1 otrcm = do
    aState <- authState <$> getState
    case aState of
        AuthStateNone -> return ()
        _             -> OtrT $ throwError WrongState
    putAuthState $ AuthStateAwaitingRevealsig otrcm
    gy <- OtrT . gets $ pub . ourCurrentKey
    return $ DHK (MPI gy)


bob2 (DHK gyMpi) = do
    aState <- authState <$> getState
    r <- case aState of
        AuthStateAwaitingDHKey r -> return r
        _ -> throwError WrongState
    checkAndSaveDHKey gyMpi
    sm <- mkAuthMessage KeysRSM
    putAuthState $ AuthStateAwaitingSig
    return $! RSM (DATA r) sm

-- alice2 :: (Monad m, Functor m, CRandom.CryptoRandomGen g) =>
--      OtrRevealSignatureMessage -> OtrT g m OtrSignatureMessage
alice2 (RSM r sm) = do
    aState <- authState <$> getState
    DHC{..} <- case aState of
        AuthStateAwaitingRevealsig dhc -> return dhc
        _ -> throwError WrongState
    let gxMpi = aesCtrZero (unDATA r) (unDATA gxMpiAes) -- decrypt
    protocolGuard HashMismatch (SHA256.hash gxMpi == unDATA gxMpiSha256)
    gx <- case Serialize.decode gxMpi of
        Right mpi@MPI{} -> return mpi
        Left e -> throwError . ProtocolError .  DeserializationError $
          "Could not decode gx MPI: " ++ show e
    checkAndSaveDHKey gx
    checkAndSaveAuthMessage KeysRSM sm
    am <- mkAuthMessage KeysSM
    putAuthState AuthStateNone
    putMsgState MsgStateEncrypted
    return am

-- bob3 :: Monad m => OtrSignatureMessage -> OtrT g m ()
bob3 (SM xaEncrypted xaSha256Mac) = do
    aState <- OtrT $ gets authState
    case aState of
        AuthStateAwaitingSig -> return ()
        _ -> throwError $ WrongState
    checkAndSaveAuthMessage KeysSM (SM xaEncrypted xaSha256Mac)
    putAuthState AuthStateNone
    putMsgState MsgStateEncrypted
    return ()

data AuthKeys = KeysRSM -- RevealSignatureMessage
              | KeysSM  -- SignatureMessage

-- checkAndSaveDHKey :: Monad m => BS.ByteString -> OtrT g m ()
checkAndSaveDHKey :: Monad m => MPI -> OtrT g m ()
checkAndSaveDHKey (MPI key) = do
    protocolGuard KeyRange (2 <= key && key <= prime - 2)
    OtrT $ modify (\s -> s{theirCurrentKey = Just key})

mkMessageHeader :: OtrByte -> Otr g OtrMessageHeader
mkMessageHeader tp = do
    tit <- OtrT $ gets theirIT
    oit <- OtrT $ gets ourIT
    return MH{ version = 3
             , messageType = tp
             , senderITag = oit
             , receiverITag = tit
             }

mkMessage :: OtrMessageBody -> Otr g OtrMessage
mkMessage msgBody = do
    let tp = case msgBody of
            DHCommitMessage b        -> 0x02
            DHKeyMessage b           -> 0x0a
            RevealSignatureMessage b -> 0x11
            SignatureMessage b       -> 0x12
            DataMessage b            -> 0x03
    mh <- mkMessageHeader tp
    return OM { messageHeader = mh
              , messageBody = msgBody
              }


checkAndSaveAuthMessage keyType (SM (DATA xEncrypted) (MAC xSha256Mac)) = do
    DHKeyPair gx x <- OtrT $ gets ourCurrentKey
    Just gy <- OtrT $ gets theirCurrentKey
    let s = makeDHSharedSecret x gy prime
        KD{..} = keyDerivs s
        (macKey1, macKey2, aesKey)  = case keyType of
            KeysRSM -> (kdM1 , kdM2 , kdC )
            KeysSM  -> (kdM1', kdM2', kdC')
        xEncryptedD = Serialize.encode $ DATA xEncrypted
        xSha256Mac' = HMAC.hmac' (HMAC.MacKey macKey2) xEncryptedD :: Crypto.SHA256
    protocolGuard MACFailure (BS.take 20 (Serialize.encode xSha256Mac') == xSha256Mac)
    let (Right (SD (DsaP theirPub) theirKeyID (DsaS sig))) =
                Serialize.decode $ aesCtrZero aesKey xEncrypted
        theirM = m gy gx theirPub theirKeyID macKey1
    -- check that the public key they present is the one we have stored (if any)
    storedPubkey <- OtrT $ gets theirPublicKey
    case storedPubkey of
        Nothing -> return ()
        Just sp -> protocolGuard PubkeyMismatch (sp == theirPub)
    protocolGuard SignatureMismatch $ DSA.verify id theirPub sig theirM
    OtrT . modify $ \s' -> s'{ theirKeyID = theirKeyID
                             , theirPublicKey = Just theirPub
                             }

-- mkAuthMessage :: (Monad m, Functor m, CRandom.CryptoRandomGen g) =>
--      OtrT g m OtrSignatureMessage
mkAuthMessage keyType = do
    DHKeyPair gx x <- ourCurrentKey <$> getState
    Just gy <- theirCurrentKey <$> getState
    let s = makeDHSharedSecret x gy prime
    let KD{..} = keyDerivs s
    let (macKey1, macKey2, aesKey)  = case keyType of
            KeysRSM -> (kdM1 , kdM2 , kdC )
            KeysSM  -> (kdM1', kdM2', kdC')
    (ourPub, _) <- OtrT ask
    keyID <- OtrT $ gets ourKeyID
    let mb = m gx gy ourPub keyID macKey1
    sig <- sign mb
    let (xbEncrypted, xbSha256Mac) = xs ourPub keyID sig aesKey macKey2
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
           , sdKeyID = kid
           , sdSig = DsaS sig
           }
    xEncrypted = aesCtrZero aesKey x
    xEncryptedD = Serialize.encode $ DATA xEncrypted
    xSha256Mac'= HMAC.hmac' (HMAC.MacKey macKey) xEncryptedD :: Crypto.SHA256
    xSha256Mac = BS.take 20 $ Serialize.encode xSha256Mac'


bob :: CRandom.CPRG g => Otr g ()
bob = do
    sendMessage =<< mkMessage . DHCommitMessage =<< bob1
    DHKeyMessage msg1 <- messageBody <$> recvMessage
    sendMessage =<< mkMessage . RevealSignatureMessage =<< bob2 msg1
    SignatureMessage msg2 <- messageBody <$> recvMessage
    bob3 msg2

-- alice :: CRandom.CPRG g => Otr g ()
alice = do
    DHCommitMessage msg1 <- messageBody <$> recvMessage
    sendMessage =<< mkMessage . DHKeyMessage =<< alice1 msg1
    RevealSignatureMessage msg2 <- messageBody <$> recvMessage
    sendMessage =<< mkMessage . SignatureMessage =<< alice2 msg2

type DSAKeys = (DSA.PublicKey, DSA.PrivateKey)

newSession :: (OtrMessage -> IO a)
           -> IO OtrMessage
           -> Otr CRandom.SystemRandom ()
           -> DSAKeys
           -> IO (Either OtrError
                  (DSAKeys, (MVar (OtrState, CRandom.SystemRandom))))
newSession sm rm side keys = do
    g <- CRandom.getSystemRandomGen
    let (st, g') = runRand g newState
    res <- runMessaging sm rm $ runOtrT keys st side g
    case res of
        Left e -> return $ Left e
        Right (((), st), g) -> Right . (,) keys  <$> newMVar (st,g)

withSession
  :: ((DSA.PublicKey, DSA.PrivateKey), MVar (OtrState, g))
     -> (OtrMessage -> IO a)
     -> IO OtrMessage
     -> OtrT g Messaging b
     -> IO (Either OtrError b)
withSession (keys, s) sm rm f = do
    Ex.bracketOnError (takeMVar s)
                      (putMVar s) $ \(st, g) -> do
        res <- runMessaging sm rm $ runOtrT keys st f g
        case res of
            Left e -> return $ Left e
            Right ((a, st), g) -> do
                putMVar s (st, g)
                return $ Right a

makeMessageKeys tKeyID oKeyID = do
    OtrState{..} <- OtrT get
    tck <- case ( tKeyID == theirKeyID - 1
                , tKeyID == theirKeyID
                , theirPreviousKey
                , theirCurrentKey
                ) of
               (True, _   , Just tpk , _        ) -> return tpk
               (True, _   , Nothing  , _        ) -> throwError NoPeerDHKey
               (_   , True, _        , Just tck ) -> return tck
               (_   , True, _        , Nothing  ) -> throwError NoPeerDHKey
               _                              -> throwError
                                                 $ ProtocolError WrongKeyID
    ok <- case ( oKeyID == ourKeyID
               , oKeyID == ourKeyID + 1
                ) of
               (True, _) -> return ourCurrentKey
               (_, True) -> return nextDH
               _ -> throwError $ ProtocolError WrongKeyID
    let sharedSecret = makeDHSharedSecret (priv ok) tck prime
        secBytes = Serialize.runPut . putMPI $ MPI sharedSecret
        (sendByte, recvByte) = if tck <= pub ok
                               then (0x01, 0x02)
                               else (0x02, 0x01)
        h1 b = (Unsafe.unsafePerformIO $ do
                     putStr "$$$"
                     print secBytes) `seq`
               SHA1.hash (BS.singleton b `BS.append` secBytes)
        sendAES = BS.take 16 $ h1 sendByte
        sendMAC = SHA1.hash sendAES
        recvAES = BS.take 16 $ h1 recvByte
        recvMAC = SHA1.hash recvAES
    return MK{..}

sendDataMessage payload = do
    OtrState{..} <- OtrT get
    mh <- mkMessageHeader 0x03
    unless (msgState == MsgStateEncrypted) $ throwError WrongState
    MK{..} <- makeMessageKeys theirKeyID ourKeyID
    let ctr = AES.IV . Serialize.runPut $ do
            Serialize.putWord64be counter
            Serialize.putWord64be 0
        pl = aesCtr ctr sendAES . Serialize.runPut $ putMP payload
        rawDataMessage = RDM { flags = 0
                             , senderKeyID = ourKeyID
                             , recipientKeyID = theirKeyID
                             , nextDHy = MPI . pub $ nextDH
                             , ctrHi = counter
                             , messageAes128 = DATA pl
                             }
        messageBytes = Serialize.runPut $ do
            putMessageHeader mh
            putRDM rawDataMessage
        messageMAC' = HMAC.hmac' (HMAC.MacKey sendMAC) messageBytes :: Crypto.SHA1
        messageMAC = MAC $ Serialize.encode messageMAC'
        oldMACKeys = DATA BS.empty -- TODO
        outMsg = DataMessage $ DM{..}
    OtrT $ modify (\s -> s{counter = counter + 1})
    sendMessage =<< mkMessage outMsg

recvDataMessage = do
    OtrState{..} <- OtrT get
    unless (msgState == MsgStateEncrypted) $ throwError WrongState
    msg' <- recvMessage
    case messageBody msg' of
        DataMessage msg@DM{rawDataMessage = rdm@RDM{..}} -> do
            mk@MK{..} <- makeMessageKeys senderKeyID recipientKeyID
            -- recreate the part of the message until the beginning of the MAC
            let msgBytes = Serialize.runPut $ do
                    putMessageHeader $ messageHeader msg'
                    putRDM rdm
                mMAC' = HMAC.hmac' (HMAC.MacKey recvMAC) msgBytes :: Crypto.SHA1
                mMAC = MAC $ Serialize.encode mMAC'
            -- TODO: register recvMac
            protocolGuard MACFailure (mMAC == messageMAC msg)
            case () of () | recipientKeyID == ourKeyID    -> return ()
                          | recipientKeyID == ourKeyID +1 -> shiftKeys
                          | otherwise -> throwError $ ProtocolError WrongKeyID
            let ctr = AES.IV . Serialize.runPut $ do
                    Serialize.putWord64be ctrHi
                    Serialize.putWord64be 0
                pl = aesCtr ctr recvAES $ unDATA messageAes128
                mp = Serialize.runGet getMP pl
            shiftTheirKeys (unMPI nextDHy) senderKeyID
            return mp
        _ -> throwError WrongState

  where
    shiftKeys = do
        newDH <- makeDHKeyPair
        s@OtrState{..} <- OtrT get
        OtrT $ put s{ ourPreviousKey = ourCurrentKey
                    , ourCurrentKey = nextDH
                    , nextDH = newDH
                    , ourKeyID = ourKeyID + 1
                    }
    shiftTheirKeys newKey keyID = do
        s@OtrState{..} <- OtrT get
        when (keyID == theirKeyID) .
            OtrT $ put s{ theirPreviousKey = theirCurrentKey
                        , theirCurrentKey = Just newKey
                        , theirKeyID = theirKeyID + 1
                        }
