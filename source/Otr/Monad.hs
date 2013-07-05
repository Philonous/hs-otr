{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE DeriveFunctor #-}
{-# LANGUAGE FunctionalDependencies #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE NoMonomorphismRestriction #-}
module Otr.Monad where

import           Control.Monad.Error
import           Control.Monad.Identity
import           Control.Monad.Reader
import           Control.Monad.State.Strict
import           Control.Monad.Trans.State.Strict (liftCatch)
import qualified Crypto.PubKey.DSA as DSA
import qualified Crypto.Random.API as CRandom
import           Otr.Types
import qualified Data.ByteString as BS

newtype RandT g m a = RandT { unRandT :: StateT g m a }
                      deriving (Monad, Functor, MonadTrans)

runRandT :: g -> RandT g m a -> m (a, g)
runRandT g m = runStateT (unRandT m) g

type Rand g = RandT g Identity

runRand :: g -> RandT g Identity a -> (a, g)
runRand g = runIdentity . runRandT g

class Monad m => MonadRandom g m | m -> g where
    withRandGen :: (g -> (a, g)) -> m a

instance Monad m => MonadRandom g (RandT g m) where
    withRandGen f = RandT . StateT $ return . f

instance (MonadRandom g m, Monad m) => MonadRandom g (ReaderT r m) where
    withRandGen = lift . withRandGen
instance (MonadRandom g m, Monad m) => MonadRandom g (StateT s m) where
    withRandGen = lift . withRandGen

instance MonadState s m => MonadState s (RandT g m) where
    get = lift get
    put = lift . put

instance MonadError e m => MonadError e (RandT g m) where
    throwError = lift . throwError
    catchError m f = RandT $ liftCatch catchError (unRandT m) (unRandT . f)

getBytes :: (CRandom.CPRG g, MonadRandom g m) => Int -> m BS.ByteString
getBytes b = withRandGen $ CRandom.genRandomBytes b

newtype OtrT g m a = OtrT {unOtrT :: ReaderT (DSA.PublicKey, DSA.PrivateKey)
                                        (StateT OtrState                                        (RandT g
                                        (ErrorT OtrError
                                        m )))
                                      a
                          } deriving (Monad, Functor)

instance MonadTrans (OtrT g) where
    lift = OtrT . lift . lift . lift . lift

instance Monad m => MonadRandom g (OtrT g m) where
    withRandGen = OtrT . withRandGen

runOtrT:: (DSA.PublicKey, DSA.PrivateKey)
       -> OtrState
       -> OtrT g m a
       -> g
       -> m (Either OtrError ((a , OtrState) , g))
runOtrT dsaKeys s m g =  runErrorT
                       . runRandT g
                       . flip runStateT s
                       . flip runReaderT dsaKeys
                       $ unOtrT m

instance Monad m => MonadError OtrError (OtrT g m) where
    throwError = OtrT . throwError
    catchError (OtrT m) f = OtrT . catchError m $ unOtrT . f

instance MonadIO m => MonadIO (OtrT g m) where
    liftIO = lift . liftIO


data Messaging a = SendMessage OtrMessage (Messaging a)
                 | RecvMessage (OtrMessage -> Messaging a)
                 | Return a
                 deriving Functor

instance Monad Messaging where
    return = Return
    Return a >>= f = f a
    SendMessage msg g >>= f = SendMessage msg (g >>= f)
    RecvMessage g >>= f = RecvMessage (\msg -> g msg >>= f)

type Otr g a = OtrT g Messaging a

runMessaging :: Monad m
             => (OtrMessage -> m a)
             -> m OtrMessage
             -> Messaging b
             -> m b
runMessaging sm rm m = go m
  where
    go (Return a) = return a
    go (SendMessage msg g) = sm msg >> go g
    go (RecvMessage f) = rm >>= \msg -> go (f msg)

sendMessage :: OtrMessageBody -> Otr g ()
sendMessage msgBody = do
    tit <- OtrT $ gets theirIT
    oit <- OtrT $ gets ourIT
    lift $ SendMessage OM{ version = 3
                         , senderITag = oit
                         , receiverITag = tit
                         , messageBody = msgBody
                         } (return ())

recvMessage :: Otr g OtrMessageBody
recvMessage = do
    OM{..} <- lift $ RecvMessage return
    tit <- OtrT $ gets theirIT
    case tit of
        0 -> if senderITag > 0x100
             then do
                 OtrT $ modify( \s -> s{theirIT = senderITag} )
                 return $ messageBody
             else OtrT $ throwError InstanceTagRange
        n -> if senderITag == n
             then return $ messageBody
             else recvMessage -- When the instance tag doesn't match we just
                              -- ignore the message since it's not intended for
                              -- this session
