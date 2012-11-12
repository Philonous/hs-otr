{-# LANGUAGE FunctionalDependencies #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ScopedTypeVariables #-}

{-# LANGUAGE NoMonomorphismRestriction #-}
module Otr.Monad where

import           Control.Monad
import           Control.Monad.Error
import           Control.Monad.Identity
import           Control.Monad.Reader
import           Control.Monad.State.Strict
import           Control.Monad.Trans.State.Strict (liftCatch)
import qualified Crypto.Cipher.DSA as DSA
import qualified Crypto.Random as CRandom
import qualified Data.ByteString as BS
import           Otr.Types

newtype RandT g m a = RandT { unRandT :: StateT g m a }
                      deriving (Monad, Functor, MonadTrans)

runRandT :: g -> RandT g m a -> m (a, g)
runRandT g m = runStateT (unRandT m) g

type Rand g = RandT g Identity

runRand g = runIdentity . runRandT g

class Monad m => MonadRandom g m | m -> g where
    withRandGen :: (g -> Either CRandom.GenError (a, g)) -> m a

instance (MonadError OtrError m, Monad m) => MonadRandom g (RandT g m) where
    withRandGen f = RandT . StateT  $ \gen ->
        case f gen of
            Left e -> throwError $ RandomGenError e
            Right r -> return r

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

getBytes  :: (CRandom.CryptoRandomGen g, MonadRandom g m) =>
                Int -> m BS.ByteString
getBytes b = withRandGen $ CRandom.genBytes b

newtype OtrT g m a = OtrT {unOtrT :: ReaderT (DSA.PublicKey, DSA.PrivateKey)
                                        (StateT OtrState
                                        (RandT g
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
