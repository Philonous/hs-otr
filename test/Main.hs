{-# LANGUAGE PatternGuards #-}
{-# LANGUAGE NoMonomorphismRestriction #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE MultiWayIf #-}
module Main where

import           Control.Applicative ((<$>))
import           Control.Concurrent
import           Control.Monad
import           Control.Monad.Trans
import           Crypto.Types.PubKey.DSA
import           Data.ASN1.BinaryEncoding
import           Data.ASN1.Encoding
import           Data.ASN1.Types
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64 as B64
import qualified Data.ByteString.Lazy as BSL
import           Data.Default
import           Data.Maybe (fromJust)
import           Data.PEM
import qualified Data.Serialize as Serialize
import           Data.Text (Text)
import qualified Data.Text as Text
import qualified Data.Text.Encoding as Text
import           Network
import           Network.Xmpp
import qualified Network.Xmpp.Internal as Xmpp
import           Network.Xmpp.IM
import           Numeric
import           Otr hiding (getMessage)
import           System.Log.Logger
import qualified Control.Exception as Ex


autoAccept context = forever $ do
    st <- waitForPresence (\p -> presenceType p == Subscribe) context
    sendPresence (presenceSubscribed (fromJust $ presenceFrom st)) context

autoMessage :: Session -> IO ()
autoMessage context = forever $ do
    st <- getStanza context
    if | Xmpp.MessageS msg <- st
       , Just im <- getIM msg
       , InstantMessage{imBody = MessageBody{bodyContent = bd}:_} <- im
          -> putStrLn $ (show $ messageFrom msg) ++ ": " ++ Text.unpack bd
       | True -> return ()

them :: Jid
them = parseJid "uart14@species64739.dyndns.org" -- [jidQ|uart14@species64739.dyndns.org|]

tag :: String
tag = "\x20\x09\x20\x20\x09\x09\x09\x09\x20\x09\x20\x09\x20\x09\x20\x20"
      ++ "\x20\x20\x09\x09\x20\x20\x09\x09"

otrPrefix = "?OTR:"
otrSuffix = "."

send :: (Serialize.Serialize a, Show a) => Session -> a -> IO Bool
send session x = do
    let outData = Text.concat [ otrPrefix
                              , x'
                              , otrSuffix
                              ]
    liftIO $ debugM "Pontarius.Xmpp.Otr" $ "OtrOut:" ++ show x
    sendMessage (simpleIM them outData) session
    return True
  where x' = Text.decodeUtf8 . B64.encode $ Serialize.encode x

recv :: Session -> IO OtrMessage
recv session = do
    msg <- getMessage session
    case getIM msg of
        Just (InstantMessage{imBody = MessageBody{bodyContent = bd}:_})
            | Just bs64msg <- Text.stripPrefix otrPrefix bd -> do
                msg <- case B64.decode . Text.encodeUtf8 $ Text.init bs64msg of
                    Left _ -> Ex.throw . ProtocolError . DeserializationError
                              $ "Base64 decode failed"
                    Right msg' -> return msg'
                r <- case Serialize.decode msg of
                    Left e -> Ex.throw . ProtocolError . DeserializationError $
                                "Binary decoding failed:" ++ show e
                    Right r' -> return r'

                liftIO $ debugM "Pontarius.Xmpp.Otr"
                    $ "OtrIn:" ++ show r
                return r
        _ -> recv session
  where
    decode = Serialize.decode . (\(Right x) -> x) . B64.decode . Text.encodeUtf8
              . fromJust . Text.stripPrefix otrPrefix . Text.init

waitForOtr sess keys = do
    msg <- getMessage sess
    case getIM msg of
        Just (InstantMessage{imBody = MessageBody{bodyContent = bd}:_})
            | checkOtr bd -> newSession (send sess) (recv sess) bob keys
        _ -> waitForOtr sess keys
  where
    checkOtr :: Text -> Bool
    checkOtr bd = case Text.stripPrefix "?OTRv" bd of
        Nothing -> False
        Just s -> let (vers:_) = Text.splitOn "?" s in "3" `Text.isInfixOf` vers



main = do
    updateGlobalLogger "Pontarius.Xmpp" $ setLevel DEBUG
    let keyFile = "../privkey.pem"
    Right ((PEM pName _ bs) : _) <- pemParseLBS `fmap` (BSL.readFile keyFile)
    let Right keysASN1 = decodeASN1 DER (BSL.fromChunks [bs])
    let Right (keyPair, _) = fromASN1 keysASN1
    let (KeyPair params _ _) = keyPair
    Right sess <- session "species64739.dyndns.org"
             (Just ( \_ -> [scramSha1 "echo1" Nothing "pwd"]
                   , Just "bot"))
             def{sessionStreamConfiguration
              = def{ connectionDetails = UseHost "localhost" (PortNumber 5222)
                   , tlsBehaviour = Xmpp.RefuseTls
                   }

                }
    thread1 <- forkIO $ autoAccept =<< dupSession sess
    sendPresence presenceOnline sess
    let active = True
    ns <- if active
          then do
              sendMessage (simpleIM them "?OTRv3?") sess
              sendMessage (simpleIM them "OTR token sent.") sess
              newSession (send sess) (recv sess) alice ( toPublicKey keyPair
                                                       , toPrivateKey keyPair)
          else waitForOtr sess (toPublicKey keyPair, toPrivateKey keyPair)
    case ns of
        Left e  -> print e
        Right r -> do
            putStrLn "Success!"
            forever $ do
                msg <- withSession r (send sess) (recv sess) recvDataMessage
                print msg
                withSession r (send sess) (recv sess) . sendDataMessage
                    $ MP { messagePlaintext = "Hello encrypted"
                         , tlvs = []
                         }

            return ()

    return sess
