;; # -*- coding: utf-8 -*-

(ns com.example.util.utils
   (:use    [clojure.tools.logging :only (info warn error)])
   (:require [clojure.data.json :as json])
   (import (java.security MessageDigest)
     (javax.crypto Cipher Mac)
     (javax.crypto.spec SecretKeySpec) 
     (java.math BigInteger)
     (org.apache.commons.codec.binary Base64)))

(defn ^{:static true} getBytes [s]
  (.getBytes ^String s "UTF-8"))

(defn ^{:static true} base64 [b]
  (Base64/encodeBase64String b))

(defn ^{:static true} debase64 [s]
  (Base64/decodeBase64 (getBytes ^String s)))

(defn ^{:static true} hexify [s]
  (apply str (map #(format "%02x" %) s)))

;use for universal md5 digest
(defn ^{:static true} get-md5 [^String token]
  (let [hash-bytes (doto (MessageDigest/getInstance "MD5") (.reset) (.update (getBytes token)))]
      (clojure.string/upper-case (hexify (.digest hash-bytes)))))


;use for uniscore get method
(defn ^{:static true} get-signature [^String str ^String ssec]
  (let [instanse (doto (Mac/getInstance "HmacSHA1") (.init (new SecretKeySpec (getBytes ssec) "HmacSHA1")))]
      (clojure.string/lower-case (hexify (.doFinal instanse (.getBytes str))))))

;use for universal aes encrypt
(defn ^{:static true} aes-encrypt [^String str ^String ssec]
  (let [instanse (doto (Cipher/getInstance "AES") (.init  (Cipher/ENCRYPT_MODE) (new SecretKeySpec (debase64 ssec) "AES")))]
       (base64 (.doFinal instanse (getBytes str)))))

;use for universal aes decrypt
(defn ^{:static true} aes-decrypt [^String str ^String ssec]
  (let [instanse (doto (Cipher/getInstance "AES") (.init  (Cipher/DECRYPT_MODE) (new SecretKeySpec (debase64 ssec) "AES")))]
      (String. (.doFinal instanse  (debase64 str)))))

