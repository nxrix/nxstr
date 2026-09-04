// Copyright nxrix, 2026

/*

0:	User Metadata
1:	Short Text Note
2:	Recommend Relay
3:	Follows
4:	Encrypted Direct Messages
5:	Event Deletion Request
6:	Repost
7:	Reaction

 1000 <= n < 10000 || 4 <= n < 45 || n == 1 || n == 2, they're all expected to be stored by relays. - stored.
10000 <= n < 20000 || n == 0 || n == 3, for each combination of pubkey and kind, only the latest event MUST be stored by relays, older versions MAY be discarded. - replaceable.
20000 <= n < 30000, they are not expected to be stored by relays. - ephemeral.
30000 <= n < 40000, for each combination of pubkey, kind and d tag, only the latest event MUST be stored by relays, older versions MAY be discarded. - replaceable 2.

sent:
  ["EVENT",<event JSON>]    - publish events.
  ["REQ",<id>,<...filters>] - request events and subscribe to new updates.
  ["CLOSE",<id>]            - stop previous subscriptions.

filter: {
  "ids"         event ids
  "authors"     lowercase pubkeys
  "kinds"       kind numbers
  "#(a-zA-Z)"   tag values
  "since"       integer unix timestamp in seconds. created_at >=
  "until"       integer unix timestamp in seconds. created_at <=
  "limit"       limit
}

received:
  ["EVENT", <id>, <event JSON>], events requested.
  ["OK", <id>, <true|false>, <message>], acceptance or denial of an EVENT message.
  ["EOSE", <subscription_id>] indicate the end of stored events and the beginning of events newly received in real-time.
  ["CLOSED", <subscription_id>, <message>] indicate that a subscription was ended on the server side.
  ["NOTICE", <message>] human-readable error messages or other things.

*/

import * as nobleSecp256k1 from "https://cdn.jsdelivr.net/npm/@noble/secp256k1@3.1.0/index.min.js";

let sk = null;
let pk = null;

const getSecretKey = () => sk;
const getPublicKey = () => pk;

const b2h = (b) => Array.from(b).map(i=>i.toString(16).padStart(2,"0")).join("");
const h2b = (h) => Uint8Array.from(h.match(/.{1,2}/g).map(i=>parseInt(i,16)));

const sha256 = async (b) => new Uint8Array(await crypto.subtle.digest("SHA-256",b));
nobleSecp256k1.hashes.sha256Async = sha256;

const generateKeys = (csk) => {
  if (csk) {
    sk = csk;
    pk = b2h(nobleSecp256k1.schnorr.getPublicKey(h2b(csk)));
  } else {
    const k = nobleSecp256k1.utils.randomSecretKey();
    sk = b2h(k);
    pk = b2h(nobleSecp256k1.schnorr.getPublicKey(k));
  }
}

const sign = async (e,csk) => {
  const se = { ...e };
  if (se.pubkey === undefined) se.pubkey = pk;
  if (se.created_at === undefined) se.created_at = Math.floor(Date.now()/1000);
  if (se.tags === undefined) se.tags = [];
  if (se.content === undefined) se.content = "";
  const data = JSON.stringify([
    0,
    se.pubkey,
    se.created_at,
    se.kind,
    se.tags,
    se.content
  ]);
  se.id = await sha256(new TextEncoder().encode(data));
  se.sig = b2h(await nobleSecp256k1.schnorr.signAsync(se.id,h2b(csk||sk)));
  se.id = b2h(se.id);
  return se;
}

const verify = async (e) => {
  const { id, pubkey, created_at, kind, tags, content, sig } = e;
  const data = JSON.stringify([0,pubkey,created_at,kind,tags,content]);
  const cid = await sha256(new TextEncoder().encode(data));
  if (b2h(cid)!==id) return false;
  return await nobleSecp256k1.schnorr.verifyAsync(h2b(sig),h2b(id),h2b(pubkey));
};

const encrypt = async (text,cpk,csk) => {
  const sharedSecret = nobleSecp256k1.getSharedSecret(h2b(csk||sk), h2b("02"+cpk), true).slice(1,33);
  const key = await crypto.subtle.importKey("raw",sharedSecret,{name:"AES-CBC"},false,["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(16));
  const ciphertext = await crypto.subtle.encrypt({name:"AES-CBC",iv},key,new TextEncoder().encode(text));
  return btoa(String.fromCharCode(...new Uint8Array(ciphertext)))+"?iv="+btoa(String.fromCharCode(...iv));
}

const decrypt = async (text,cpk,csk) => {
  const [encryptedMessage,ivB64] = text.split("?iv=");
  const sharedSecret = nobleSecp256k1.getSharedSecret(h2b(csk||sk), h2b("02"+cpk), true).slice(1,33);
  const key = await crypto.subtle.importKey("raw",sharedSecret,{name:"AES-CBC"},false,["decrypt"]);
  const iv = Uint8Array.from(atob(ivB64), c => c.charCodeAt(0));
  const decrypted = await crypto.subtle.decrypt({name:"AES-CBC",iv},key,Uint8Array.from(atob(encryptedMessage),c=>c.charCodeAt(0)));
  return new TextDecoder().decode(decrypted);
}

export {
  getSecretKey,
  getPublicKey,
  b2h,
  h2b,
  generateKeys,
  sign,
  verify,
  encrypt,
  decrypt
};
