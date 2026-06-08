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
let socket = null;

const b2h = (a) => Array.from(a).map(b=>b.toString(16).padStart(2,"0")).join("");
const h2b = (h) => Uint8Array.from(h.match(/.{1,2}/g).map(b=>parseInt(b,16)));
const b642h = (b) => Array.from(atob(b)).map(c=>c.charCodeAt(0).toString(16).padStart(2,"0")).join("");

const sha256 = async (data) => {
  const encoder = new TextEncoder();
  const hb = await crypto.subtle.digest("SHA-256",encoder.encode(data));
  return new Uint8Array(hb);
}

nobleSecp256k1.hashes.sha256Async = sha256;

const getSecretKey = () => {
  if (confirm("Do you want to export your secret key?")) {
    return sk;
  }
  return null;
}

const generateKeys = () => {
  const k = nobleSecp256k1.utils.randomSecretKey();
  sk = b2h(k);
  pk = b2h(nobleSecp256k1.schnorr.getPublicKey(k));
}

const login = (csk) => {
  if (csk) {
    sk = csk;
    pk = b2h(nobleSecp256k1.schnorr.getPublicKey(h2b(csk)));
  } else {
    generateKeys();
  }
}

const sign = async (event,csk) => {
  if (!event.pubkey) event.pubkey = pk;
  if (!event.created_at) event.created_at = Math.floor(Date.now()/1000);
  if (!event.content) event.content = "";
  const data = JSON.stringify([
    0,
    event.pubkey,
    event.created_at,
    event.kind,
    event.tags,
    event.content
  ]);
  event.id = await sha256(data);
  event.sig = b2h(await nobleSecp256k1.schnorr.signAsync(event.id,h2b(csk||sk)));
  event.id = b2h(event.id);
  return event;
}

const encrypt = async (text,cpk,csk) => {
  const sharedSecret = nobleSecp256k1.getSharedSecret(csk||sk,"02"+cpk,true).substring(2);
  const key = await crypto.subtle.importKey("raw",h2b(sharedSecret),{name:"AES-CBC"},false,["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(16));
  const ciphertext = await crypto.subtle.encrypt({name:"AES-CBC",iv},key,new TextEncoder().encode(text));
  return btoa(String.fromCharCode(...new Uint8Array(ciphertext)))+"?iv="+btoa(String.fromCharCode(...iv));
}

const decrypt = async (text,cpk,csk) => {
  const [encryptedMessage,ivB64] = text.split("?iv=");
  const sharedSecret = nobleSecp256k1.getSharedSecret(csk||sk,"02"+cpk,true).substring(2);
  const key = await crypto.subtle.importKey("raw",h2b(sharedSecret),{name:"AES-CBC"},false,["decrypt"]);
  const iv = Uint8Array.from(atob(ivB64), c => c.charCodeAt(0));
  const decrypted = await crypto.subtle.decrypt({name:"AES-CBC",iv },key,Uint8Array.from(atob(encryptedMessage),c=>c.charCodeAt(0)));
  return new TextDecoder().decode(decrypted);
}

const connect = (url) => {
  if (socket) socket.close();
  socket = new WebSocket(url);
}

const changeBase = (i,c1,c2) => {
  const b1 = c1.length;
  const b2 = c2.length;
  let lz = 0;
  while (i[lz]==c1[0]) {
    lz++;
  }
  let d = "0";
  for (let n=lz;n<i.length; n++) {
    d = (BigInt(d)*BigInt(b1)+BigInt(c1.indexOf(i[n]))).toString();
  }
  if (d=="0") {
    return c2[0].repeat(lz+1);
  }
  let o = "";
  while (d!="0") {
    let r = BigInt(d)%BigInt(b2);
    o = c2[Number(r)]+o;
    d = (BigInt(d)/BigInt(b2)).toString();
  }
  return c2[0].repeat(lz)+o;
}

const rawToFriendly = (k,f=[0,0,0,0]) => {
  let bytes = f;
  for (let i=0;i<32;i++) bytes.push(+("0x"+k[i*2]+k[i*2+1]));
  return btoa(String.fromCodePoint(...bytes)).replace(/\+/g,"-").replace(/\//g,"_");
}

export {
  pk,
  socket,
  b2h,
  h2b,
  b642h,
  getSecretKey,
  generateKeys,
  login,
  sign,
  encrypt,
  decrypt,
  connect,
  changeBase,
  rawToFriendly
};
