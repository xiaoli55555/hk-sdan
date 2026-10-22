'use strict';
// Web Crypto only; rejection sampling avoids modulo bias.
function generateCustomerPassword(){
  const groups=['ABCDEFGHJKLMNPQRSTUVWXYZ','abcdefghijkmnopqrstuvwxyz','23456789','!@#$%*-_=+'];
  const alphabet=groups.join('');
  function pick(limit){const bytes=new Uint32Array(1),ceiling=Math.floor(4294967296/limit)*limit;do{crypto.getRandomValues(bytes);}while(bytes[0]>=ceiling);return bytes[0]%limit;}
  const chars=groups.map(group=>group[pick(group.length)]);
  while(chars.length<20)chars.push(alphabet[pick(alphabet.length)]);
  for(let i=chars.length-1;i>0;i--){const j=pick(i+1);[chars[i],chars[j]]=[chars[j],chars[i]];}
  return chars.join('');
}

