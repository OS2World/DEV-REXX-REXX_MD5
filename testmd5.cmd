/* Test the "rexx only" MD5 and the "dll" MD5
   This uses the test strings found in rfc131 (that defines the MD5 digest
   algorithim  */

signal on error name foo1 ; signal on syntax name foo1 ;

/* Load all functions in the SRXFUNC dll. There's only one now (SRX_MD5),
   but maybe more will be added someday */

if rxfuncquery('srx_md5')=1  then do
  call RXFuncAdd 'SRXLoadFuncs', 'SRXFUNC', 'SRXLoadFuncs'
  call SRXLoadFuncs
end
if rxfuncquery('srx_md5')=1  then do
  say " Could not load SRX_MD5 from SRXFUNC.DLL"
  exit
end

/* Begin Tests */


say ' For: "" (empty string) '
say "   MD5 should be: d41d8cd98f00b204e9800998ecf8427e"
a1=srx_md5('')
say "        From dll: "a1
a2=rexx_md5('')
say "       From rexx: "a2

say
say ' For: "a" (just the character "a", not including the "s) '
say "   MD5 should be: 0cc175b9c0f1b6a831c399e269772661" 
a1=srx_md5('a')
say "        From dll: "a1
a2=rexx_md5('a')
say "       From rexx: "a2

say
say ' For: "abc" '
say "   MD5 should be: 900150983cd24fb0d6963f7d28e17f72"
a1=srx_md5('abc')
say "        From dll: "a1
a2=rexx_md5('abc')
say "       From rexx: "a2

say
test='message digest'
say '  For: "'test'"'
say "   MD5 should be: f96b697d7cb7938d525a2f31aaf161d0"
a1=srx_md5(test)
say "        From dll: "a1
a2=rexx_md5(test)
say "       From rexx: "a2

say
test="abcdefghijklmnopqrstuvwxyz" 
say '  For: "'test'"'
say "   MD5 should be: c3fcd3d76192e4007dfb496cca67e13b"
a1=srx_md5(test)
say "        From dll: "a1
a2=rexx_md5(test)
say "       From rexx: "a2

say
test="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
say '  For: "'test'"'
say "   MD5 should be: d174ab98d277d9f5a5611c2c9f419d9f"
a1=srx_md5(test)
say "        From dll: "a1
a2=rexx_md5(test)
say "       From rexx: "a2

say
test="12345678901234567890123456789012345678901234567890123456789012345678901234567890"
say '  For: "'test'"'
say "   MD5 should be: 57edf4a22be3c955ac49da2e2107b67a"
a1=srx_md5(test)
say "        From dll: "a1
a2=rexx_md5(test)
say "       From rexx: "a2


if stream('testmd5.cmd','c','query exists')<>'' then do
  test=charin('testmd5.cmd',1,chars('testmd5.cmd'))
  say
  say " For file: testmd5.CMD"
  a1=srx_md5(test)
  say "        From dll: "a1
foo=time('r')
  a2=rexx_md5(test)
foo2=time('e')
  say foo2"       From rexx: "a2
end



call SRXDropFuncs
exit

foo1: 
say " error " rc sigl
exit



/*  ------------------------------ */
/* this is an "all rexx" md5 procedure. It works, but it is slow */
rexx_md5:procedure
parse arg stuff
numeric digits 11
lenstuff=length(stuff)

c0=d2c(0)
c1=d2c(128)
c1a=d2c(255)
c1111=c1a||c1a||c1a||c1a
slen=length(stuff)*8
slen512=slen//512

/* pad message to multiple of 512 bits.  Last 2 words are 64 bit # bits in message*/
if slen512=448 then  addme=512
if slen512<448 then addme=448-slen512
if slen512>448 then addme=960-slen512
addwords=addme/8

apad=c1||copies(c0,addwords-1)

xlen=reverse(right(d2c(lenstuff*8),4,c0))||c0||c0||c0||c0  /* 2**32 max bytes in message */

/* NEWSTUFF is the message to be md5'ed */
newstuff=stuff||apad||xlen

/* starting values of registers */
 a ='67452301'x;
 b ='efcdab89'x;
 c ='98badcfe'x;
 d ='10325476'x;

lennews=length(newstuff)/4

/* loop through entire message */
do i1 = 0 to ((lennews/16)-1)
  i16=i1*64
  do j=1 to 16
     j4=((j-1)*4)+1
     jj=i16+j4
     m.j=reverse(substr(newstuff,jj,4))
  end /* do */

/* transform this block of 16 chars to 4 values. Save prior values first */
 aa=a;bb=b;cc=c;dd=d

/* do 4 rounds, 16 operations per round (rounds differ in bit'ing functions */
S11=7
S12=12
S13=17
S14=22
  a=round1( a, b, c, d,   0 , S11, 3614090360); /* 1 */
  d=round1( d, a, b, c,   1 , S12, 3905402710); /* 2 */
  c=round1( c, d, a, b,   2 , S13,  606105819); /* 3 */
  b=round1( b, c, d, a,   3 , S14, 3250441966); /* 4 */
  a=round1( a, b, c, d,   4 , S11, 4118548399); /* 5 */
  d=round1( d, a, b, c,   5 , S12, 1200080426); /* 6 */
  c=round1( c, d, a, b,   6 , S13, 2821735955); /* 7 */
  b=round1( b, c, d, a,   7 , S14, 4249261313); /* 8 */
  a=round1( a, b, c, d,   8 , S11, 1770035416); /* 9 */
  d=round1( d, a, b, c,   9 , S12, 2336552879); /* 10 */
  c=round1( c, d, a, b,  10 , S13, 4294925233); /* 11 */
  b=round1( b, c, d, a,  11 , S14, 2304563134); /* 12 */
  a=round1( a, b, c, d,  12 , S11, 1804603682); /* 13 */
  d=round1( d, a, b, c,  13 , S12, 4254626195); /* 14 */
  c=round1( c, d, a, b,  14 , S13, 2792965006); /* 15 */
  b=round1( b, c, d, a,  15 , S14, 1236535329); /* 16 */

  /* Round 2 */
S21=5
S22=9
S23=14
S24=20
a= round2( a, b, c, d,   1 , S21, 4129170786); /* 17 */
d= round2( d, a, b, c,   6 , S22, 3225465664); /* 18 */
c=  round2( c, d, a, b,  11 , S23,  643717713); /* 19 */
b=  round2( b, c, d, a,   0 , S24, 3921069994); /* 20 */
a=  round2( a, b, c, d,   5 , S21, 3593408605); /* 21 */
d=  round2( d, a, b, c,  10 , S22,   38016083); /* 22 */
c=  round2( c, d, a, b,  15 , S23, 3634488961); /* 23 */
b= round2( b, c, d, a,   4 , S24, 3889429448); /* 24 */
a= round2( a, b, c, d,   9 , S21,  568446438); /* 25 */
d= round2( d, a, b, c,  14 , S22, 3275163606); /* 26 */
c=  round2( c, d, a, b,   3 , S23, 4107603335); /* 27 */
b=  round2( b, c, d, a,   8 , S24, 1163531501); /* 28 */
a=  round2( a, b, c, d,  13 , S21, 2850285829); /* 29 */
d=  round2( d, a, b, c,   2 , S22, 4243563512); /* 30 */
c=  round2( c, d, a, b,   7 , S23, 1735328473); /* 31 */
b= round2( b, c, d, a,  12 , S24, 2368359562); /* 32 */

  /* Round 3 */
S31= 4
S32= 11
S33= 16
S34= 23
a= round3( a, b, c, d,   5 , S31, 4294588738); /* 33 */
d=  round3( d, a, b, c,   8 , S32, 2272392833); /* 34 */
c=  round3( c, d, a, b,  11 , S33, 1839030562); /* 35 */
b=  round3( b, c, d, a,  14 , S34, 4259657740); /* 36 */
a=  round3( a, b, c, d,   1 , S31, 2763975236); /* 37 */
d=  round3( d, a, b, c,   4 , S32, 1272893353); /* 38 */
c=  round3( c, d, a, b,   7 , S33, 4139469664); /* 39 */
b=  round3( b, c, d, a,  10 , S34, 3200236656); /* 40 */
a=  round3( a, b, c, d,  13 , S31,  681279174); /* 41 */
d=  round3( d, a, b, c,   0 , S32, 3936430074); /* 42 */
c=  round3( c, d, a, b,   3 , S33, 3572445317); /* 43 */
b=  round3( b, c, d, a,   6 , S34,   76029189); /* 44 */
a=  round3( a, b, c, d,   9 , S31, 3654602809); /* 45 */
d=  round3( d, a, b, c,  12 , S32, 3873151461); /* 46 */
c=  round3( c, d, a, b,  15 , S33,  530742520); /* 47 */
b=  round3( b, c, d, a,   2 , S34, 3299628645); /* 48 */

  /* Round 4 */
S41=6
S42=10
S43=15
s44=21
a=round4( a, b, c, d,   0 , S41, 4096336452); /* 49 */
d=round4( d, a, b, c,   7 , S42, 1126891415); /* 50 */
c=round4( c, d, a, b,  14 , S43, 2878612391); /* 51 */
b=round4( b, c, d, a,   5 , s44, 4237533241); /* 52 */
a=round4( a, b, c, d,  12 , S41, 1700485571); /* 53 */
d=round4( d, a, b, c,   3 , S42, 2399980690); /* 54 */
c=round4( c, d, a, b,  10 , S43, 4293915773); /* 55 */
b=round4( b, c, d, a,   1 , s44,  2240044497); /* 56 */
a=round4( a, b, c, d,   8 , S41, 1873313359); /* 57 */
d=round4( d, a, b, c,  15 , S42, 4264355552); /* 58 */
c=round4( c, d, a, b,   6 , S43, 2734768916); /* 59 */
b=round4( b, c, d, a,  13 , s44, 1309151649); /* 60 */
a=round4( a, b, c, d,   4 , S41, 4149444226); /* 61 */
d=round4( d, a, b, c,  11 , S42, 3174756917); /* 62 */
c=round4( c, d, a, b,   2 , S43,  718787259); /* 63 */
b=round4( b, c, d, a,   9 , s44, 3951481745); /* 64 */


a=m32add(aa,a) ; b=m32add(bb,b) ; c=m32add(cc,c) ; d=m32add(dd,d)

end

aa=c2x(reverse(a))||c2x(reverse(b))||c2x(reverse(C))||c2x(reverse(D))
return aa

/* round 1 to 4 functins */

round1:procedure expose m. c1111 c0 c1
parse arg a1,b1,c1,d1,kth,shift,sini
kth=kth+1
t1=c2d(a1)+c2d(f(b1,c1,d1))+ c2d(m.kth) + sini
t1a=right(d2c(t1),4,c0)
t2=rotleft(t1a,shift)
t3=m32add(t2,b1)
return t3

round2:procedure expose m. c1111 c0 c1
parse arg a1,b1,c1,d1,kth,shift,sini
kth=kth+1
t1=c2d(a1)+c2d(g(b1,c1,d1))+ c2d(m.kth) + sini
t1a=right(d2c(t1),4,c0)
t2=rotleft(t1a,shift)
t3=m32add(t2,b1)
return t3

round3:procedure expose m. c1111 c0 c1
parse arg a1,b1,c1,d1,kth,shift,sini
kth=kth+1
t1=c2d(a1)+c2d(h(b1,c1,d1))+ c2d(m.kth) + sini
t1a=right(d2c(t1),4,c0)
t2=rotleft(t1a,shift)
t3=m32add(t2,b1)
return t3

round4:procedure expose m. c1111 c0 c1
parse arg a1,b1,c1,d1,kth,shift,sini
kth=kth+1
t1=c2d(a1)+c2d(i(b1,c1,d1))+ c2d(m.kth) + sini
t1a=right(d2c(t1),4,c0)
t2=rotleft(t1a,shift)
t3=m32add(t2,b1)
return t3

/* add to "char" numbers, modulo 2**32, return as char */
m32add:procedure expose c0 c1 c1111
parse arg v1,v2
t1=c2d(v1)+c2d(v2)
t2=d2c(t1)
t3=right(t2,4,c0)
return t3



/*********** Basic functions */
/* F(x, y, z) == (((x) & (y)) | ((~x) & (z))) */
f:procedure expose c0 c1 c1111 
parse arg x,y,z
t1=bitand(x,y)
notx=bitxor(x,c1111)
t2=bitand(notx,z)
return bitor(t1,t2)


/* G(x, y, z) == (((x) & (z)) | ((y) & (~z)))*/
g:procedure expose c0 c1 c1111
parse arg x,y,z
t1=bitand(x,z)
notz=bitxor(z,c1111)
t2=bitand(y,notz)
return bitor(t1,t2)

/* H(x, y, z) == ((x) ^ (y) ^ (z)) */
h:procedure expose c0 c1 c1111
parse arg x,y,z
t1=bitxor(x,y)
return bitxor(t1,z)

/* I(x, y, z) == ((y) ^ ((x) | (~z))) */
i:procedure expose c0 c1 c1111
parse arg x,y,z
notz=bitxor(z,c1111)
t2=bitor(x,notz)
return bitxor(y,t2)

/* bit rotate to the left by s positions */
rotleft:procedure 
parse arg achar,s
if s=0 then return achar

bits=x2b(c2x(achar))
lb=length(bits)
t1=left(bits,s)
t2=bits||t1
yib=right(t2,lb)
return x2c(b2x(yib))





